#include "vm27_native_network_v1.h"
#include <libslirp.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

enum { VM27NetworkPollLimit = 4096, VM27NetworkPacketLimit = 65536 };
typedef struct NetworkTimer NetworkTimer;
struct NetworkTimer {
    NetworkTimer *next;
    SlirpTimerCb callback;
    void *callbackContext;
    int64_t deadlineMS;
    bool armed;
};
struct VM27NativeNetworkV1 {
    _Atomic unsigned references;
    _Atomic bool stopping;
    int peer, cancellation[2];
    Slirp *slirp;
    NetworkTimer *timers;
    struct pollfd descriptors[VM27NetworkPollLimit + 2];
    unsigned descriptorCount;
    bool pollOverflow;
    uint64_t received, transmitted, dropped;
};

static int Nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return errno;
    flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) return errno;
    return 0;
}
static int64_t ClockNS(void *context) {
    (void)context;
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) abort();
    return (int64_t)time.tv_sec * INT64_C(1000000000) + time.tv_nsec;
}
static void ReleaseNetwork(VM27NativeNetworkV1 *network) {
    if (atomic_fetch_sub_explicit(&network->references, 1, memory_order_acq_rel) != 1) return;
    /* These remain open while either the caller or worker can use them.
     * In particular, a failed worker cannot leave Stop writing a reused fd. */
    close(network->peer);
    close(network->cancellation[0]);
    close(network->cancellation[1]);
    free(network);
}
static void Notify(void *context) {
    VM27NativeNetworkV1 *network = context;
    int saved = errno;
    const uint8_t byte = 1;
    ssize_t ignored = write(network->cancellation[1], &byte, 1);
    (void)ignored;
    errno = saved;
}
static slirp_ssize_t SendPacket(const void *bytes, size_t count, void *context) {
    VM27NativeNetworkV1 *network = context;
    if (count < 14 || count > VM27NetworkPacketLimit) { errno = EMSGSIZE; return -1; }
    ssize_t result = send(network->peer, bytes, count, MSG_DONTWAIT);
    if (result == (ssize_t)count) ++network->transmitted;
    else ++network->dropped;
    return result;
}
static void GuestError(const char *message, void *context) {
    (void)message;
    VM27NativeNetworkV1 *network = context;
    if (++network->dropped <= 4)
        fprintf(stderr, "[Independent27Network] guest packet rejected by native library; payload not logged\n");
}
static void *TimerNew(SlirpTimerCb callback, void *argument, void *context) {
    VM27NativeNetworkV1 *network = context;
    NetworkTimer *timer = calloc(1, sizeof(*timer));
    if (!timer) return NULL;
    timer->callback = callback;
    timer->callbackContext = argument;
    timer->next = network->timers;
    network->timers = timer;
    return timer;
}
static void TimerFree(void *pointer, void *context) {
    VM27NativeNetworkV1 *network = context;
    NetworkTimer **link = &network->timers;
    while (*link && *link != pointer) link = &(*link)->next;
    if (!*link) abort();
    NetworkTimer *timer = *link;
    *link = timer->next;
    free(timer);
}
static void TimerModify(void *pointer, int64_t milliseconds, void *context) {
    (void)context;
    NetworkTimer *timer = pointer;
    timer->deadlineMS = milliseconds;
    timer->armed = true;
}
static short PollEvents(int events) {
    short value = 0;
    if (events & SLIRP_POLL_IN) value |= POLLIN;
    if (events & SLIRP_POLL_OUT) value |= POLLOUT;
    if (events & SLIRP_POLL_PRI) value |= POLLPRI;
    return value;
}
static int AddPollSocket(slirp_os_socket descriptor, int events, void *context) {
    VM27NativeNetworkV1 *network = context;
    if (network->descriptorCount == VM27NetworkPollLimit + 2) {
        network->pollOverflow = true;
        return -1;
    }
    unsigned index = network->descriptorCount++;
    network->descriptors[index] = (struct pollfd){descriptor, PollEvents(events), 0};
    return (int)index;
}
static int PollResults(int index, void *context) {
    VM27NativeNetworkV1 *network = context;
    if (index < 2 || (unsigned)index >= network->descriptorCount) return 0;
    short events = network->descriptors[index].revents;
    int result = 0;
    if (events & POLLIN) result |= SLIRP_POLL_IN;
    if (events & POLLOUT) result |= SLIRP_POLL_OUT;
    if (events & POLLPRI) result |= SLIRP_POLL_PRI;
    if (events & (POLLERR | POLLNVAL)) result |= SLIRP_POLL_ERR;
    if (events & POLLHUP) result |= SLIRP_POLL_HUP;
    return result;
}
static void PollRegistration(slirp_os_socket descriptor, void *context) {
    (void)descriptor;
    (void)context; /* The library fills the current socket list on each poll. */
}
static void RunTimers(VM27NativeNetworkV1 *network) {
    for (unsigned iteration = 0; iteration < 64; ++iteration) {
        int64_t now = ClockNS(NULL) / INT64_C(1000000);
        NetworkTimer *timer = network->timers;
        while (timer && (!timer->armed || timer->deadlineMS > now)) timer = timer->next;
        if (!timer) return;
        timer->armed = false;
        SlirpTimerCb callback = timer->callback;
        void *argument = timer->callbackContext;
        callback(argument); /* It may remove or rearm any timer. */
    }
}
static void *NetworkWorker(void *context) {
    VM27NativeNetworkV1 *network = context;
    pthread_setname_np("VirtualMac.independent27.network");
    SlirpConfig configuration = {0};
    configuration.version = SLIRP_CONFIG_VERSION_MAX;
    configuration.in_enabled = true;
    configuration.vnetwork.s_addr = htonl(UINT32_C(0x0a000200));
    configuration.vnetmask.s_addr = htonl(UINT32_C(0xffffff00));
    configuration.vhost.s_addr = htonl(UINT32_C(0x0a000202));
    configuration.vdhcp_start.s_addr = htonl(UINT32_C(0x0a00020f));
    configuration.vnameserver.s_addr = htonl(UINT32_C(0x0a000203));
    configuration.vhostname = "VirtualMac";
    configuration.if_mtu = configuration.if_mru = 1500;
    configuration.disable_host_loopback = true;
    SlirpCb callbacks = {0};
    callbacks.send_packet = SendPacket;
    callbacks.guest_error = GuestError;
    callbacks.clock_get_ns = ClockNS;
    callbacks.timer_new = TimerNew;
    callbacks.timer_free = TimerFree;
    callbacks.timer_mod = TimerModify;
    callbacks.notify = Notify;
    callbacks.register_poll_socket = PollRegistration;
    callbacks.unregister_poll_socket = PollRegistration;
    network->slirp = slirp_new(&configuration, &callbacks, network);
    if (network->slirp) {
        fprintf(stderr, "[Independent27Network] actual IPv4 NAT library ready version=%s mtu=1500 nativeDatagram=1\n", slirp_version_string());
        uint8_t packet[VM27NetworkPacketLimit];
        while (!atomic_load_explicit(&network->stopping, memory_order_acquire)) {
            network->descriptorCount = 2;
            network->descriptors[0] = (struct pollfd){network->peer, POLLIN, 0};
            network->descriptors[1] = (struct pollfd){network->cancellation[0], POLLIN, 0};
            uint32_t timeout = 1000;
            slirp_pollfds_fill_socket(network->slirp, &timeout, AddPollSocket, network);
            int64_t now = ClockNS(NULL) / INT64_C(1000000);
            for (NetworkTimer *timer = network->timers; timer; timer = timer->next) {
                if (!timer->armed) continue;
                int64_t remaining = timer->deadlineMS > now ? timer->deadlineMS - now : 0;
                if (remaining < timeout) timeout = (uint32_t)remaining;
            }
            int status = poll(network->descriptors, network->descriptorCount, (int)timeout);
            if (status < 0 && errno == EINTR) continue;
            if (network->descriptors[1].revents & POLLIN) {
                uint8_t discard[128];
                while (read(network->cancellation[0], discard, sizeof(discard)) > 0) {}
            }
            if (atomic_load_explicit(&network->stopping, memory_order_acquire)) break;
            slirp_pollfds_poll(network->slirp, status < 0, PollResults, network);
            if (network->pollOverflow || status < 0) {
                fprintf(stderr, "[Independent27Network] poll stopped overflow=%d error=%d\n", network->pollOverflow, status < 0 ? errno : 0);
                break;
            }
            if (network->descriptors[0].revents & POLLIN) {
                for (unsigned count = 0; count < 256; ++count) {
                    struct iovec vector = {packet, sizeof(packet)};
                    struct msghdr message = {0};
                    message.msg_iov = &vector;
                    message.msg_iovlen = 1;
                    ssize_t length = recvmsg(network->peer, &message, MSG_DONTWAIT);
                    if (length < 0 && errno == EINTR) continue;
                    if (length < 0) break;
                    if (length < 14 || (message.msg_flags & MSG_TRUNC)) { ++network->dropped; continue; }
                    ++network->received;
                    slirp_input(network->slirp, packet, (int)length);
                }
            }
            RunTimers(network);
        }
        slirp_cleanup(network->slirp);
        network->slirp = NULL;
    } else fprintf(stderr, "[Independent27Network] native library initialization failed\n");
    fprintf(stderr, "[Independent27Network] worker stopped guestFrames=%llu hostFrames=%llu drops=%llu\n",
        (unsigned long long)network->received, (unsigned long long)network->transmitted, (unsigned long long)network->dropped);
    if (network->timers) abort();
    ReleaseNetwork(network);
    return NULL;
}
int VM27NativeNetworkStartV1(VM27NativeNetworkV1 **out, int *guestDescriptor) {
    if (!out || !guestDescriptor) return EINVAL;
    int pair[2] = {-1, -1}, cancellation[2] = {-1, -1};
    int error = 0;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) || pipe(cancellation)) { error = errno; goto fail; }
    for (unsigned i = 0; i < 2; ++i) {
        if ((error = Nonblocking(pair[i])) || (error = Nonblocking(cancellation[i]))) goto fail;
        int sendBytes = 65536, receiveBytes = 262144, yes = 1;
        if (setsockopt(pair[i], SOL_SOCKET, SO_SNDBUF, &sendBytes, sizeof(sendBytes)) ||
            setsockopt(pair[i], SOL_SOCKET, SO_RCVBUF, &receiveBytes, sizeof(receiveBytes)) ||
            setsockopt(pair[i], SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes))) { error = errno; goto fail; }
        socklen_t bytes = sizeof(int);
        if (getsockopt(pair[i], SOL_SOCKET, SO_SNDBUF, &sendBytes, &bytes) ||
            getsockopt(pair[i], SOL_SOCKET, SO_RCVBUF, &receiveBytes, &bytes)) { error = errno; goto fail; }
        if (sendBytes < 1500 || receiveBytes < 2 * sendBytes) { error = ENOBUFS; goto fail; }
    }
    VM27NativeNetworkV1 *network = calloc(1, sizeof(*network));
    if (!network) { error = ENOMEM; goto fail; }
    atomic_init(&network->references, 2);
    atomic_init(&network->stopping, false);
    network->peer = pair[1];
    network->cancellation[0] = cancellation[0];
    network->cancellation[1] = cancellation[1];
    pthread_attr_t attributes;
    error = pthread_attr_init(&attributes);
    if (!error) {
        error = pthread_attr_setstacksize(&attributes, 512 * 1024);
        pthread_t thread;
        if (!error) error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        if (!error) error = pthread_create(&thread, &attributes, NetworkWorker, network);
        pthread_attr_destroy(&attributes);
    }
    if (error) { free(network); goto fail; }
    *out = network;
    *guestDescriptor = pair[0];
    return 0;
fail:
    for (unsigned i = 0; i < 2; ++i) {
        if (pair[i] >= 0) close(pair[i]);
        if (cancellation[i] >= 0) close(cancellation[i]);
    }
    return error;
}
void VM27NativeNetworkStopV1(VM27NativeNetworkV1 *network) {
    if (!network) return;
    atomic_store_explicit(&network->stopping, true, memory_order_release);
    Notify(network);
    ReleaseNetwork(network);
}
