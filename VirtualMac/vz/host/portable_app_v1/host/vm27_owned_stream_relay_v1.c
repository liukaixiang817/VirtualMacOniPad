#include "vm27_owned_stream_relay_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VM27_RELAY_BUFFER_BYTES 16384u

struct vm27_relay_direction {
    unsigned char bytes[VM27_RELAY_BUFFER_BYTES];
    size_t offset;
    size_t length;
    int source;
    int destination;
    int source_eof;
    int destination_shutdown;
    uint64_t written;
};

static int vm27_relay_finish(struct vm27_stream_relay_v1_result *result,
                             const struct vm27_relay_direction directions[2],
                             enum vm27_stream_relay_v1_stop stop, int error)
{
    result->bytes_left_to_right = directions[0].written;
    result->bytes_right_to_left = directions[1].written;
    result->stop = stop;
    result->error = error;
    return error;
}

static int vm27_relay_now(uint64_t *milliseconds)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return errno;
    if (now.tv_sec < 0 || (uint64_t)now.tv_sec > UINT64_MAX / 1000u)
        return EOVERFLOW;
    *milliseconds = (uint64_t)now.tv_sec * 1000u
                  + (uint64_t)now.tv_nsec / 1000000u;
    return 0;
}

static int vm27_relay_socket(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0)
        return errno;
    if ((flags & O_NONBLOCK) == 0)
        return EINVAL;
    int type = 0;
    socklen_t length = sizeof(type);
    if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &length) != 0)
        return errno;
    if (length != sizeof(type) || type != SOCK_STREAM)
        return EPROTOTYPE;
#ifdef SO_NOSIGPIPE
    int no_signal = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE,
                   &no_signal, sizeof(no_signal)) != 0)
        return errno;
#endif
    return 0;
}

static int vm27_relay_read(struct vm27_relay_direction *direction,
                           int *progress)
{
    if (direction->source_eof || direction->length == VM27_RELAY_BUFFER_BYTES)
        return 0;
    if (direction->offset != 0) {
        memmove(direction->bytes, direction->bytes + direction->offset,
                direction->length);
        direction->offset = 0;
    }
    ssize_t count = recv(direction->source,
                         direction->bytes + direction->length,
                         VM27_RELAY_BUFFER_BYTES - direction->length, 0);
    if (count > 0) {
        direction->length += (size_t)count;
        *progress = 1;
    } else if (count == 0) {
        direction->source_eof = 1;
        *progress = 1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return errno;
    }
    return 0;
}

static int vm27_relay_write(struct vm27_relay_direction *direction,
                            int *progress)
{
    if (direction->length != 0) {
#ifdef MSG_NOSIGNAL
        int flags = MSG_NOSIGNAL;
#else
        int flags = 0;
#endif
        ssize_t count = send(direction->destination,
                              direction->bytes + direction->offset,
                              direction->length, flags);
        if (count > 0) {
            if (direction->written > UINT64_MAX - (uint64_t)count)
                return EOVERFLOW;
            direction->written += (uint64_t)count;
            direction->offset += (size_t)count;
            direction->length -= (size_t)count;
            *progress = 1;
        } else if (count == 0) {
            return EIO;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return errno;
        }
    }
    if (direction->source_eof && direction->length == 0
        && !direction->destination_shutdown) {
        if (shutdown(direction->destination, SHUT_WR) != 0)
            return errno;
        direction->destination_shutdown = 1;
        *progress = 1;
    }
    return 0;
}

int vm27_owned_stream_relay_v1_run(
    int left_fd, int right_fd, int cancellation_read_fd,
    uint32_t idle_milliseconds, struct vm27_stream_relay_v1_result *result)
{
    if (result == NULL)
        return EINVAL;
    memset(result, 0, sizeof(*result));
    struct vm27_relay_direction directions[2] = {
        { .source = left_fd, .destination = right_fd },
        { .source = right_fd, .destination = left_fd }
    };
    int error = 0;
    if (left_fd < 0 || right_fd < 0 || cancellation_read_fd < 0
        || left_fd == right_fd || left_fd == cancellation_read_fd
        || right_fd == cancellation_read_fd || idle_milliseconds == 0
        || idle_milliseconds > 3600000u) {
        error = EINVAL;
    } else {
        error = vm27_relay_socket(left_fd);
        if (error == 0)
            error = vm27_relay_socket(right_fd);
        int flags = fcntl(cancellation_read_fd, F_GETFL);
        struct stat cancellation_stat;
        if (error == 0 && flags < 0)
            error = errno;
        if (error == 0 && (flags & O_NONBLOCK) == 0)
            error = EINVAL;
        if (error == 0 && fstat(cancellation_read_fd, &cancellation_stat) != 0)
            error = errno;
        if (error == 0 && !S_ISFIFO(cancellation_stat.st_mode))
            error = EINVAL;
    }
    uint64_t last_progress = 0;
    if (error == 0)
        error = vm27_relay_now(&last_progress);
    if (error != 0)
        return vm27_relay_finish(result, directions,
                                 VM27_STREAM_RELAY_V1_ERROR, error);

    for (;;) {
        if (directions[0].destination_shutdown
            && directions[1].destination_shutdown)
            return vm27_relay_finish(result, directions,
                                     VM27_STREAM_RELAY_V1_COMPLETE, 0);
        uint64_t now = 0;
        error = vm27_relay_now(&now);
        if (error != 0 || now < last_progress)
            return vm27_relay_finish(result, directions,
                VM27_STREAM_RELAY_V1_ERROR, error != 0 ? error : EIO);
        uint64_t elapsed = now - last_progress;
        if (elapsed >= idle_milliseconds)
            return vm27_relay_finish(result, directions,
                                     VM27_STREAM_RELAY_V1_IDLE, ETIMEDOUT);
        uint64_t remaining = idle_milliseconds - elapsed;
        int timeout = remaining > 1000u ? 1000 : (int)remaining;
        struct pollfd descriptors[3] = {
            { .fd = left_fd }, { .fd = right_fd },
            { .fd = cancellation_read_fd, .events = POLLIN }
        };
        for (size_t index = 0; index < 2; ++index) {
            const struct vm27_relay_direction *direction = &directions[index];
            if (!direction->source_eof
                && direction->length < VM27_RELAY_BUFFER_BYTES)
                descriptors[index].events |= POLLIN;
            if (direction->length != 0)
                descriptors[1u - index].events |= POLLOUT;
        }
        for (size_t index = 0; index < 2; ++index) {
            /* poll reports HUP even with events==0. A full source buffer must
             * sleep for its destination, rather than spin on a closed source. */
            if (descriptors[index].events == 0)
                descriptors[index].fd = -1;
        }
        int ready = poll(descriptors, 3, timeout);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return vm27_relay_finish(result, directions,
                                     VM27_STREAM_RELAY_V1_ERROR, errno);
        }
        if (descriptors[2].revents != 0) {
            if ((descriptors[2].revents & (POLLERR | POLLNVAL)) != 0)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_ERROR, EBADF);
            unsigned char cancellation_byte;
            ssize_t count = read(cancellation_read_fd, &cancellation_byte, 1);
            if (count >= 0)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_CANCELLED,
                                         ECANCELED);
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_ERROR, errno);
        }
        int progress = 0;
        for (size_t index = 0; index < 2; ++index) {
            short events = descriptors[index].revents;
            if ((events & POLLNVAL) != 0)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_ERROR, EBADF);
            if ((events & POLLERR) != 0) {
                int socket_error = 0;
                socklen_t length = sizeof(socket_error);
                if (getsockopt(descriptors[index].fd, SOL_SOCKET, SO_ERROR,
                               &socket_error, &length) != 0)
                    error = errno;
                else if (length != sizeof(socket_error))
                    error = EIO;
                else
                    error = socket_error;
                if (error != 0)
                    return vm27_relay_finish(result, directions,
                                             VM27_STREAM_RELAY_V1_ERROR, error);
            }
            if ((events & (POLLIN | POLLHUP)) != 0) {
                error = vm27_relay_read(&directions[index], &progress);
                if (error != 0)
                    return vm27_relay_finish(result, directions,
                                             VM27_STREAM_RELAY_V1_ERROR, error);
            }
        }
        for (size_t index = 0; index < 2; ++index) {
            /* Attempt writes after both reads, including newly observed EOF.
             * Every send is nonblocking and the fixed buffer bounds memory. */
            error = vm27_relay_write(&directions[index], &progress);
            if (error != 0)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_ERROR, error);
        }
        if (progress) {
            error = vm27_relay_now(&last_progress);
            if (error != 0)
                return vm27_relay_finish(result, directions,
                                         VM27_STREAM_RELAY_V1_ERROR, error);
        }
    }
}
