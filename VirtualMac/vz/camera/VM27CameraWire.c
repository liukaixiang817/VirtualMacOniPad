#include "VM27CameraWire.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

static uint64_t milliseconds(void) {
    struct timespec stamp;
    clock_gettime(CLOCK_MONOTONIC, &stamp);
    return (uint64_t)stamp.tv_sec * 1000 + (uint64_t)stamp.tv_nsec / 1000000;
}

static int transfer(int fd, void *data, size_t size, bool writing, uint64_t deadline) {
    unsigned char *cursor = data;
    while (size) {
        uint64_t now = milliseconds();
        if (now >= deadline) return ETIMEDOUT;
        struct pollfd ready = {fd, writing ? POLLOUT : POLLIN, 0};
        int result = poll(&ready, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return errno;
        if (!result) return ETIMEDOUT;
        ssize_t count = writing ? send(fd, cursor, size, MSG_DONTWAIT) : recv(fd, cursor, size, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) return count == 0 ? ECONNRESET : errno;
        cursor += count;
        size -= (size_t)count;
    }
    return 0;
}

static bool valid(VM27CameraPacket packet) {
    if (packet.profile > 2 || packet.enabled > 1 || packet.mirrored > 1 || packet.length > VM27_CAMERA_MAX_PACKET)
        return false;
    switch (packet.kind) {
        case VM27CameraDemand:
        case VM27CameraState:
            return !packet.width && !packet.height && !packet.length && !packet.mirrored;
        case VM27CameraNV12:
            return !packet.profile && packet.enabled && packet.width >= 2 && packet.width <= 1920 &&
                packet.height >= 2 && packet.height <= 1920 && !((packet.width | packet.height) & 1) &&
                packet.length == (uint32_t)packet.width * packet.height * 3 / 2;
        case VM27CameraJPEG:
            return packet.profile && packet.enabled && !packet.mirrored && packet.length >= 4 &&
                ((packet.profile == 1 && packet.width == 1280 && packet.height == 720) ||
                 (packet.profile == 2 && packet.width == 1920 && packet.height == 1080));
        default: return false;
    }
}

int VM27CameraRead(int fd, VM27CameraPacket *packet, void *payload, size_t capacity) {
    uint8_t header[16];
    uint64_t deadline = milliseconds() + 1000;
    int status = transfer(fd, header, sizeof(header), false, deadline);
    if (status) return status;
    if (header[0] != 'V' || header[1] != 'C' || header[2] != 'A' || header[3] != 1) return EPROTO;
    VM27CameraPacket parsed = {
        header[4], header[5], header[6], header[7],
        (uint16_t)((unsigned)header[8] << 8 | header[9]), (uint16_t)((unsigned)header[10] << 8 | header[11]),
        (uint32_t)header[12] << 24 | (uint32_t)header[13] << 16 | (uint32_t)header[14] << 8 | header[15],
    };
    if (!valid(parsed) || parsed.length > capacity || (parsed.length && !payload)) return EPROTO;
    *packet = parsed;
    return transfer(fd, payload, parsed.length, false, deadline);
}

int VM27CameraWrite(int fd, VM27CameraPacket packet, const void *payload) {
    if (!valid(packet) || (packet.length && !payload)) return EINVAL;
    uint8_t header[16] = {
        'V', 'C', 'A', 1, packet.kind, packet.profile, packet.enabled, packet.mirrored,
        packet.width >> 8, packet.width & 255, packet.height >> 8, packet.height & 255,
        packet.length >> 24, (packet.length >> 16) & 255, (packet.length >> 8) & 255, packet.length & 255,
    };
    uint64_t deadline = milliseconds() + 700;
    int status = transfer(fd, header, sizeof(header), true, deadline);
    return status ? status : transfer(fd, (void *)payload, packet.length, true, deadline);
}
