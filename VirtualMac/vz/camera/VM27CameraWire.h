#ifndef VM27_CAMERA_WIRE_H
#define VM27_CAMERA_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define VM27_CAMERA_VSOCK_PORT 39033u
#define VM27_CAMERA_MAX_PACKET (1920u * 1080u * 2u)

enum VM27CameraPacketKind {
    VM27CameraDemand = 1,
    VM27CameraState,
    VM27CameraNV12,
    VM27CameraJPEG,
};

typedef struct {
    uint8_t kind;
    uint8_t profile;
    uint8_t enabled;
    uint8_t mirrored;
    uint16_t width;
    uint16_t height;
    uint32_t length;
} VM27CameraPacket;

// One request and one reply at a time. The descriptor is owned by the caller.
// Returns zero or errno. A partial or invalid record retires the connection.
int VM27CameraRead(int fd, VM27CameraPacket *packet, void *payload, size_t capacity);
int VM27CameraWrite(int fd, VM27CameraPacket packet, const void *payload);

#endif
