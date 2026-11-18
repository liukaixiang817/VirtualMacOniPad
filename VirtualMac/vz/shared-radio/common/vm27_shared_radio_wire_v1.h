#ifndef VM27_SHARED_RADIO_WIRE_V1_H
#define VM27_SHARED_RADIO_WIRE_V1_H
#include <stddef.h>
#include <stdint.h>

enum {
    VM27_RADIO_WIRE_HEADER = 32,
    VM27_RADIO_WIRE_MAX_PAYLOAD = 65536,
    VM27_RADIO_WIRE_VERSION = 1,
    VM27_RADIO_VSOCK_PORT = 39027,
    VM27_RADIO_HELLO = 1,
    VM27_RADIO_HELLO_REPLY = 2,
    VM27_RADIO_REQUEST = 3,
    VM27_RADIO_REPLY = 4,
    VM27_RADIO_ETHERNET = 5,
    VM27_RADIO_HCI_COMMAND = 6,
    VM27_RADIO_HCI_EVENT = 7,
};
struct vm27_radio_frame_v1 {
    uint16_t type;
    uint32_t payload_bytes;
    uint64_t request_id;
    uint64_t generation;
};
/* Fixed big-endian fields, independent of compiler packing and host ABI.
 * Bytes 12..15 are reserved and must be zero. Decode never reads a payload. */
int vm27_radio_header_encode_v1(uint8_t out[32], const struct vm27_radio_frame_v1 *frame);
int vm27_radio_header_decode_v1(const uint8_t *bytes, size_t length,
                              struct vm27_radio_frame_v1 *out);
#endif
