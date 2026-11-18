#include "vm27_shared_radio_wire_v1.h"
#include <errno.h>
#include <string.h>

static uint64_t get(const uint8_t *p, unsigned n) {
    uint64_t value = 0;
    while (n--) value = (value << 8) | *p++;
    return value;
}
static void put(uint8_t *p, uint64_t value, unsigned n) {
    while (n) { p[--n] = (uint8_t)value; value >>= 8; }
}
static int valid(const struct vm27_radio_frame_v1 *f) {
    if (!f || f->type < VM27_RADIO_HELLO || f->type > VM27_RADIO_HCI_EVENT ||
        f->payload_bytes > VM27_RADIO_WIRE_MAX_PAYLOAD || !f->request_id) return EPROTO;
    if (f->type == VM27_RADIO_HELLO) return f->generation ? EPROTO : 0;
    return f->generation ? 0 : EPROTO;
}
int vm27_radio_header_encode_v1(uint8_t out[32], const struct vm27_radio_frame_v1 *f) {
    if (!out) return EINVAL;
    int error = valid(f); if (error) return error;
    memset(out, 0, 32); memcpy(out, "VMR1", 4);
    put(out + 4, VM27_RADIO_WIRE_VERSION, 2); put(out + 6, f->type, 2);
    put(out + 8, f->payload_bytes, 4); put(out + 16, f->request_id, 8);
    put(out + 24, f->generation, 8); return 0;
}
int vm27_radio_header_decode_v1(const uint8_t *p, size_t n, struct vm27_radio_frame_v1 *out) {
    if (!p || !out) return EINVAL;
    if (n < 32) return EAGAIN;
    if (memcmp(p, "VMR1", 4) || get(p + 4, 2) != VM27_RADIO_WIRE_VERSION || get(p + 12, 4)) return EPROTO;
    struct vm27_radio_frame_v1 f = {(uint16_t)get(p + 6, 2), (uint32_t)get(p + 8, 4),
        get(p + 16, 8), get(p + 24, 8)};
    int error = valid(&f); if (error) return error;
    *out = f; return 0;
}
