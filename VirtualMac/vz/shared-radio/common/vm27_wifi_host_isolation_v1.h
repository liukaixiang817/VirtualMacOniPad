#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { VM27_WIFI_HOST_ADDRESS_LIMIT = 128 };
typedef struct {
    uint8_t family; // 4: IPv4, 6: IPv6; bytes are in network order.
    uint8_t bytes[16];
} VM27WiFiHostAddressV1;

static inline bool vm27_wifi_host_address_v1(const uint8_t *address, unsigned family,
                                            const VM27WiFiHostAddressV1 *host, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (host[i].family == family && !memcmp(address, host[i].bytes, family == 4 ? 4 : 16))
            return true;
    return false;
}
static inline uint16_t vm27_wifi_host_be16_v1(const uint8_t *p) {
    return (uint16_t)p[0] << 8 | p[1];
}
static inline bool vm27_wifi_mapped_host_v1(const uint8_t *address,
                                           const VM27WiFiHostAddressV1 *host, size_t count) {
    const uint8_t mapped[12]={0,0,0,0,0,0,0,0,0,0,255,255};
    return !memcmp(address,mapped,12) &&
           (address[12]==127 || vm27_wifi_host_address_v1(address+12,4,host,count));
}
// The physical STA is a separate path from Ethernet NAT. Apply this policy
// before either direction crosses the VM boundary, using a fresh host address
// snapshot. No route to a host service is granted by the radio transport.
static inline bool vm27_wifi_host_frame_allowed_v1(const uint8_t *p, size_t n,
                                                  const VM27WiFiHostAddressV1 *host,
                                                  size_t count, bool snapshotValid) {
    if (!p || n < 14 || n > 1518 || !snapshotValid ||
        count > VM27_WIFI_HOST_ADDRESS_LIMIT || (count && !host)) return false;
    uint16_t type = vm27_wifi_host_be16_v1(p + 12);
    const uint8_t *body = p + 14; size_t size = n - 14;
    if (type == 0x0806) {
        if (size < 28 || vm27_wifi_host_be16_v1(body) != 1 ||
            vm27_wifi_host_be16_v1(body + 2) != 0x0800 || body[4] != 6 || body[5] != 4)
            return false;
        return !vm27_wifi_host_address_v1(body + 14, 4, host, count) &&
               !vm27_wifi_host_address_v1(body + 24, 4, host, count);
    }
    if (type == 0x0800) {
        if (size < 20 || body[0] >> 4 != 4) return false;
        size_t header = (body[0] & 15) * 4, total = vm27_wifi_host_be16_v1(body + 2);
        if (header < 20 || header > total || total > size) return false;
        if (body[12] == 127 || body[16] == 127 || body[16] == 0) return false;
        return !vm27_wifi_host_address_v1(body + 12, 4, host, count) &&
               !vm27_wifi_host_address_v1(body + 16, 4, host, count);
    }
    if (type == 0x86dd) {
        if (size < 40 || body[0] >> 4 != 6) return false;
        size_t total = 40 + vm27_wifi_host_be16_v1(body + 4);
        if (total > size) return false;
        const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (!memcmp(body + 8, loopback, 16) || !memcmp(body + 24, loopback, 16) ||
            vm27_wifi_host_address_v1(body + 8, 6, host, count) ||
            vm27_wifi_host_address_v1(body + 24, 6, host, count) ||
            vm27_wifi_mapped_host_v1(body + 8, host, count) ||
            vm27_wifi_mapped_host_v1(body + 24, host, count)) return false;
        // NS/NA may name a host in their target while using multicast as the
        // outer destination. Parse bounded extension headers before the target.
        uint8_t next = body[6]; size_t at = 40;
        for (unsigned i = 0; next == 0 || next == 43 || next == 60; ++i) {
            if (i == 8 || total - at < 8) return false;
            size_t bytes = ((size_t)body[at + 1] + 1) * 8;
            if (bytes > total - at) return false;
            next = body[at]; at += bytes;
        }
        // Fragmented NDP is not forwarded; other IPv6 fragments retain the
        // already checked outer source/destination address policy.
        if (next == 44) return total - at >= 8 && (body[at] == 6 || body[at] == 17);
        if (next == 58 && total - at >= 1 && (body[at] == 135 || body[at] == 136))
            return total - at >= 24 && !vm27_wifi_host_address_v1(body + at + 8, 6, host, count);
        return true;
    }
    // VLAN encapsulation and unknown EtherTypes cannot bypass IP/ARP checks.
    return false;
}
