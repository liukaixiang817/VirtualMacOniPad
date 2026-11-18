// Build-specific payloads audited against the exact Apple VMAPPLE collections.
// These are independent of the authenticated C++ vtable declarations.
#pragma once
#include <stdint.h>
#include <string.h>

#if !defined(VM27_NATIVE_BEACON_HEADER_BYTES) || !defined(VM27_NATIVE_EXTENDED_RSN_OFFSET) || !defined(VM27_NATIVE_EXTENDED_BE_VERSION_OFFSET) || !defined(VM27_NATIVE_LQM_BYTES)
#error Build-specific wireless payload layout is required
#endif

namespace VM27WiFiPayloadV1 {
enum : uint32_t {
    beaconHeader = VM27_NATIVE_BEACON_HEADER_BYTES,
    beaconFlags = beaconHeader - 4,
    rsnOffset = VM27_NATIVE_EXTENDED_RSN_OFFSET,
    // Write only the defined fields, without assuming the caller's padding.
    extendedBytes = rsnOffset + 0x101,
    beVersionOffset = VM27_NATIVE_EXTENDED_BE_VERSION_OFFSET,
    lqmBytes = VM27_NATIVE_LQM_BYTES,
    lqmTrafficOffset = lqmBytes == 0x250 ? 0x64 : 0x14,
    lqmCallbackOffset = lqmBytes == 0x250 ? 0xa4 : 0x54,
    lqmCountersOffset = lqmBytes == 0x250 ? 0x230 : 0x1d8
};
static_assert(beaconHeader == 0x40 || beaconHeader == 0x44, "audited beacon layout");
static_assert(rsnOffset == 0xdd || rsnOffset == 0x113 || rsnOffset == 0x120, "audited RSN layout");
static_assert(lqmBytes == 0x150 || lqmBytes == 0x1dc || lqmBytes == 0x250, "audited LQM layout");

template <typename T> inline void store(void *data, uint32_t offset, T value) {
    memcpy((uint8_t *)data + offset, &value, sizeof(value));
}

inline void buildLqm(uint8_t *message, int32_t rssi, uint32_t tick,
                     uint32_t receivedFrames, uint32_t beacons) {
    // IO80211InfraInterface::postMessage mutates this buffer before dispatch.
    // On 27 it unconditionally writes eight bytes at +0x238 for event 0x27;
    // the old 26 allocation (0x1dc) therefore corrupts the adjacent object.
    memset(message, 0, lqmBytes);
    message[0] = 1;
    store<int32_t>(message, 4, rssi);
    message[lqmCallbackOffset] = 1;
    if (lqmBytes != 0x150) {
        store<uint32_t>(message, lqmTrafficOffset, tick);
        store<uint32_t>(message, lqmTrafficOffset + 8, tick + 1);
        store<uint32_t>(message, lqmTrafficOffset + 0x10, receivedFrames ? receivedFrames : 1);
        store<uint32_t>(message, lqmTrafficOffset + 0x14, beacons);
        message[lqmTrafficOffset + 0x1c] = 1;
        message[lqmCountersOffset] = message[lqmCountersOffset + 1] = 1;
    }
}

template <typename Bss> inline uint32_t buildBeacon(uint8_t *message, const Bss &bss,
                                                  uint32_t maxIE, uint16_t chanspec) {
    const uint32_t ieLength = bss.ie_len > maxIE ? maxIE : bss.ie_len;
    const uint8_t ssidLength = bss.ssid_len > 32 ? 32 : bss.ssid_len;
    memset(message, 0, beaconHeader);
    store<uint32_t>(message, 0, ieLength);
    store<uint16_t>(message, 4, chanspec);
    memcpy(message + 6, bss.ssid, ssidLength);
    message[0x26] = ssidLength;
    message[0x27] = bss.channel;
    memcpy(message + 0x29, bss.bssid, 6);
    store<int32_t>(message, 0x30, bss.rssi);
    store<uint16_t>(message, 0x38, bss.beacon_interval);
    store<uint16_t>(message, 0x3a, bss.capability);
    store<uint32_t>(message, beaconFlags, 2u | (bss.probe_resp ? 0u : 0x80u) | (bss.rssi ? 0x4000u : 0u));
    memcpy(message + beaconHeader, bss.ie, ieLength);
    return beaconHeader + ieLength;
}

inline void initializeExtendedBss(uint8_t *data) {
    const uint32_t offsets[5] = {0, 0xbc, 0xcc, 0xd4, beVersionOffset};
    const unsigned count = beVersionOffset ? 5 : 4;
    uint32_t versions[5];
    for (unsigned i = 0; i < count; ++i) memcpy(&versions[i], data + offsets[i], 4);
    memset(data, 0, extendedBytes);
    for (unsigned i = 0; i < count; ++i) store<uint32_t>(data, offsets[i], versions[i]);
    store<uint16_t>(data, 0xd0, 0xffff);
    store<uint16_t>(data, 0xd8, 0xffff);
}
} // namespace VM27WiFiPayloadV1
