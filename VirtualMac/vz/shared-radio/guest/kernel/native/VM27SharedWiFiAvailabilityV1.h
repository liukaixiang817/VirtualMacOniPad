// 26A5416b: AppleBCMWLANCore::powerOn posts event 0x37, version 3,
// 0xf8 bytes, available at +8, reason 0xe0821803 at +0x10.
// Both WCLSystemStateManager and IO80211ControllerMonitor require that size.
// This announces a usable driver transport; it never claims an association.
#pragma once
#include <stdint.h>
#include <string.h>
#ifndef VM27_NATIVE_DRIVER_AVAILABLE_EVENT_BYTES
#define VM27_NATIVE_DRIVER_AVAILABLE_EVENT_BYTES 0
#endif
namespace VM27WiFiAvailabilityV1 {
constexpr uint32_t eventCode = 0x37;
constexpr uint32_t eventBytes = 0xf8;
inline bool shouldAnnounce(bool announced, bool bound, bool datapathEnabled,
                           bool guestPowerOn, bool hostClientOnline,
                           bool independentAssociationAvailable) {
    return !announced && bound && datapathEnabled && guestPowerOn &&
           hostClientOnline && independentAssociationAvailable;
}
inline void buildAvailable(uint8_t (&message)[eventBytes]) {
    memset(message, 0, sizeof(message));
    const uint32_t version = 3, available = 1, reason = 0xe0821803u;
    memcpy(message, &version, 4);
    memcpy(message + 8, &available, 4);
    memcpy(message + 0x10, &reason, 4);
}
}
