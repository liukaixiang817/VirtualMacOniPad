#ifndef VM27_NO_MAC_PACKET_PORT_V1_H
#define VM27_NO_MAC_PACKET_PORT_V1_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* These private UIKit-profile errors never manufacture a CG event or field.
 * All arguments are borrowed. They throw before acquiring any resource;
 * original callers must retain their genuine exception cleanup tables. */
__attribute__((noreturn)) void VM27RejectPacketV1(const void *allocator,
                                                const void *borrowedData);
__attribute__((noreturn)) void VM27RejectMacKeyV1(const void *source,
                                                uint16_t key, bool down);
__attribute__((noreturn)) void VM27RejectFieldV1(const void *borrowedEvent,
                                              uint32_t field);
#ifdef __cplusplus
}
#endif
#endif
