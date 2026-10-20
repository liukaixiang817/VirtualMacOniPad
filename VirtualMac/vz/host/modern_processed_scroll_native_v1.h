#ifndef VM27_PROCESSED_SCROLL_NATIVE_V1_H
#define VM27_PROCESSED_SCROLL_NATIVE_V1_H
#include "modern_input_packet_v2.h"
#include <CoreFoundation/CoreFoundation.h>

/* Finite source port: processed two-finger pan only. The native factory owns
 * the real type6 event. It does not dispatch to any service or input system.
 * Each unsuccessful entry leaves output untouched. Native timestamps use the
 * original27 arithmetic with the real host Mach timebase; UIKit's clock origin
 * still requires actual platform validation before backend admission. */
int vm27_processed_scroll_native_profile_matches(void);
VM27InputResult vm27_processed_scroll_mach_ticks(double seconds, uint32_t numer,
                                                uint32_t denom, uint64_t *output);
/* +1 genuine native object on success. No raw/accelerated/momentum/sender data
 * is represented. Quantization to the native signed16.16 packet is explicit;
 * unrepresentable finite deltas are rejected rather than saturated. */
VM27InputResult vm27_processed_scroll_create_owned(const VM27InputPacket *, CFTypeRef *output);
void vm27_processed_scroll_release_owned(CFTypeRef *event);
#endif
