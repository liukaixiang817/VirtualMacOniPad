#ifndef VM27_DISPLAY_FRAME_TIMING_V1_H
#define VM27_DISPLAY_FRAME_TIMING_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Dormant unless the exact running display owner starts a finite capture.
 * Metadata only: no pixels, waits, ACK changes or per-frame logging. */
void VM27DisplayFrameArrivalTimingV1(uint64_t sequence);
#ifdef __cplusplus
}
#endif
#ifdef __OBJC__
#import "vm27_uikit_guest_display_v1.h"
@interface VM27UIKitGuestDisplayV1 (VM27FiniteFrameTimingV1)
- (BOOL)vm27_beginFiniteFrameTimingForVirtualMachineV1:(id)vm;
@end
#endif
#endif
