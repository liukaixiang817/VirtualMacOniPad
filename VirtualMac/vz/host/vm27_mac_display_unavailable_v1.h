#ifndef VM27_MAC_DISPLAY_UNAVAILABLE_V1_H
#define VM27_MAC_DISPLAY_UNAVAILABLE_V1_H
#include <stdint.h>
struct CGColorSpace;
#ifdef __cplusplus
extern "C" {
#endif
/* Only the unavailable macOS display-ID profile reaches these entries.
 * They never substitute a color space or report fabricated HDR headroom. */
__attribute__((noreturn,visibility("default")))
struct CGColorSpace *VM27MacDisplayColorSpaceUnavailableV1(uint32_t displayID);
__attribute__((noreturn,visibility("default")))
float VM27MacDisplayHeadroomUnavailableV1(uint32_t displayID);
#ifdef __cplusplus
}
#endif
#endif
