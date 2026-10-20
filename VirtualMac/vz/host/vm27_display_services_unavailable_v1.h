#ifndef VM27_DISPLAY_SERVICES_UNAVAILABLE_V1_H
#define VM27_DISPLAY_SERVICES_UNAVAILABLE_V1_H
#include <stdint.h>
#ifdef __OBJC__
#import <Foundation/Foundation.h>
/* Own object for the finite UIKit display profile. It provides no Mac display
 * service values; unsupported service messages raise an actual exception. */
__attribute__((visibility("default")))
@interface VM27DSClientV1 : NSObject
@end
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Own refusal API for the one original call site (path, literal flags=2,
 * immutable requirement). A nonzero errno follows its original failure path.
 * This is an own ABI, not a declaration of Apple's private XPC function. */
__attribute__((visibility("default")))
int32_t VM27PluginUnavailableV1(const char *path, uint64_t flags,
                              const void *requirement);
/* The actual callers use a uint32 display ID, pointer and S0-float results.
 * Unavailable queries never produce either result. Forward declaring this
 * real CoreGraphics opaque type preserves its C ABI on iOS and macOS. */
struct CGColorSpace;
__attribute__((noreturn,visibility("default")))
struct CGColorSpace *VM27CGUnavailableV1(uint32_t displayID);
__attribute__((noreturn,visibility("default")))
float VM27HeadroomUnavailableV1(uint32_t displayID);
#ifdef __cplusplus
}
#endif
#endif
