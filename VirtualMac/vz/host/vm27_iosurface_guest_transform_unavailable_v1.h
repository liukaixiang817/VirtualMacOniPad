#ifndef VM27_IOSURFACE_GUEST_TRANSFORM_UNAVAILABLE_V1_H
#define VM27_IOSURFACE_GUEST_TRANSFORM_UNAVAILABLE_V1_H
#include <IOKit/IOReturn.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Caller owns a readable/writable packet of the declared extent. No
 * accelerator object, IOSurface, native driver, or embedded pointer is read.
 * This distinct own entry reports a capability failure, never translation. */
__attribute__((visibility("default")))
IOReturn VM27IOSurfaceGuestTransformUnavailableV1(const void *actualAccelerator,
                                                void *packet,size_t packetBytes);
#ifdef __cplusplus
}
#endif
#endif
