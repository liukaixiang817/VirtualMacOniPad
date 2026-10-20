#ifndef VM27_SCOPED_DISPLAY_ROUTES_H
#define VM27_SCOPED_DISPLAY_ROUTES_H
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>

/* Application-private provider for two audited original VZ imports. It is
 * not a global interposer or a complete SkyLight system replacement. */
#ifdef __cplusplus
extern "C" {
#endif
uint32_t SLMainDisplayID(void);
CFDictionaryRef SLSCopyDisplayInfoDictionary(uint32_t displayID) CF_RETURNS_RETAINED;
#ifdef __cplusplus
}
#endif
#endif
