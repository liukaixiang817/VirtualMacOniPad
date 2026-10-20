#ifndef VM27_PROCESS_TITLE_STATE_V1_H
#define VM27_PROCESS_TITLE_STATE_V1_H
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern const CFStringRef _kLSDisplayNameKey;
// Borrowed provider-private process identity. It is not a system LSASN and
// may be forwarded only to this provider's scoped setter, as original VZ does.
CFTypeRef _LSGetCurrentApplicationASN(void);
int32_t _LSSetApplicationInformationItem(int32_t session, CFTypeRef identity,
    CFStringRef key, CFTypeRef value, CFTypeRef *unsupportedOutput);
// Retained readback for the private frontend/diagnostics, null if never set.
CFStringRef VM27CopyPrivateProcessDisplayName(void) CF_RETURNS_RETAINED;
#ifdef __cplusplus
}
#endif
#endif
