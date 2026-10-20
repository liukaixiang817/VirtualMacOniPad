#ifndef VM27_CLIENT_REGISTRATION_V1_H
#define VM27_CLIENT_REGISTRATION_V1_H
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>
#ifdef __cplusplus
extern "C" {
#endif
/* One private peer selected by our owned service bootstrap. Configure before
 * accepting its native control messages; no system LaunchServices registration. */
int VM27ClientRegistrationConfigureV1(pid_t expectedPeerPID,
    const char *reviewedPeerCDHash, uint64_t privateBootstrapNonce);
/* Actual received native dictionary only. Native message/connection audit
 * tokens, PID version and current kernel CDHash/CS_VALID must all agree. */
int VM27ClientRegistrationReceiveV1(xpc_object_t actualReceivedMessage);
extern const CFStringRef _kLSPIDKey;
/* Original consumed ABI: effective signed32 session, effective32 count, live
 * arrays of count CF pointers. Only one registered PID pair is supported. */
CFArrayRef _LSCopyMatchingApplicationsWithItems(int32_t session, uint32_t count,
    const CFStringRef *liveKeys, const CFTypeRef *liveValues) CF_RETURNS_RETAINED;
/* Borrowed identity obtained from this provider's retained matching array only.
 * Return is retained real CFString. Unknown identity/key/peer fails NULL. */
CFTypeRef _LSCopyApplicationInformationItem(int32_t session,
    CFTypeRef privateClientIdentity, CFStringRef key) CF_RETURNS_RETAINED;
#ifdef __cplusplus
}
#endif
#endif
