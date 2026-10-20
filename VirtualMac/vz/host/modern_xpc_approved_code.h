#ifndef VM27_MODERN_XPC_APPROVED_CODE_H
#define VM27_MODERN_XPC_APPROVED_CODE_H
#include "modern_xpc_lwcr_policy.h"
#include <stddef.h>
#include <stdint.h>

typedef struct VM27ApprovedCodePolicy VM27ApprovedCodePolicy;
typedef struct {
    char fileSHA256[65], CDHash[41], UUID[33];
    uint64_t bytes;
    uint32_t codePages;
    bool pagesVerified, embeddedSlotsVerified;
    bool pluginPresent, pluginIsBoolean, pluginValue;
} VM27ApprovedCodeInfo;
typedef struct {
    VM27LWCRMessageResult nativePolicy;
    int result, codeQueryError, statusQueryError;
    uint32_t auditPID, auditPIDVersion, codeStatus;
    char kernelCDHash[41];
    bool filePinMatched, auditTokenPresent, codeHashMatched, dynamicCodeValid;
    bool explicitApprovedCodeAccepted;
} VM27ApprovedCodeMessageResult;
typedef struct {
    uint64_t created, destroyed, messageChecks, accepted, rejected;
    uint64_t codeQueries, statusQueries;
} VM27ApprovedCodeStats;

/* Bounded thin arm64 SHA256 ad-hoc CodeDirectory20400 diagnostic contract.
 * Authenticates every code page and embedded slots2/5/7, rejects external
 * resource hashes and scatter/alternate CD formats. Not a trust decision. */
int VM27ApprovedCodeInspectBytes(const unsigned char *bytes, size_t count,
                                VM27ApprovedCodeInfo *result);
/* Explicit app-private authorization: both expected hashes are mandatory,
 * supplied by the approving caller, and compared with actual verified code.
 * The exact original27 LWCR and authenticated Boolean true remain required. */
int VM27ApprovedCodePolicyCreate(const char *absoluteOwnedExecutable,
                                const char *expectedSHA256,
                                const char *expectedCDHash,
                                xpc_object_t originalRequirement,
                                VM27ApprovedCodePolicy **result);
void VM27ApprovedCodePolicyRelease(VM27ApprovedCodePolicy *policy);
/* A separate opt-in compatibility gate; original strict LWCR is unchanged.
 * Requires the particular received message's kernel audit token, matching
 * csops_audittoken CDHash, CS_VALID and a native Boolean true entitlement. */
int VM27ApprovedCodeCheckReceivedMessage(const VM27ApprovedCodePolicy *policy,
                                        xpc_object_t message,
                                        VM27ApprovedCodeMessageResult *result);
void VM27ApprovedCodeCopyStats(VM27ApprovedCodeStats *result);
#endif
