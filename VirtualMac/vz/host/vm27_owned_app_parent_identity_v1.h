#ifndef VM27_OWNED_APP_PARENT_IDENTITY_V1_H
#define VM27_OWNED_APP_PARENT_IDENTITY_V1_H
#include <xpc/xpc.h>
#include <stdint.h>
#include <stdbool.h>
typedef struct {
 uint32_t auditPID,auditPIDVersion,codeStatus,baseCapabilityMask;
 char kernelCDHash[41];
 bool nativeEntitlementsValidated;
} VM27OwnedAppParentIdentityV1;
/* Fresh actual dictionary+connection token equality, getppid, kernel CD and
 * CS_VALID, plus both native connection and genuine CFBoolean entitlements.
 * Reuses the exact reviewed V10 native getter ABI; no message-body authority.
 * nativeEntitlementsValidated is diagnostic, never fabricated or substituted
 * for the unchanged V10 dual-Boolean policy. No file hash input is accepted. */
int VM27OwnedAppCheckActualParentMessageV1(xpc_object_t actualMessage,
 VM27OwnedAppParentIdentityV1 *actualIdentity);
#endif
