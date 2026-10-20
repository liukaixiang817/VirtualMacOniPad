/* An independent, explicit owned-code decision. No native trust flag,
 * SecTaskEntitlementsValidated result, requirement or old policy is changed. */
#include "vm27_owned_bundle_approved_policy_v1.h"
#include <errno.h>
#include <limits.h>
#include <mach/message.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

#define VM27_OWNED_BUNDLE_POLICY_MAGIC_V1 UINT64_C(0x564d323742415031)

struct VM27OwnedBundleApprovedPolicyV1 {
    uint64_t magic;
    const VM27LargeServicePlan *plan;
    VM27LWCRPolicy *nativePolicy;
    VM27BundleParentConfigurationV1 child;
    VM27BundleParentInspectionV1 initial;
    VM27LargeServiceInfo planInfo;
    char bundlePath[4096], name[256], sha[65], cd[41];
};

static bool HexV1(const char *value, size_t length) {
    if (!value || strnlen(value, length + 1) != length) return false;
    for (size_t i = 0; i < length; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}

static bool InspectedV1(const VM27BundleParentInspectionV1 *value) {
    return value->formatVersion == 1 && value->codePagesVerified &&
        value->embeddedSlotsVerified && value->externalInfoSlotVerified &&
        value->externalResourcesSlotVerified && value->descriptorsAndNamesStable &&
        value->infoExecutableNameMatched && value->codeResourcesIsDictionary &&
        value->signedPluginPresent && value->signedPluginIsBoolean && value->signedPluginValue;
}

static bool SameInspectionV1(const VM27BundleParentInspectionV1 *a,
                             const VM27BundleParentInspectionV1 *b) {
    return InspectedV1(a) && InspectedV1(b) && a->actualOwnerUID == b->actualOwnerUID &&
        a->executableBytes == b->executableBytes && a->infoPlistBytes == b->infoPlistBytes &&
        a->codeResourcesBytes == b->codeResourcesBytes && a->codePages == b->codePages &&
        !strcmp(a->executableSHA256, b->executableSHA256) &&
        !strcmp(a->executableCDHash, b->executableCDHash) &&
        !strcmp(a->executableUUID, b->executableUUID) &&
        !strcmp(a->infoPlistSHA256, b->infoPlistSHA256) &&
        !strcmp(a->codeResourcesSHA256, b->codeResourcesSHA256);
}

static int VerifyFilesV1(const VM27OwnedBundleApprovedPolicyV1 *policy,
                         VM27BundleParentInspectionV1 *inspection) {
    int status = VM27LargeServicePlanVerify(policy->plan);
    if (!status) status = VM27BundleChildInspectV1(&policy->child, inspection);
    if (!status && !SameInspectionV1(&policy->initial, inspection)) status = ESTALE;
    /* Keep the exact registered FD/name pins valid through inspection too. */
    if (!status) status = VM27LargeServicePlanVerify(policy->plan);
    return status;
}

int VM27OwnedBundleApprovedPolicyCreateV1(
    const VM27BundleParentConfigurationV1 *child,
    const VM27LargeServicePlan *plan, xpc_object_t requirement,
    VM27OwnedBundleApprovedPolicyV1 **result) {
    if (!result) return EINVAL;
    *result = NULL;
    if (!child || !plan || !requirement || !child->bundlePath || !child->executableName ||
        child->expectedOwnerUID != geteuid() || child->bundlePath[0] != '/' ||
        strnlen(child->bundlePath, 4096) >= 4096 ||
        !strnlen(child->executableName, 256) || strnlen(child->executableName, 256) >= 256 ||
        !HexV1(child->reviewedExecutableSHA256, 64) ||
        !HexV1(child->reviewedExecutableCDHash, 40)) return EINVAL;
    VM27OwnedBundleApprovedPolicyV1 *created = calloc(1, sizeof(*created));
    if (!created) return ENOMEM;
    created->plan = plan;
    strcpy(created->bundlePath, child->bundlePath);
    strcpy(created->name, child->executableName);
    strcpy(created->sha, child->reviewedExecutableSHA256);
    strcpy(created->cd, child->reviewedExecutableCDHash);
    created->child = (VM27BundleParentConfigurationV1){created->bundlePath, created->name,
        created->sha, created->cd, child->expectedOwnerUID};
    int status = VM27LargeServicePlanVerify(plan);
    if (!status) status = VM27LargeServicePlanCopyInfo(plan, &created->planInfo);
    char executable[4096];
    int length = snprintf(executable, sizeof(executable), "%s/Contents/MacOS/%s",
                          created->bundlePath, created->name);
    if (!status && (length < 0 || (size_t)length >= sizeof(executable) ||
        strcmp(executable, created->planInfo.executablePath) ||
        strcmp(created->sha, created->planInfo.executableSHA256) ||
        created->planInfo.flags != 2)) status = EACCES;
    if (!status) status = VM27BundleChildInspectV1(&created->child, &created->initial);
    if (!status && (!InspectedV1(&created->initial) ||
        strcmp(created->initial.executableUUID, created->planInfo.executableUUID) ||
        created->initial.executableBytes != created->planInfo.executableBytes)) status = EACCES;
    if (!status) status = VM27LargeServicePlanVerify(plan);
    if (!status) status = VM27LWCRPolicyCreate(requirement, &created->nativePolicy);
    if (status) { free(created); return status; }
    created->magic = VM27_OWNED_BUNDLE_POLICY_MAGIC_V1;
    *result = created;
    return 0;
}

void VM27OwnedBundleApprovedPolicyReleaseV1(VM27OwnedBundleApprovedPolicyV1 *policy) {
    if (!policy || policy->magic != VM27_OWNED_BUNDLE_POLICY_MAGIC_V1) abort();
    policy->magic = 0;
    VM27LWCRPolicyRelease(policy->nativePolicy);
    free(policy);
}

int VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(
    const VM27OwnedBundleApprovedPolicyV1 *policy, xpc_object_t message,
    VM27ApprovedCodeMessageResult *result) {
    VM27ApprovedCodeMessageResult detail = {0}; detail.result = EACCES;
    if (!policy || policy->magic != VM27_OWNED_BUNDLE_POLICY_MAGIC_V1) {
        detail.result = EINVAL; goto done;
    }
    if (result) {
        uintptr_t at = (uintptr_t)result, begin = (uintptr_t)policy;
        if (at > UINTPTR_MAX - sizeof(*result) ||
            (at < begin + sizeof(*policy) && begin < at + sizeof(*result))) return EINVAL;
    }
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY ||
        !xpc_dictionary_get_remote_connection(message)) goto done;
    VM27BundleParentInspectionV1 inspected = {0};
    int status = VerifyFilesV1(policy, &inspected);
    if (status) { detail.result = status; goto done; }
    detail.filePinMatched = true;
    /* One genuine query; false/13 is retained, never rewritten as native success. */
    (void)VM27LWCRPolicyCheckReceivedMessage(policy->nativePolicy, message, &detail.nativePolicy);
    audit_token_t token = {{0}};
    xpc_dictionary_get_audit_token(message, &token);
    detail.auditPID = token.val[5]; detail.auditPIDVersion = token.val[7];
    detail.auditTokenPresent = detail.auditPID > 1 && detail.auditPID <= INT32_MAX &&
        detail.auditPIDVersion != 0;
    if (!detail.auditTokenPresent) goto done;
    unsigned char cdhash[20] = {0};
    if (csops_audittoken((pid_t)detail.auditPID, 5, cdhash, sizeof(cdhash), &token))
        detail.codeQueryError = errno ? errno : EIO;
    if (detail.codeQueryError) goto done;
    for (size_t i = 0; i < sizeof(cdhash); ++i)
        snprintf(detail.kernelCDHash + i * 2, 3, "%02x", cdhash[i]);
    detail.codeHashMatched = !strcmp(detail.kernelCDHash, policy->cd);
    if (csops_audittoken((pid_t)detail.auditPID, 0, &detail.codeStatus, sizeof(detail.codeStatus), &token))
        detail.statusQueryError = errno ? errno : EIO;
    detail.dynamicCodeValid = !detail.statusQueryError && (detail.codeStatus & 1) != 0;
    if (detail.codeHashMatched && detail.dynamicCodeValid &&
        detail.nativePolicy.hasRemoteConnection && detail.nativePolicy.taskCreated &&
        !detail.nativePolicy.entitlementReadError && detail.nativePolicy.entitlementPresent &&
        detail.nativePolicy.entitlementIsBoolean && detail.nativePolicy.entitlementValue) {
        /* No file/name change during the real native queries may be accepted. */
        memset(&inspected, 0, sizeof(inspected));
        status = VerifyFilesV1(policy, &inspected);
        if (status) { detail.filePinMatched = false; detail.result = status; goto done; }
        detail.explicitApprovedCodeAccepted = true; detail.result = 0;
    }
done:
    if (result) *result = detail;
    return detail.result;
}
