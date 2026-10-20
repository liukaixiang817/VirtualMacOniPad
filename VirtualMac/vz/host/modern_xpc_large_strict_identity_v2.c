/* Ordinary app-private strict identity-result wiring; no execution adapters. */
#include "modern_xpc_large_strict_identity_v2.h"
#include <bsm/audit.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

static bool ReviewedHex(const char *text, size_t bytes) {
    if (!text || strnlen(text, bytes + 1) != bytes) return false;
    for (size_t i = 0; i < bytes; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') ||
              (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
static void Hex20(const unsigned char digest[20], char text[41]) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 20; ++i) {
        text[2 * i] = alphabet[digest[i] >> 4];
        text[2 * i + 1] = alphabet[digest[i] & 15];
    }
    text[40] = 0;
}
int VM27LargeStrictIdentityV2CheckReceivedMessage(
    const VM27LargeServicePlan *plan, const char *SHA, const char *CD,
    xpc_object_t message, VM27ApprovedCodeMessageResult *out) {
    if (!out) return EINVAL;
    memset(out, 0, sizeof(*out));
    int status = EINVAL;
    if (!plan || !ReviewedHex(SHA, 64) || !ReviewedHex(CD, 40) ||
        !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) goto finish;

    /* This function rechecks the bounded actual registry file pins and calls
     * the unchanged Security native received-message policy. */
    status = VM27LargeServicePlanCheckReceivedMessage(plan, message,
                                                     &out->nativePolicy);
    if (status) goto finish;
    const VM27LWCRMessageResult *native = &out->nativePolicy;
    if (native->result || !native->hasRemoteConnection || !native->taskCreated ||
        !native->entitlementsValidated || !native->entitlementPresent ||
        !native->entitlementIsBoolean || !native->entitlementValue ||
        native->entitlementReadError) { status = EPROTO; goto finish; }

    VM27LargeServiceInfo info = {0};
    status = VM27LargeServicePlanCopyInfo(plan, &info);
    if (status) goto finish;
    if (info.flags != 2 || !info.executableBytes ||
        info.executableBytes > UINT64_C(8) * 1024 * 1024 ||
        memcmp(info.executableSHA256, SHA, 65)) {
        status = EACCES; goto finish;
    }
    out->filePinMatched = true;

    audit_token_t token = {{0}};
    xpc_dictionary_get_audit_token(message, &token);
    out->auditPID = token.val[5]; out->auditPIDVersion = token.val[7];
    out->auditTokenPresent = out->auditPID > 1 && out->auditPID <= INT32_MAX &&
                             out->auditPIDVersion != 0;
    if (!out->auditTokenPresent) { status = EACCES; goto finish; }

    unsigned char digest[20] = {0};
    errno = 0;
    if (csops_audittoken((pid_t)out->auditPID, 5, digest, sizeof(digest), &token)) {
        out->codeQueryError = errno ? errno : EIO;
        status = out->codeQueryError; goto finish;
    }
    Hex20(digest, out->kernelCDHash);
    out->codeHashMatched = !strcmp(out->kernelCDHash, CD);
    uint32_t flags = 0;
    errno = 0;
    if (csops_audittoken((pid_t)out->auditPID, 0, &flags, sizeof(flags), &token)) {
        out->statusQueryError = errno ? errno : EIO;
        status = out->statusQueryError; goto finish;
    }
    out->codeStatus = flags;
    out->dynamicCodeValid = (flags & UINT32_C(1)) != 0;
    status = out->codeHashMatched && out->dynamicCodeValid ? 0 : EACCES;
finish:
    out->result = status;
    /* explicitApprovedCodeAccepted remains false on every strict path. */
    return status;
}
