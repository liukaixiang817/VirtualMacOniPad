/* HOST model only: genuine on-disk child signature + real Registry/Plan/FD
 * checks. Received connection/audit/SecTask/kernel queries are explicit mocks;
 * this file is not compiled into any product provider. */
#define VM27LWCRPolicyCheckReceivedMessage ModelNativeCheckV1
#define xpc_dictionary_get_remote_connection ModelRemoteV1
#define xpc_dictionary_get_audit_token ModelAuditV1
#define csops_audittoken ModelCsopsV1
#include "vm27_owned_bundle_approved_policy_v1.c"
#undef VM27LWCRPolicyCheckReceivedMessage
#undef xpc_dictionary_get_remote_connection
#undef xpc_dictionary_get_audit_token
#undef csops_audittoken
#include <fcntl.h>

static unsigned checks, nativeCalls, codeCalls, statusCalls;
static int mode;
static char resourcesPath[4096], executablePath[4096];
static unsigned char expectedCD[20];
static char mutationPath[4096];
static unsigned char originalByte;
static bool mutated;
static void NeedV1(bool condition, const char *label) {
    ++checks;
    if (!condition) { fprintf(stderr, "FAIL %s mode=%d errno=%d\n", label, mode, errno); exit(90); }
}
static void FlipV1(const char *path) {
    NeedV1(!mutated, "one owned mutation only");
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    NeedV1(fd >= 0, "open own fixture mutation");
    NeedV1(pread(fd, &originalByte, 1, 0) == 1, "read own byte");
    unsigned char replacement = originalByte ^ 1;
    NeedV1(pwrite(fd, &replacement, 1, 0) == 1, "write own byte");
    NeedV1(close(fd) == 0, "close mutation");
    strcpy(mutationPath, path); mutated = true;
}
static void RestoreV1(void) {
    if (!mutated) return;
    int fd = open(mutationPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    NeedV1(fd >= 0 && pwrite(fd, &originalByte, 1, 0) == 1, "restore exact own byte");
    NeedV1(close(fd) == 0, "close restore"); mutated = false;
}
xpc_connection_t ModelRemoteV1(xpc_object_t message) {
    (void)message;
    return mode == 1 ? NULL : (xpc_connection_t)(uintptr_t)1;
}
void ModelAuditV1(xpc_object_t message, audit_token_t *token) {
    (void)message; memset(token, 0, sizeof(*token));
    token->val[5] = mode == 5 ? 0 : 1234;
    token->val[7] = mode == 4 ? 0 : 5678;
}
int ModelNativeCheckV1(const VM27LWCRPolicy *policy, xpc_object_t message,
                       VM27LWCRMessageResult *out) {
    (void)policy; (void)message; ++nativeCalls;
    *out = (VM27LWCRMessageResult){.result = EACCES, .hasRemoteConnection = true,
        .taskCreated = true, .entitlementsValidated = false, .entitlementPresent = true,
        .entitlementIsBoolean = true, .entitlementValue = true};
    if (mode == 2) out->entitlementValue = false;
    if (mode == 3) { out->entitlementReadError = true; out->result = EIO; }
    if (mode == 15) { out->entitlementIsBoolean = false; out->entitlementValue = false; }
    if (mode == 16) out->taskCreated = false;
    return out->result;
}
int ModelCsopsV1(pid_t pid, unsigned operation, void *output, size_t size,
                 audit_token_t *token) {
    NeedV1(pid == 1234 && token->val[5] == 1234 && token->val[7] == 5678,
           "both queries use same real-message model token");
    if (operation == 5) {
        ++codeCalls; NeedV1(size == 20, "exact read-only CDHash size");
        if (mode == 7) { errno = EIO; return -1; }
        memcpy(output, expectedCD, 20);
        if (mode == 6) ((unsigned char *)output)[0] ^= 1;
        if (mode == 13) FlipV1(resourcesPath);
        return 0;
    }
    NeedV1(operation == 0 && size == sizeof(uint32_t), "only read-only CS_STATUS");
    ++statusCalls;
    if (mode == 8) { errno = EACCES; return -1; }
    *(uint32_t *)output = mode == 9 ? 0 : 0x36003005;
    if (mode == 14) FlipV1(executablePath);
    return 0;
}
static xpc_object_t RequirementV1(void) {
    xpc_object_t requirement = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t entitlements = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t query = xpc_array_create(NULL, 0);
    xpc_object_t select = xpc_array_create(NULL, 0), match = xpc_array_create(NULL, 0);
    xpc_array_set_int64(select, XPC_ARRAY_APPEND, 1);
    xpc_array_set_string(select, XPC_ARRAY_APPEND, VM27_PLUGIN_ENTITLEMENT);
    xpc_array_set_int64(match, XPC_ARRAY_APPEND, 5);
    xpc_array_set_bool(match, XPC_ARRAY_APPEND, true);
    xpc_array_append_value(query, select); xpc_array_append_value(query, match);
    xpc_dictionary_set_value(entitlements, "$query", query);
    xpc_dictionary_set_value(requirement, "entitlements", entitlements);
    xpc_release(entitlements); xpc_release(query); xpc_release(select); xpc_release(match);
    return requirement;
}
int main(int argc, char **argv) {
    NeedV1(argc == 6, "root bundle SHA CD arguments");
    char *root = argv[1], *bundle = argv[2], *sha = argv[3], *cd = argv[4];
    for (size_t i = 0; i < 20; ++i) {
        unsigned byte; NeedV1(sscanf(cd + i * 2, "%2x", &byte) == 1, "actual pinned CD hex");
        expectedCD[i] = (unsigned char)byte;
    }
    char childPath[4096];
    NeedV1(snprintf(childPath, sizeof(childPath), "%s/Contents/XPCServices/%s.xpc",
                   bundle, argv[5]) < (int)sizeof(childPath), "child path bounded");
    NeedV1(snprintf(executablePath, sizeof(executablePath), "%s/Contents/MacOS/%s",
                   childPath, argv[5]) < (int)sizeof(executablePath), "code path bounded");
    NeedV1(snprintf(resourcesPath, sizeof(resourcesPath), "%s/Contents/_CodeSignature/CodeResources",
                   childPath) < (int)sizeof(resourcesPath), "resources path bounded");
    xpc_object_t requirement = RequirementV1();
    VM27LargeBundleRegistry *registry = NULL; VM27LargeServicePlan *plan = NULL;
    NeedV1(VM27LargeBundleRegistryCreate(root, &registry) == 0, "actual registry retained root FD");
    NeedV1(VM27LargeBundleRegistryRegister(registry, bundle, 2, requirement) == 0, "actual signed bundle registration");
    NeedV1(VM27LargeBundleRegistryCopyServicePlan(registry, argv[5], &plan) == 0, "actual retained plan");
    VM27BundleParentConfigurationV1 config = {childPath, argv[5], sha, cd, geteuid()};
    VM27OwnedBundleApprovedPolicyV1 *policy = NULL;
    NeedV1(VM27OwnedBundleApprovedPolicyCreateV1(&config, plan, requirement, &policy) == 0,
           "actual external 1/3 pages+embedded+signed Boolean true accepted");
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    for (mode = 0; mode <= 16; ++mode) {
        nativeCalls = codeCalls = statusCalls = 0;
        if (mode == 10) FlipV1(policy->planInfo.executablePath);
        if (mode == 11) FlipV1(resourcesPath);
        if (mode == 12) {
            char infoPath[4096]; NeedV1(snprintf(infoPath, sizeof(infoPath), "%s/Contents/Info.plist",
                childPath) < (int)sizeof(infoPath), "info path bounded"); FlipV1(infoPath);
        }
        VM27ApprovedCodeMessageResult result = {0};
        int status = VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(policy, message, &result);
        NeedV1(result.result == status, "exact own result publication");
        NeedV1((status == 0) == (mode == 0), "accept only genuine-model decision");
        NeedV1(result.explicitApprovedCodeAccepted == (status == 0), "separate explicit decision");
        bool beforeQueryReject = mode == 1 || (mode >= 10 && mode <= 12);
        NeedV1(nativeCalls == (beforeQueryReject ? 0U : 1U), "native LWCR at most exactly once");
        if (nativeCalls) NeedV1(!result.nativePolicy.entitlementsValidated &&
            result.nativePolicy.result == (mode == 3 ? EIO : EACCES), "native false/rejection not rewritten");
        NeedV1(codeCalls == (beforeQueryReject || mode == 4 || mode == 5 ? 0U : 1U), "one CD query boundary");
        NeedV1(statusCalls == (beforeQueryReject || mode == 4 || mode == 5 || mode == 7 ? 0U : 1U),
               "one status query boundary");
        if (mode == 7) NeedV1(result.codeQueryError == EIO, "actual code query error retained");
        if (mode == 8) NeedV1(result.statusQueryError == EACCES, "actual status query error retained");
        if (mode == 13 || mode == 14) NeedV1(!result.filePinMatched, "post-query file mutation fail closed");
        RestoreV1();
    }
    mode = 0; nativeCalls = codeCalls = statusCalls = 0;
    NeedV1(VM27OwnedBundleApprovedPolicyCheckReceivedMessageV1(policy, message,
        (VM27ApprovedCodeMessageResult *)&policy->magic) == EINVAL, "policy-output alias rejected");
    NeedV1(policy->magic == VM27_OWNED_BUNDLE_POLICY_MAGIC_V1 && nativeCalls == 0,
           "alias rejection does not mutate policy/query");
    VM27OwnedBundleApprovedPolicyV1 *bad = NULL;
    VM27BundleParentConfigurationV1 wrong = config; wrong.reviewedExecutableCDHash = sha;
    NeedV1(VM27OwnedBundleApprovedPolicyCreateV1(&wrong, plan, requirement, &bad) == EINVAL && !bad,
           "malformed caller approval rejected");
    wrong = config; wrong.expectedOwnerUID = geteuid() + 1;
    NeedV1(VM27OwnedBundleApprovedPolicyCreateV1(&wrong, plan, requirement, &bad) == EINVAL && !bad,
           "unowned approval rejected");
    wrong = config; wrong.executableName = "Other";
    NeedV1(VM27OwnedBundleApprovedPolicyCreateV1(&wrong, plan, requirement, &bad) == EACCES && !bad,
           "plan cannot authorize a different executable");
    VM27OwnedBundleApprovedPolicyReleaseV1(policy);
    VM27LargeServicePlanRelease(plan); VM27LargeBundleRegistryRelease(registry);
    xpc_release(message); xpc_release(requirement);
    printf("{\"passed\":true,\"checks\":%u,\"messageModes\":17,\"actualRegistryAndBundleBytes\":true,"
           "\"receivedAuditSecTaskKernelQueriesMocked\":true,\"deviceOperations\":0}\n", checks);
    return 0;
}
