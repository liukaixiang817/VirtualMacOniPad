#include "modern_xpc_approved_code.h"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modern_xpc_approved_pins.h"

static _Atomic unsigned gChecks, gFailures;
static void Check(bool ok, const char *label) {
    atomic_fetch_add(&gChecks, 1);
    if (!ok) { atomic_fetch_add(&gFailures, 1); printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", label); }
}
static unsigned char *Read(const char *path, size_t *bytes) {
    *bytes = 0; FILE *file = fopen(path, "rb"); struct stat state;
    if (!file || fstat(fileno(file), &state) || !S_ISREG(state.st_mode) || state.st_size <= 0 || state.st_size > 8 * 1024 * 1024) { if (file) fclose(file); return NULL; }
    unsigned char *data = malloc((size_t)state.st_size);
    if (!data || fread(data, 1, (size_t)state.st_size, file) != (size_t)state.st_size || ferror(file)) { free(data); fclose(file); return NULL; }
    fclose(file); *bytes = (size_t)state.st_size; return data;
}
static bool Write(const char *path, const unsigned char *data, size_t bytes) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0700);
    if (fd < 0) return false;
    size_t at = 0; bool ok = true;
    while (at < bytes) { ssize_t n = write(fd, data + at, bytes - at); if (n <= 0) { ok = false; break; } at += (size_t)n; }
    ok = !fsync(fd) && ok; close(fd); return ok;
}
static void Identity(const char *phase, const char *name, void *function, const char *expectedSHA,
                     uint64_t expectedBytes, const char *expectedUUID) {
    void *raw = ptrauth_strip(function, ptrauth_key_function_pointer); Dl_info info = {0};
    Check(dladdr(raw, &info) && info.dli_fbase && info.dli_fname, "actual-provider-dladdr");
    const struct mach_header_64 *header = info.dli_fbase; const unsigned char *uuid = NULL;
    Check(header && header->magic == MH_MAGIC_64 && header->sizeofcmds < 16384, "actual-provider-header");
    if (header) {
        const struct load_command *c = (const void *)(header + 1);
        for (unsigned i = 0; i < header->ncmds; ++i) { if (c->cmd == LC_UUID && c->cmdsize == 24) uuid = (const unsigned char *)c + 8; c = (const void *)((const char *)c + c->cmdsize); }
    }
    char uuidHex[33] = {0}; if (uuid) for (unsigned i = 0; i < 16; ++i) snprintf(uuidHex + 2 * i, 3, "%02x", uuid[i]);
    Check(uuid && !strcmp(uuidHex, expectedUUID), "actual-provider-uuid");
    size_t bytes = 0; unsigned char *data = info.dli_fname ? Read(info.dli_fname, &bytes) : NULL, digest[32]; char hex[65] = {0};
    bool read = data != NULL;
    if (data) { CC_SHA256(data, (CC_LONG)bytes, digest); for (unsigned i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", digest[i]); free(data); }
    Check(read && bytes == expectedBytes && !strcmp(hex, expectedSHA), "actual-provider-file-pin");
    printf("{\"record\":\"provider\",\"phase\":\"%s\",\"symbol\":\"%s\",\"path\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\",\"SHA256\":\"%s\"}\n", phase, name, info.dli_fname ? info.dli_fname : "", uuidHex, (unsigned long long)((uintptr_t)raw - (uintptr_t)info.dli_fbase), hex);
}
static bool NoVMImages(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *p = _dyld_get_image_name(i);
        if (!p || strstr(p, "/Virtualization.framework/") || strstr(p, "/Hypervisor.framework/") || strstr(p, "/ParavirtualizedGraphics.framework/") || strstr(p, "/VirtualMachine.xpc/")) return false;
    }
    return true;
}
static xpc_object_t Requirement(void) {
    xpc_object_t outer = xpc_dictionary_create(NULL, NULL, 0), e = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t q = xpc_array_create(NULL, 0), s = xpc_array_create(NULL, 0), m = xpc_array_create(NULL, 0);
    xpc_object_t one = xpc_int64_create(1), five = xpc_int64_create(5), key = xpc_string_create(VM27_PLUGIN_ENTITLEMENT), b = xpc_bool_create(true);
    xpc_array_append_value(s, one); xpc_array_append_value(s, key); xpc_array_append_value(m, five); xpc_array_append_value(m, b);
    xpc_array_append_value(q, s); xpc_array_append_value(q, m); xpc_dictionary_set_value(e, "$query", q); xpc_dictionary_set_value(outer, "entitlements", e);
    xpc_release(e); xpc_release(q); xpc_release(s); xpc_release(m); xpc_release(one); xpc_release(five); xpc_release(key); xpc_release(b); return outer;
}
struct Fixture { const unsigned char *data; size_t bytes; const char *SHA, *CD; };
static void *Worker(void *value) {
    struct Fixture *f = value;
    for (unsigned i = 0; i < 32; ++i) {
        VM27ApprovedCodeInfo info;
        Check(!VM27ApprovedCodeInspectBytes(f->data, f->bytes, &info), "thread-real-code-directory-verify");
        Check(!strcmp(info.fileSHA256, f->SHA) && !strcmp(info.CDHash, f->CD) && info.pluginIsBoolean && info.pluginValue, "thread-authenticated-true-and-exact-hashes");
    }
    return NULL;
}
static uint32_t BE(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit limit = {5, 5}; setrlimit(RLIMIT_CPU, &limit); alarm(15);
    if (argc != 8 || (strcmp(argv[1], "missing") && strcmp(argv[1], "false") && strcmp(argv[1], "integer") && strcmp(argv[1], "true") && strcmp(argv[1], "true-unapproved"))) return 64;
    bool signedTrue = !strcmp(argv[1], "true") || !strcmp(argv[1], "true-unapproved");
    size_t selfBytes = 0, approvedBytes = 0;
    unsigned char *self = Read(argv[0], &selfBytes), *approved = Read(argv[4], &approvedBytes);
    VM27ApprovedCodeInfo selfInfo, approvedInfo;
    Check(self && approved && selfBytes == strtoull(argv[3], NULL, 10) && approvedBytes == strtoull(argv[7], NULL, 10), "exact-self-and-approved-input-size");
    if (!self || !approved) return 78;
    Check(!VM27ApprovedCodeInspectBytes(self, selfBytes, &selfInfo) && !strcmp(selfInfo.fileSHA256, argv[2]), "actual-self-cd-pages-verified");
    Check(!VM27ApprovedCodeInspectBytes(approved, approvedBytes, &approvedInfo) && !strcmp(approvedInfo.fileSHA256, argv[5]) && !strcmp(approvedInfo.CDHash, argv[6]), "explicit-approved-executable-fully-authenticated");
    Check(selfInfo.pluginPresent == (strcmp(argv[1], "missing") != 0), "self-signed-plugin-present-by-variant");
    Check(selfInfo.pluginIsBoolean == (!strcmp(argv[1], "false") || signedTrue), "self-signed-plugin-type-by-variant");
    Check(selfInfo.pluginValue == signedTrue, "self-signed-plugin-value-by-variant");
    Check(approvedInfo.pluginIsBoolean && approvedInfo.pluginValue, "approved-code-authenticated-true");
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"signatureVariant\":\"%s\",\"selfCDHash\":\"%s\",\"approvedCDHash\":\"%s\",\"VMCalls\":0,\"GPUCalls\":0,\"childLaunches\":0,\"registrationCalls\":0}\n", getpid(), getuid(), argv[1], selfInfo.CDHash, approvedInfo.CDHash);
    Check(NoVMImages(), "no-vm-images-preflight");
    Identity("before", "VM27ApprovedCodeCheckReceivedMessage", (void *)VM27ApprovedCodeCheckReceivedMessage, VM27_APPROVED_SHA256, VM27_APPROVED_BYTES, VM27_APPROVED_UUID);
    Identity("before", "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
    unsigned char *copy = malloc(approvedBytes); Check(copy != NULL, "own-negative-memory-copy");
    if (!copy) return 78;
    uint32_t signatureAt = 0; size_t at = 32;
    for (unsigned i = 0; i < ((struct mach_header_64 *)approved)->ncmds; ++i) { struct load_command *c = (void *)(approved + at); if (c->cmd == LC_CODE_SIGNATURE) signatureAt = ((struct linkedit_data_command *)c)->dataoff; at += c->cmdsize; }
    unsigned xmlAt = 0, cdAt = 0; unsigned count = BE(approved + signatureAt + 8);
    for (unsigned i = 0; i < count; ++i) { uint32_t kind = BE(approved + signatureAt + 12 + i * 8), o = BE(approved + signatureAt + 16 + i * 8); if (kind == 5) xmlAt = signatureAt + o; if (!kind) cdAt = signatureAt + o; }
    for (unsigned mode = 0; mode < 8; ++mode) {
        memcpy(copy, approved, approvedBytes);
        if (mode == 0) copy[signatureAt / 2] ^= 1;
        if (mode == 1) copy[xmlAt + 8] ^= 1;
        if (mode == 2) copy[signatureAt + 8] = 0xff;
        if (mode == 3) copy[cdAt + 37] = 1;
        if (mode == 4) copy[cdAt + 39] = 31;
        if (mode == 5) copy[cdAt + 47] = 1;
        if (mode == 6) copy[cdAt + 16] = 0xff;
        if (mode == 7) copy[cdAt + 12] = 0xff;
        VM27ApprovedCodeInfo out;
        Check(VM27ApprovedCodeInspectBytes(copy, approvedBytes, &out) != 0, "page-slot-range-format-corruption-refused");
    }
    free(copy);
    char root[] = "/tmp/VM27-ApprovedCode-XXXXXX"; Check(mkdtemp(root) != NULL, "own-temporary-created");
    char path[4096]; snprintf(path, sizeof(path), "%s/ApprovedExec", root);
    Check(Write(path, approved, approvedBytes), "own-approved-clone-created");
    xpc_object_t requirement = Requirement(); VM27ApprovedCodePolicy *policy = NULL, *bad = (void *)(uintptr_t)1;
    if (!signedTrue) Check(VM27ApprovedCodePolicyCreate(argv[0], selfInfo.fileSHA256, selfInfo.CDHash, requirement, &bad) == EACCES && !bad, "authentic-missing-false-integer-code-cannot-create-approved-policy");
    Check(VM27ApprovedCodePolicyCreate(path, argv[5], "0000000000000000000000000000000000000000", requirement, &bad) == EACCES && !bad, "unapproved-code-hash-refused");
    Check(VM27ApprovedCodePolicyCreate(path, "0000000000000000000000000000000000000000000000000000000000000000", argv[6], requirement, &bad) == EACCES && !bad, "unapproved-full-file-hash-refused");
    xpc_dictionary_set_bool(requirement, "extra-fact", true);
    Check(VM27ApprovedCodePolicyCreate(path, argv[5], argv[6], requirement, &bad) == ENOTSUP && !bad, "additional-lwcr-fact-not-dropped");
    xpc_release(requirement); requirement = Requirement();
    Check(!VM27ApprovedCodePolicyCreate(path, argv[5], argv[6], requirement, &policy) && policy, "explicit-approved-code-policy-created");
    xpc_dictionary_set_bool(requirement, "changed-after-create", true); xpc_release(requirement);
    if (!policy) return 78;
    xpc_object_t spoof = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_bool(spoof, VM27_PLUGIN_ENTITLEMENT, true);
    VM27ApprovedCodeMessageResult detail;
    Check(VM27ApprovedCodeCheckReceivedMessage(policy, spoof, &detail) == EACCES && !detail.auditTokenPresent && !detail.explicitApprovedCodeAccepted, "body-true-without-kernel-message-refused"); xpc_release(spoof);
    struct Fixture fixture = {approved, approvedBytes, argv[5], argv[6]}; pthread_t workers[4]; unsigned joined = 0;
    for (unsigned i = 0; i < 4; ++i) { int rc = pthread_create(&workers[i], NULL, Worker, &fixture); Check(!rc, "worker-created"); if (rc) return 78; }
    for (unsigned i = 0; i < 4; ++i) { Check(!pthread_join(workers[i], NULL), "worker-joined"); ++joined; }
    dispatch_queue_t server = dispatch_queue_create("VM27.Approved.server", DISPATCH_QUEUE_SERIAL), clientQueue = dispatch_queue_create("VM27.Approved.client", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t replies = dispatch_semaphore_create(0);
    __block xpc_connection_t peer = NULL; __block unsigned received = 0, application = 0;
    bool positive = !strcmp(argv[1], "true");
    xpc_connection_t listener = xpc_connection_create(NULL, server);
    Check(listener != NULL, "anonymous-owned-listener");
    xpc_connection_set_event_handler(listener, ^(xpc_object_t connection) {
        if (xpc_get_type(connection) != XPC_TYPE_CONNECTION) return;
        Check(!peer, "single-owned-peer"); peer = (xpc_connection_t)xpc_retain(connection);
        xpc_connection_set_target_queue(peer, server);
        xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
            if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) return;
            VM27ApprovedCodeMessageResult result; int status = VM27ApprovedCodeCheckReceivedMessage(policy, event, &result);
            bool tampered = received == 0;
            if (tampered) Check(status == ESTALE && !result.filePinMatched && !result.auditTokenPresent, "tampered-owned-code-rejected-before-native-query");
            else {
                Check(result.filePinMatched && result.auditTokenPresent && result.auditPID == (uint32_t)getpid() && result.auditPIDVersion > 0, "particular-message-kernel-audit-token");
                Check(!result.codeQueryError && !result.statusQueryError && !strcmp(result.kernelCDHash, selfInfo.CDHash), "kernel-readonly-codehash-and-status-real");
                Check(result.nativePolicy.taskCreated && result.nativePolicy.hasRemoteConnection && !result.nativePolicy.entitlementReadError, "native-true-requirement-from-that-message");
                Check(result.nativePolicy.entitlementPresent == selfInfo.pluginPresent && result.nativePolicy.entitlementIsBoolean == selfInfo.pluginIsBoolean && result.nativePolicy.entitlementValue == selfInfo.pluginValue, "native-entitlement-equals-authenticated-file-type-value");
                Check(result.codeHashMatched == positive && status == (positive ? 0 : EACCES) && result.explicitApprovedCodeAccepted == positive, "only-explicit-approved-code-and-real-true-accepted");
                if (positive) Check(result.dynamicCodeValid, "approved-code-remains-cs-valid");
                if (received == 1) printf("{\"record\":\"nativeIdentity\",\"auditPID\":%u,\"auditPIDVersion\":%u,\"kernelCDHash\":\"%s\",\"codeStatus\":%u,\"codeHashMatched\":%s,\"dynamicCodeValid\":%s,\"entitlementsValidated\":%s,\"nativeBooleanTrue\":%s,\"explicitApprovedCodeAccepted\":%s}\n", result.auditPID, result.auditPIDVersion, result.kernelCDHash, result.codeStatus, result.codeHashMatched ? "true" : "false", result.dynamicCodeValid ? "true" : "false", result.nativePolicy.entitlementsValidated ? "true" : "false", result.nativePolicy.entitlementIsBoolean && result.nativePolicy.entitlementValue ? "true" : "false", result.explicitApprovedCodeAccepted ? "true" : "false");
            }
            ++received; if (!status) ++application;
            xpc_object_t reply = xpc_dictionary_create_reply(event); Check(reply != NULL, "control-reply-created");
            if (reply) { xpc_dictionary_set_int64(reply, "gateStatus", status); xpc_connection_send_message(peer, reply); xpc_release(reply); }
        }); xpc_connection_resume(peer);
    }); xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener); xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
    Check(endpoint && client, "owned-endpoint-client"); xpc_connection_set_event_handler(client, ^(xpc_object_t e) { (void)e; }); xpc_connection_resume(client);
    unsigned char original = approved[40]; approved[40] ^= 1; Check(Write(path, approved, approvedBytes), "own-code-clone-tampered"); approved[40] = original;
    for (unsigned i = 0; i < 65; ++i) {
        __block int replyStatus = -1;
        xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_bool(request, VM27_PLUGIN_ENTITLEMENT, true);
        xpc_connection_send_message_with_reply(client, request, clientQueue, ^(xpc_object_t reply) { replyStatus = xpc_get_type(reply) == XPC_TYPE_DICTIONARY ? (int)xpc_dictionary_get_int64(reply, "gateStatus") : -2; dispatch_semaphore_signal(replies); }); xpc_release(request);
        Check(!dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "own-control-message-reply-arrived");
        Check(replyStatus == (i == 0 ? ESTALE : positive ? 0 : EACCES), "own-control-reply-reports-precise-gate");
        if (i == 0) Check(Write(path, approved, approvedBytes), "own-code-clone-restored");
    }
    dispatch_sync(server, ^{ Check(received == 65 && application == (positive ? 64u : 0u), "only-approved-real-messages-reach-application"); });
    xpc_connection_cancel(client); xpc_connection_cancel(listener); if (peer) xpc_connection_cancel(peer);
    dispatch_sync(server, ^{}); dispatch_sync(clientQueue, ^{});
    if (peer) xpc_release(peer); xpc_release(client); xpc_release(endpoint); xpc_release(listener);
    dispatch_release(replies); dispatch_release(clientQueue); dispatch_release(server);
    VM27ApprovedCodePolicyRelease(policy); free(approved); free(self);
    Check(!unlink(path) && !rmdir(root) && access(root, F_OK) == -1 && errno == ENOENT, "only-owned-temporary-removed");
    VM27ApprovedCodeStats stats; VM27ApprovedCodeCopyStats(&stats); VM27LWCRStats native; VM27LWCRCopyStats(&native);
    Check(stats.created == stats.destroyed && stats.created == 1, "approved-policy-lifetime-balanced");
    Check(stats.messageChecks == 66 && stats.codeQueries == 64 && stats.statusQueries == 64, "every-untampered-real-message-kernel-checked");
    Check(stats.accepted == (positive ? 64u : 0u) && stats.rejected == (positive ? 2u : 66u), "exact-approved-native-message-counter");
    Check(native.taskCreates == native.taskReleases && native.taskCreates == 64 && native.policiesCreated == native.policiesDestroyed, "native-task-and-policy-lifetimes-balanced");
    Identity("after", "VM27ApprovedCodeCheckReceivedMessage", (void *)VM27ApprovedCodeCheckReceivedMessage, VM27_APPROVED_SHA256, VM27_APPROVED_BYTES, VM27_APPROVED_UUID);
    Identity("after", "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
    Check(NoVMImages(), "no-vm-images-after");
    printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"passed\":%s,\"messageChecks\":%llu,\"accepted\":%llu,\"rejected\":%llu,\"codeQueries\":%llu,\"statusQueries\":%llu,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"approvedPoliciesCreated\":%llu,\"approvedPoliciesDestroyed\":%llu,\"workersJoined\":%u,\"applicationCalls\":%u,\"explicitApprovedCodePositiveCovered\":%s,\"strictNativePositiveCovered\":%s,\"ownTemporaryRemoved\":true,\"childLaunches\":0,\"completeBundleRegistration\":false}\n", atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", (unsigned long long)stats.messageChecks, (unsigned long long)stats.accepted, (unsigned long long)stats.rejected, (unsigned long long)stats.codeQueries, (unsigned long long)stats.statusQueries, (unsigned long long)native.taskCreates, (unsigned long long)native.taskReleases, (unsigned long long)stats.created, (unsigned long long)stats.destroyed, joined, application, positive ? "true" : "false", native.acceptedMessages != 0 ? "true" : "false");
    return atomic_load(&gFailures) ? 1 : 0;
}
