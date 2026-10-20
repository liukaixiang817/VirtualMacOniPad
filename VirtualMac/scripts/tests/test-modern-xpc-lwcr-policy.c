#include "modern_xpc_lwcr_policy.h"
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modern_xpc_lwcr_pins.h"

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern SecTaskRef SecTaskCreateWithXPCMessage(xpc_object_t message);
extern Boolean SecTaskEntitlementsValidated(SecTaskRef task);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task,
                                               CFStringRef entitlement,
                                               CFErrorRef *error);
static _Atomic unsigned gChecks, gFailures;
static void Check(bool value, const char *label) {
    atomic_fetch_add(&gChecks, 1);
    if (!value) { atomic_fetch_add(&gFailures, 1); printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", label); }
}
static bool FilePin(const char *path, const char *expected, uint64_t expectedBytes) {
    struct stat before = {0}, after = {0};
    FILE *file = fopen(path, "rb");
    if (!file || fstat(fileno(file), &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size != expectedBytes ||
        expectedBytes > 2 * 1024 * 1024) { if (file) fclose(file); return false; }
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    unsigned char data[16384], digest[32]; uint64_t total = 0;
    for (;;) {
        size_t bytes = fread(data, 1, sizeof(data), file);
        if (bytes) { CC_SHA256_Update(&context, data, (CC_LONG)bytes); total += bytes; }
        if (bytes != sizeof(data)) break;
    }
    bool ok = !ferror(file) && total == expectedBytes && !fstat(fileno(file), &after) &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && before.st_mtime == after.st_mtime;
    fclose(file); CC_SHA256_Final(digest, &context);
    char hex[65]; for (unsigned i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    return ok && strlen(expected) == 64 && !strcmp(hex, expected);
}
static xpc_object_t Requirement(void) {
    xpc_object_t outer = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t entitlements = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t query = xpc_array_create(NULL, 0);
    xpc_object_t select = xpc_array_create(NULL, 0);
    xpc_object_t match = xpc_array_create(NULL, 0);
    xpc_object_t one = xpc_int64_create(1), five = xpc_int64_create(5);
    xpc_object_t key = xpc_string_create(VM27_PLUGIN_ENTITLEMENT);
    xpc_object_t boolean = xpc_bool_create(true);
    xpc_array_append_value(select, one); xpc_array_append_value(select, key);
    xpc_array_append_value(match, five); xpc_array_append_value(match, boolean);
    xpc_array_append_value(query, select); xpc_array_append_value(query, match);
    xpc_dictionary_set_value(entitlements, "$query", query);
    xpc_dictionary_set_value(outer, "entitlements", entitlements);
    xpc_release(entitlements); xpc_release(query); xpc_release(select); xpc_release(match);
    xpc_release(one); xpc_release(five); xpc_release(key); xpc_release(boolean);
    return outer;
}
static void Reject(xpc_object_t requirement, int expected, const char *label) {
    VM27LWCRPolicy *policy = (VM27LWCRPolicy *)(uintptr_t)1;
    int result = VM27LWCRPolicyCreate(requirement, &policy);
    Check(result == expected && policy == NULL, label);
}
static void Fixtures(VM27LWCRPolicy *policy) {
    Reject(NULL, EINVAL, "null-requirement");
    xpc_object_t bad = xpc_int64_create(1); Reject(bad, EINVAL, "integer-root"); xpc_release(bad);
    xpc_object_t empty = xpc_dictionary_create(NULL, NULL, 0);
    Reject(empty, ENOTSUP, "empty-root-does-not-match-all"); xpc_release(empty);
    for (unsigned mode = 0; mode < 12; ++mode) {
        xpc_object_t r = Requirement();
        xpc_object_t e = xpc_dictionary_get_value(r, "entitlements");
        xpc_object_t q = xpc_dictionary_get_value(e, "$query");
        xpc_object_t s = xpc_array_get_value(q, 0), m = xpc_array_get_value(q, 1);
        int expected = ENOTSUP;
        if (mode == 0) xpc_dictionary_set_bool(r, "extra-fact", true);
        if (mode == 1) xpc_dictionary_set_bool(e, "extra-query", true);
        if (mode == 2) { xpc_object_t t = xpc_int64_create(9); xpc_array_set_value(s, 0, t); xpc_release(t); }
        if (mode == 3) { xpc_object_t t = xpc_int64_create(7); xpc_array_set_value(m, 0, t); xpc_release(t); }
        if (mode == 4) { xpc_object_t t = xpc_string_create("other.entitlement"); xpc_array_set_value(s, 1, t); xpc_release(t); }
        if (mode == 5) { xpc_object_t t = xpc_bool_create(false); xpc_array_set_value(m, 1, t); xpc_release(t); }
        if (mode == 6) { xpc_object_t t = xpc_int64_create(1); xpc_array_set_value(m, 1, t); xpc_release(t); expected = EINVAL; }
        if (mode == 7) { xpc_object_t t = xpc_bool_create(true); xpc_array_set_value(s, 0, t); xpc_release(t); }
        if (mode == 8) { xpc_object_t t = xpc_string_create("true"); xpc_array_set_value(m, 1, t); xpc_release(t); expected = EINVAL; }
        if (mode == 9) { xpc_object_t t = xpc_int64_create(1); xpc_array_append_value(q, t); xpc_release(t); }
        if (mode == 10) { xpc_object_t t = xpc_int64_create(1); xpc_array_append_value(s, t); xpc_release(t); expected = EINVAL; }
        if (mode == 11) { xpc_object_t t = xpc_array_create(NULL, 0); xpc_dictionary_set_value(e, "$query", t); xpc_release(t); }
        Reject(r, expected, "malformed-or-unsupported-query"); xpc_release(r);
    }
    xpc_object_t entitlements = xpc_dictionary_create(NULL, NULL, 0);
    Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, entitlements) == EACCES, "missing-owned-key");
    xpc_dictionary_set_bool(entitlements, VM27_PLUGIN_ENTITLEMENT, false);
    Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, entitlements) == EACCES, "false-owned-key");
    xpc_dictionary_set_int64(entitlements, VM27_PLUGIN_ENTITLEMENT, 1);
    Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, entitlements) == EACCES, "integer-one-is-not-true");
    xpc_dictionary_set_string(entitlements, VM27_PLUGIN_ENTITLEMENT, "true");
    Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, entitlements) == EACCES, "string-is-not-true");
    xpc_dictionary_set_bool(entitlements, VM27_PLUGIN_ENTITLEMENT, true);
    Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, entitlements) == 0, "owned-true-matches");
    VM27LWCRMessageResult result = {0};
    Check(VM27LWCRPolicyCheckReceivedMessage(policy, entitlements, &result) == EACCES &&
          !result.hasRemoteConnection && !result.taskCreated, "unsigned-dictionary-cannot-claim-peer-entitlement");
    xpc_release(entitlements);
}
static void *Worker(void *argument) {
    VM27LWCRPolicy *policy = argument;
    xpc_object_t values = xpc_dictionary_create(NULL, NULL, 0);
    for (unsigned i = 0; i < 128; ++i) {
        Check(VM27LWCRPolicyRetain(policy), "thread-retain");
        xpc_dictionary_set_bool(values, VM27_PLUGIN_ENTITLEMENT, (i & 1) != 0);
        Check(VM27LWCRPolicyEvaluateOwnedEntitlements(policy, values) == ((i & 1) ? 0 : EACCES), "thread-exact-match");
        VM27LWCRPolicyRelease(policy);
    }
    xpc_release(values);
    VM27LWCRPolicyRelease(policy);
    return NULL;
}
static void Identity(const char *name, void *function) {
    Dl_info info = {0};
    void *raw = ptrauth_strip(function, ptrauth_key_function_pointer);
    Check(dladdr(raw, &info) && info.dli_fbase && info.dli_fname, "provider-identity");
    const struct mach_header_64 *header = info.dli_fbase;
    Check(header && header->magic == MH_MAGIC_64, "provider-header");
    const struct load_command *command = (const void *)(header + 1);
    const unsigned char *uuid = NULL;
    if (header) for (unsigned i = 0; i < header->ncmds; ++i) {
        if (command->cmd == LC_UUID) uuid = (const unsigned char *)command + 8;
        command = (const void *)((const char *)command + command->cmdsize);
    }
    Check(uuid != NULL, "provider-uuid");
    if (!strcmp(name, "VM27LWCRPolicyCheckReceivedMessage")) {
        char uuidHex[33] = {0};
        if (uuid) for (unsigned i = 0; i < 16; ++i) snprintf(uuidHex + i * 2, 3, "%02x", uuid[i]);
        Check(info.dli_fname && FilePin(info.dli_fname, VM27_POLICY_SHA256, VM27_POLICY_BYTES), "actual-policy-file-pin");
        Check(!strcmp(uuidHex, VM27_POLICY_UUID), "actual-policy-image-uuid");
    } else {
        Check(info.dli_fname && strstr(info.dli_fname, "/Security.framework/") != NULL, "actual-native-security-provider");
    }
    printf("{\"record\":\"provider\",\"symbol\":\"%s\",\"path\":\"%s\",\"UUID\":\"", name, info.dli_fname ? info.dli_fname : "");
    if (uuid) for (unsigned i = 0; i < 16; ++i) printf("%02x", uuid[i]);
    printf("\",\"RVA\":\"0x%llx\"}\n", (unsigned long long)((uintptr_t)raw - (uintptr_t)info.dli_fbase));
}
static bool NoVMImages(void) {
    const char *forbidden[] = {"/Virtualization.framework/", "/Hypervisor.framework/",
        "/ParavirtualizedGraphics.framework/", "/VirtualMachine.xpc/",
        "/com.apple.Virtualization.VirtualMachine"};
    bool passed = true;
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) { passed = false; continue; }
        for (unsigned j = 0; j < sizeof(forbidden) / sizeof(forbidden[0]); ++j)
            if (strstr(name, forbidden[j])) {
                printf("{\"record\":\"forbiddenImage\",\"name\":\"%s\"}\n", name);
                passed = false;
            }
    }
    return passed;
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit cpu = {5, 5}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 78;
    alarm(15);
    if (argc != 4 || (strcmp(argv[1], "missing") && strcmp(argv[1], "false") &&
        strcmp(argv[1], "integer") && strcmp(argv[1], "true"))) return 64;
    char *sizeEnd = NULL; uint64_t expectedSelfBytes = strtoull(argv[3], &sizeEnd, 10);
    Check(sizeEnd && sizeEnd != argv[3] && !*sizeEnd && FilePin(argv[0], argv[2], expectedSelfBytes), "exact-self-file-pin");
    Check(NoVMImages(), "no-vm-images-at-entry");
    if (atomic_load(&gFailures)) return 78;
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"signatureVariant\":\"%s\",\"registrationCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n", getpid(), getuid(), argv[1]);
    Identity("SecTaskCreateFromSelf", (void *)SecTaskCreateFromSelf);
    Identity("SecTaskCreateWithXPCMessage", (void *)SecTaskCreateWithXPCMessage);
    Identity("SecTaskCopyValueForEntitlement", (void *)SecTaskCopyValueForEntitlement);
    Identity("SecTaskEntitlementsValidated", (void *)SecTaskEntitlementsValidated);
    Identity("VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage);
    SecTaskRef self = SecTaskCreateFromSelf(NULL);
    Check(self != NULL, "self-task");
    CFErrorRef error = NULL;
    CFTypeRef actual = self ? SecTaskCopyValueForEntitlement(self, CFSTR(VM27_PLUGIN_ENTITLEMENT), &error) : NULL;
    bool validated = self && SecTaskEntitlementsValidated(self);
    bool present = actual != NULL;
    bool boolean = actual && CFGetTypeID(actual) == CFBooleanGetTypeID();
    bool trueValue = boolean && CFBooleanGetValue((CFBooleanRef)actual);
    Check(!error, "self-signature-readable");
    if (!strcmp(argv[1], "missing")) Check(!present, "kernel-missing-entitlement");
    if (!strcmp(argv[1], "false")) Check(boolean && !trueValue, "kernel-false-entitlement");
    if (!strcmp(argv[1], "integer")) {
        int64_t value = 0;
        Check(actual && CFGetTypeID(actual) == CFNumberGetTypeID() &&
              CFNumberGetValue((CFNumberRef)actual, kCFNumberSInt64Type, &value) && value == 1,
              "kernel-integer-entitlement");
    }
    if (!strcmp(argv[1], "true")) Check(boolean && trueValue, "kernel-true-entitlement");
    printf("{\"record\":\"selfSignature\",\"validated\":%s,\"present\":%s,\"isBoolean\":%s,\"value\":%s}\n", validated ? "true" : "false", present ? "true" : "false", boolean ? "true" : "false", trueValue ? "true" : "false");
    if (actual) CFRelease(actual);
    if (error) CFRelease(error);
    if (self) CFRelease(self);
    xpc_object_t requirement = Requirement(); VM27LWCRPolicy *policy = NULL;
    Check(VM27LWCRPolicyCreate(requirement, &policy) == 0 && policy, "original-policy-created");
    if (!policy) return 78;
    xpc_object_t e = xpc_dictionary_get_value(requirement, "entitlements");
    xpc_dictionary_set_bool(e, "malicious-post-create-mutation", true);
    xpc_release(requirement);
    Fixtures(policy);
    pthread_t workers[4]; unsigned started = 0;
    for (unsigned i = 0; i < 4; ++i) {
        Check(VM27LWCRPolicyRetain(policy), "worker-owned-policy");
        int status = pthread_create(&workers[i], NULL, Worker, policy);
        Check(status == 0, "worker-created");
        if (status) { VM27LWCRPolicyRelease(policy); break; } ++started;
    }
    for (unsigned i = 0; i < started; ++i) Check(pthread_join(workers[i], NULL) == 0, "worker-joined");
    dispatch_queue_t serverQueue = dispatch_queue_create("VM27.LWCR.owned.server", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t clientQueue = dispatch_queue_create("VM27.LWCR.owned.client", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t replies = dispatch_semaphore_create(0);
    __block xpc_connection_t retainedPeer = NULL;
    __block unsigned received = 0, applicationCalls = 0;
    __block int replyResult = -1;
    xpc_connection_t listener = xpc_connection_create(NULL, serverQueue);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        Check(retainedPeer == NULL, "single-owned-peer");
        if (retainedPeer) { xpc_connection_set_event_handler(event, ^(xpc_object_t ignored) { (void)ignored; }); xpc_connection_resume(event); xpc_connection_cancel(event); return; }
        retainedPeer = (xpc_connection_t)xpc_retain(event);
        xpc_connection_set_event_handler(retainedPeer, ^(xpc_object_t message) {
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            VM27LWCRMessageResult detail = {0};
            int status = VM27LWCRPolicyCheckReceivedMessage(policy, message, &detail);
            ++received;
            Check(detail.hasRemoteConnection && detail.taskCreated && !detail.entitlementReadError,
                  "received-message-uses-real-audit-token");
            Check(detail.entitlementsValidated == validated && detail.entitlementPresent == present &&
                  detail.entitlementIsBoolean == boolean && detail.entitlementValue == trueValue,
                  "message-entitlement-equals-native-signature");
            Check(status == (validated && boolean && trueValue ? 0 : EACCES), "fail-closed-native-gate");
            if (status == 0) ++applicationCalls;
            xpc_object_t reply = xpc_dictionary_create_reply(message);
            Check(reply != NULL, "own-control-reply");
            if (reply) { xpc_dictionary_set_int64(reply, "gateStatus", status); xpc_connection_send_message(retainedPeer, reply); xpc_release(reply); }
        });
        xpc_connection_resume(retainedPeer);
    });
    xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = (xpc_endpoint_t)xpc_endpoint_create(listener);
    xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
    xpc_connection_set_target_queue(client, clientQueue);
    xpc_connection_set_event_handler(client, ^(xpc_object_t event) { (void)event; });
    xpc_connection_resume(client);
    for (unsigned i = 0; i < 64; ++i) {
        xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_uint64(request, "sequence", i);
        /* Spoofed body entitlement must never grant access. */
        xpc_dictionary_set_bool(request, VM27_PLUGIN_ENTITLEMENT, true);
        xpc_connection_send_message_with_reply(client, request, clientQueue, ^(xpc_object_t reply) {
            replyResult = xpc_get_type(reply) == XPC_TYPE_DICTIONARY ? (int)xpc_dictionary_get_int64(reply, "gateStatus") : -2;
            dispatch_semaphore_signal(replies);
        });
        xpc_release(request);
        long waited = dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
        Check(waited == 0, "real-xpc-message-reply");
        if (waited) break;
        Check(replyResult == (validated && boolean && trueValue ? 0 : EACCES), "reply-reports-gate-result");
    }
    dispatch_sync(serverQueue, ^{
        Check(received == 64, "all-own-messages-received");
        Check(applicationCalls == (validated && boolean && trueValue ? 64 : 0), "untrusted-messages-not-forwarded");
        if (retainedPeer) {
            xpc_connection_set_event_handler(retainedPeer, ^(xpc_object_t ignored) { (void)ignored; });
            xpc_connection_cancel(retainedPeer); xpc_release(retainedPeer); retainedPeer = NULL;
        }
    });
    xpc_connection_cancel(client); xpc_connection_cancel(listener);
    dispatch_sync(serverQueue, ^{}); dispatch_sync(clientQueue, ^{});
    xpc_release(client); xpc_release(endpoint); xpc_release(listener);
    dispatch_release(replies); dispatch_release(clientQueue); dispatch_release(serverQueue);
    VM27LWCRPolicyRelease(policy);
    VM27LWCRStats stats = {0}; VM27LWCRCopyStats(&stats);
    Check(stats.policiesCreated == 1 && stats.policiesDestroyed == 1, "policy-lifetime-balanced");
    Check(stats.taskCreates == 64 && stats.taskReleases == 64, "native-task-lifetime-balanced");
    Check(stats.entitlementCopies == stats.entitlementReleases, "native-entitlement-lifetime-balanced");
    Check(stats.acceptedMessages == (validated && boolean && trueValue ? 64 : 0) &&
          stats.rejectedMessages == (validated && boolean && trueValue ? 1 : 65), "native-message-counts");
    Identity("VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage);
    Check(FilePin(argv[0], argv[2], expectedSelfBytes), "exact-self-post-file-pin");
    Check(NoVMImages(), "no-vm-images-at-exit");
    printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"passed\":%s,\"messageChecks\":%llu,\"acceptedMessages\":%llu,\"rejectedMessages\":%llu,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"copies\":%llu,\"releases\":%llu,\"policiesCreated\":%llu,\"policiesDestroyed\":%llu,\"workersJoined\":%u,\"registrationCalls\":0,\"nativeTrustedPositiveCovered\":%s}\n",
        atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true",
        (unsigned long long)stats.messageChecks, (unsigned long long)stats.acceptedMessages,
        (unsigned long long)stats.rejectedMessages, (unsigned long long)stats.taskCreates,
        (unsigned long long)stats.taskReleases, (unsigned long long)stats.entitlementCopies,
        (unsigned long long)stats.entitlementReleases, (unsigned long long)stats.policiesCreated,
        (unsigned long long)stats.policiesDestroyed, started,
        validated && boolean && trueValue ? "true" : "false");
    alarm(0); return atomic_load(&gFailures) ? 78 : 0;
}
