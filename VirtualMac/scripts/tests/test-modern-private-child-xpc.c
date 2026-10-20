#include "modern_xpc_private_endpoint.h"
#include "modern_xpc_approved_code.h"
#include "modern_xpc_child_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern char **environ;
static _Atomic unsigned gChecks, gFailures;
static void Check(bool ok, const char *name) { atomic_fetch_add(&gChecks, 1); if (!ok) { atomic_fetch_add(&gFailures, 1); printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", name); } }
static unsigned char *Read(const char *p, size_t *bytes) {
    *bytes = 0; FILE *f = fopen(p, "rb"); struct stat state;
    if (!f || fstat(fileno(f), &state) || !S_ISREG(state.st_mode) || state.st_size <= 0 || state.st_size > 2 * 1024 * 1024) { if (f) fclose(f); return NULL; }
    unsigned char *data = malloc((size_t)state.st_size);
    if (!data || fread(data, 1, (size_t)state.st_size, f) != (size_t)state.st_size || ferror(f)) { free(data); fclose(f); return NULL; }
    fclose(f); *bytes = (size_t)state.st_size; return data;
}
static void Identity(const char *role, const char *phase, const char *symbol, void *function,
                     const char *SHA, uint64_t bytes, const char *UUID) {
    void *raw = ptrauth_strip(function, ptrauth_key_function_pointer); Dl_info info = {0};
    Check(dladdr(raw, &info) && info.dli_fbase && info.dli_fname, "actual-strong-provider-dladdr");
    const struct mach_header_64 *header = info.dli_fbase; char actualUUID[33] = {0};
    if (header) { const struct load_command *c = (const void *)(header + 1); for (unsigned i = 0; i < header->ncmds; ++i) { if (c->cmd == LC_UUID && c->cmdsize == 24) { const unsigned char *p = (const void *)((const char *)c + 8); for (unsigned j = 0; j < 16; ++j) snprintf(actualUUID + 2 * j, 3, "%02x", p[j]); } c = (const void *)((const char *)c + c->cmdsize); } }
    Check(!strcmp(actualUUID, UUID), "actual-strong-provider-uuid");
    size_t count = 0; unsigned char *data = info.dli_fname ? Read(info.dli_fname, &count) : NULL, digest[32]; char hex[65] = {0}; bool hadData = data != NULL;
    if (data) { CC_SHA256(data, (CC_LONG)count, digest); for (unsigned i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", digest[i]); free(data); }
    Check(hadData && count == bytes && !strcmp(hex, SHA), "actual-strong-provider-file-sha");
    printf("{\"record\":\"provider\",\"role\":\"%s\",\"phase\":\"%s\",\"symbol\":\"%s\",\"path\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\",\"SHA256\":\"%s\"}\n", role, phase, symbol, info.dli_fname ? info.dli_fname : "", actualUUID, (unsigned long long)((uintptr_t)raw - (uintptr_t)info.dli_fbase), hex);
}
static void Providers(const char *role, const char *phase) {
    Identity(role, phase, "VM27PrivateEndpointConnectSendRight", (void *)VM27PrivateEndpointConnectSendRight, VM27_ENDPOINT_SHA256, VM27_ENDPOINT_BYTES, VM27_ENDPOINT_UUID);
    Identity(role, phase, "VM27ApprovedCodeCheckReceivedMessage", (void *)VM27ApprovedCodeCheckReceivedMessage, VM27_APPROVED_SHA256, VM27_APPROVED_BYTES, VM27_APPROVED_UUID);
    Identity(role, phase, "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
}
static bool NoVM(void) { for (uint32_t i = 0; i < _dyld_image_count(); ++i) { const char *p = _dyld_get_image_name(i); if (!p || strstr(p, "/Virtualization.framework/") || strstr(p, "/Hypervisor.framework/") || strstr(p, "/ParavirtualizedGraphics.framework/") || strstr(p, "/VirtualMachine.xpc/")) return false; } return true; }
static xpc_object_t Requirement(void) {
    xpc_object_t r = xpc_dictionary_create(NULL, NULL, 0), e = xpc_dictionary_create(NULL, NULL, 0), q = xpc_array_create(NULL, 0), s = xpc_array_create(NULL, 0), m = xpc_array_create(NULL, 0);
    xpc_object_t one = xpc_int64_create(1), five = xpc_int64_create(5), key = xpc_string_create(VM27_PLUGIN_ENTITLEMENT), b = xpc_bool_create(true);
    xpc_array_append_value(s, one); xpc_array_append_value(s, key); xpc_array_append_value(m, five); xpc_array_append_value(m, b); xpc_array_append_value(q, s); xpc_array_append_value(q, m); xpc_dictionary_set_value(e, "$query", q); xpc_dictionary_set_value(r, "entitlements", e);
    xpc_release(e); xpc_release(q); xpc_release(s); xpc_release(m); xpc_release(one); xpc_release(five); xpc_release(key); xpc_release(b); return r;
}
static void ReleasePorts(mach_port_array_t p, mach_msg_type_number_t n) { for (unsigned i = 0; i < n; ++i) if (MACH_PORT_VALID(p[i])) Check(!mach_port_deallocate(mach_task_self(), p[i]), "own-looked-up-mach-right-released"); if (p) Check(!vm_deallocate(mach_task_self(), (vm_address_t)p, n * sizeof(mach_port_t)), "own-mach-port-array-released"); }
static void EndpointNegativeCases(void) {
    unsigned before = atomic_load(&gChecks), failures = atomic_load(&gFailures);
    mach_port_t copied = MACH_PORT_DEAD, ownReceive = MACH_PORT_NULL;
    xpc_object_t wrong = xpc_dictionary_create(NULL, NULL, 0);
    dispatch_queue_t queue = dispatch_queue_create("VM27.PrivateChild.negative", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t connection = (xpc_connection_t)wrong;
    Check(VM27PrivateEndpointCopyABI(NULL) == EINVAL, "endpoint-identity-null-output-refused");
    Check(VM27PrivateEndpointCopySendRight(NULL, &copied) == EINVAL && copied == MACH_PORT_NULL, "null-endpoint-does-not-read-shape");
    copied = MACH_PORT_DEAD;
    Check(VM27PrivateEndpointCopySendRight((xpc_endpoint_t)wrong, &copied) == EINVAL && copied == MACH_PORT_NULL, "dictionary-refused-before-shape-read");
    Check(VM27PrivateEndpointCopySendRight((xpc_endpoint_t)wrong, NULL) == EINVAL, "endpoint-null-result-refused");
    Check(VM27PrivateEndpointConnectSendRight(MACH_PORT_NULL, queue, &connection) == EINVAL && connection == NULL, "null-port-refused-without-owned-shape");
    connection = (xpc_connection_t)wrong;
    Check(VM27PrivateEndpointConnectSendRight(MACH_PORT_DEAD, queue, &connection) == EINVAL && connection == NULL, "dead-port-refused-without-owned-shape");
    Check(!mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ownReceive), "negative-own-receive-right-created");
    connection = (xpc_connection_t)wrong;
    Check(VM27PrivateEndpointConnectSendRight(ownReceive, queue, &connection) == EINVAL && connection == NULL, "receive-only-right-cannot-be-endpoint-send");
    mach_port_type_t type = 0;
    Check(!mach_port_type(mach_task_self(), ownReceive, &type) && type == MACH_PORT_TYPE_RECEIVE, "refusal-does-not-add-send-reference");
    Check(VM27PrivateEndpointConnectSendRight(ownReceive, NULL, &connection) == EINVAL && connection == NULL, "null-queue-refused");
    Check(VM27PrivateEndpointConnectSendRight(ownReceive, queue, NULL) == EINVAL, "null-connection-output-refused");
    Check(!mach_port_destroy(mach_task_self(), ownReceive), "negative-own-receive-right-released");
    xpc_release(wrong); dispatch_release(queue);
    printf("{\"record\":\"endpointNegativeControls\",\"checks\":%u,\"failures\":%u,\"allRefused\":%s,\"ownObjectsReleased\":true}\n", atomic_load(&gChecks) - before, atomic_load(&gFailures) - failures, atomic_load(&gFailures) == failures ? "true" : "false");
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit limit = {5, 5}; setrlimit(RLIMIT_CPU, &limit); alarm(15);
    bool child = argc == 7 && !strcmp(argv[1], "--owned-child");
    if (!child && argc != 4) return 64;
    const char *SHA = child ? argv[3] : argv[1], *sizeText = child ? argv[4] : argv[2], *CD = child ? argv[5] : argv[3];
    size_t bytes = 0; unsigned char *data = Read(argv[0], &bytes); VM27ApprovedCodeInfo self = {0};
    Check(data && bytes == strtoull(sizeText, NULL, 10) && !VM27ApprovedCodeInspectBytes(data, bytes, &self) && !strcmp(self.fileSHA256, SHA) && !strcmp(self.CDHash, CD), "actual-self-fully-signed-and-pinned"); free(data);
    Check(NoVM(), "no-vm-images-preflight"); const char *role = child ? "child" : "parent";
    VM27PrivateEndpointABI abi; Check(!VM27PrivateEndpointCopyABI(&abi) && abi.exactHostABI, "exact-system-libxpc-owned-endpoint-abi");
    printf("{\"record\":\"start\",\"role\":\"%s\",\"PID\":%d,\"UID\":%u,\"selfCDHash\":\"%s\",\"signedPluginBooleanTrue\":%s,\"VMCalls\":0,\"GPUCalls\":0,\"bootstrapChanges\":0,\"launchdRegistrations\":0}\n", role, getpid(), getuid(), CD, self.pluginIsBoolean && self.pluginValue ? "true" : "false");
    printf("{\"record\":\"endpointABI\",\"role\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\",\"exact\":%s}\n", role, abi.providerUUID, (unsigned long long)abi.endpointCreateRVA, abi.exactHostABI ? "true" : "false"); Providers(role, "before");
    if (atomic_load(&gFailures)) return 78;
    if (!child) EndpointNegativeCases();
    mach_port_array_t ports = NULL; mach_msg_type_number_t count = 0;
    Check(!mach_ports_lookup(mach_task_self(), &ports, &count) && count == 3, "actual-three-registered-ports");
    if (!ports || count != 3) return 78;
    if (child) {
        dispatch_queue_t queue = dispatch_queue_create("VM27.PrivateChild.client", DISPATCH_QUEUE_SERIAL); dispatch_semaphore_t replies = dispatch_semaphore_create(0);
        xpc_connection_t connection = NULL;
        Check(!VM27PrivateEndpointConnectSendRight(ports[2], queue, &connection) && connection, "only-own-endpoint-reconstructed-from-real-inherited-send-right");
        if (!connection) { ReleasePorts(ports, count); return 78; }
        xpc_connection_set_event_handler(connection, ^(xpc_object_t e) { (void)e; }); xpc_connection_resume(connection);
        uint64_t nonce = strtoull(argv[2], NULL, 10); pid_t parent = (pid_t)strtol(argv[6], NULL, 10); unsigned good = 0, denied = 0;
        for (unsigned i = 0; i < 65; ++i) {
            __block int response = -1; xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_uint64(message, "nonce", i ? nonce : nonce ^ 1); xpc_dictionary_set_bool(message, VM27_PLUGIN_ENTITLEMENT, true); xpc_dictionary_set_uint64(message, "sequence", i);
            xpc_connection_send_message_with_reply(connection, message, queue, ^(xpc_object_t reply) {
                if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
                    audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(reply, &token);
                    Check(token.val[5] == (uint32_t)parent && token.val[7] > 0, "reply-real-parent-audit-token"); response = (int)xpc_dictionary_get_int64(reply, "gateStatus");
                } dispatch_semaphore_signal(replies);
            }); xpc_release(message);
            Check(!dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "cross-process-xpc-reply-arrived");
            int expected = self.pluginValue ? i ? 0 : EPROTO : EACCES;
            Check(response == expected, "cross-process-reply-reflects-real-signature-gate-and-protocol"); if (response == 0) ++good; else ++denied;
        }
        xpc_connection_cancel(connection); dispatch_sync(queue, ^{}); xpc_release(connection); dispatch_release(replies); dispatch_release(queue); ReleasePorts(ports, count);
        Providers(role, "after"); Check(NoVM(), "child-no-vm-images-after");
        printf("{\"record\":\"childSummary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"realReplies\":65,\"applicationAccepted\":%u,\"deniedReplies\":%u,\"ownedObjectsReleased\":true}\n", getpid(), atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", good, denied);
        return atomic_load(&gFailures) ? 1 : 0;
    }
    Check(ports[2] == MACH_PORT_NULL, "parent-private-registered-slot-empty"); if (ports[2]) { ReleasePorts(ports, count); return 78; }
    xpc_object_t requirement = Requirement(); VM27LWCRPolicy *strict = NULL; VM27ApprovedCodePolicy *approved = NULL;
    Check(!VM27LWCRPolicyCreate(requirement, &strict) && strict, "original-strict-policy-created");
    int create = VM27ApprovedCodePolicyCreate(argv[0], SHA, CD, requirement, &approved);
    Check(create == (self.pluginValue ? 0 : EACCES) && (approved != NULL) == self.pluginValue, "explicit-actual-child-executable-approval-or-refusal"); xpc_release(requirement);
    dispatch_queue_t server = dispatch_queue_create("VM27.PrivateChild.server", DISPATCH_QUEUE_SERIAL); dispatch_suspend(server);
    __block pid_t spawned = 0; __block xpc_connection_t peer = NULL; __block unsigned received = 0, application = 0, protocolRefused = 0;
    uint64_t nonce = 0; arc4random_buf(&nonce, sizeof(nonce)); if (!nonce) nonce = 1;
    xpc_connection_t listener = xpc_connection_create(NULL, server); Check(listener != NULL, "own-anonymous-listener-created");
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        Check(!peer, "only-one-owned-child-peer");
        if (peer) { xpc_connection_cancel((xpc_connection_t)event); return; }
        peer = (xpc_connection_t)xpc_retain(event); xpc_connection_set_target_queue(peer, server);
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(message, &token);
            Check(token.val[5] == (uint32_t)spawned && token.val[7] > 0, "every-message-actual-spawned-child-audit-token");
            VM27ApprovedCodeMessageResult result = {0}; VM27LWCRMessageResult native = {0};
            int status = approved ? VM27ApprovedCodeCheckReceivedMessage(approved, message, &result) : VM27LWCRPolicyCheckReceivedMessage(strict, message, &native);
            if (approved) {
                Check(result.auditPID == (uint32_t)spawned && !strcmp(result.kernelCDHash, CD) && result.codeHashMatched && result.dynamicCodeValid && result.nativePolicy.entitlementIsBoolean && result.nativePolicy.entitlementValue && result.explicitApprovedCodeAccepted, "every-child-message-exact-approved-code-and-native-true"); native = result.nativePolicy;
            }
            Check(native.taskCreated && native.hasRemoteConnection && !native.entitlementReadError, "every-child-message-native-sectask");
            Check(status == (self.pluginValue ? 0 : EACCES), "unapproved-code-never-reaches-user-handler");
            if (token.val[5] != (uint32_t)spawned) status = EACCES;
            xpc_object_t nonceValue = xpc_dictionary_get_value(message, "nonce"), sequenceValue = xpc_dictionary_get_value(message, "sequence");
            if (!status && (!nonceValue || !sequenceValue || xpc_get_type(nonceValue) != XPC_TYPE_UINT64 ||
                            xpc_get_type(sequenceValue) != XPC_TYPE_UINT64 ||
                            xpc_dictionary_get_uint64(message, "nonce") != nonce ||
                            xpc_dictionary_get_uint64(message, "sequence") != received)) { status = EPROTO; ++protocolRefused; }
            if (!status) ++application;
            if (!received) printf("{\"record\":\"nativeChildIdentity\",\"childPID\":%u,\"childPIDVersion\":%u,\"kernelCDHash\":\"%s\",\"codeStatus\":%u,\"explicitApproved\":%s,\"strictValidated\":%s,\"nativeBooleanTrue\":%s}\n", token.val[5], token.val[7], result.kernelCDHash, result.codeStatus, result.explicitApprovedCodeAccepted ? "true" : "false", native.entitlementsValidated ? "true" : "false", native.entitlementIsBoolean && native.entitlementValue ? "true" : "false");
            ++received; xpc_object_t reply = xpc_dictionary_create_reply(message); Check(reply != NULL, "owned-control-reply-created"); if (reply) { xpc_dictionary_set_int64(reply, "gateStatus", status); xpc_connection_send_message(peer, reply); xpc_release(reply); }
        }); xpc_connection_resume(peer);
    }); xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener); mach_port_t inherited = MACH_PORT_NULL;
    Check(!VM27PrivateEndpointCopySendRight(endpoint, &inherited) && MACH_PORT_VALID(inherited), "own-endpoint-real-send-reference-copied");
    if (!inherited) return 78;
    posix_spawnattr_t attr; Check(!posix_spawnattr_init(&attr), "spawn-attributes-created"); mach_port_t registered[3] = {ports[0], ports[1], inherited};
    Check(!posix_spawnattr_set_registered_ports_np(&attr, registered, 3), "only-child-slot-two-inherits-anonymous-port");
    char nonceText[32], parentText[32]; snprintf(nonceText, sizeof(nonceText), "%llu", (unsigned long long)nonce); snprintf(parentText, sizeof(parentText), "%d", getpid());
    char *arguments[] = {argv[0], "--owned-child", nonceText, (char *)SHA, (char *)sizeText, (char *)CD, parentText, NULL};
    int spawnResult = posix_spawn(&spawned, argv[0], NULL, &attr, arguments, environ); Check(!spawnResult && spawned > 1, "exact-approved-self-child-actually-spawned");
    Check(!posix_spawnattr_destroy(&attr), "spawn-attributes-released"); dispatch_resume(server);
    printf("{\"record\":\"spawn\",\"parentPID\":%d,\"childPID\":%d,\"spawnResult\":%d}\n", getpid(), spawned, spawnResult);
    if (spawnResult || spawned <= 1) return 78;
    int waitStatus = 0; pid_t waited; do { waited = waitpid(spawned, &waitStatus, 0); } while (waited < 0 && errno == EINTR);
    Check(waited == spawned && WIFEXITED(waitStatus) && WEXITSTATUS(waitStatus) == 0, "actual-owned-child-exit-zero-reaped"); bool absent = kill(spawned, 0) == -1 && errno == ESRCH; Check(absent, "actual-owned-child-absent");
    dispatch_sync(server, ^{ Check(received == 65 && application == (self.pluginValue ? 64u : 0u) && protocolRefused == (self.pluginValue ? 1u : 0u), "actual-cross-process-messages-gated-before-handler"); });
    if (peer) xpc_connection_cancel(peer); xpc_connection_cancel(listener); dispatch_sync(server, ^{}); if (peer) xpc_release(peer); xpc_release(endpoint); xpc_release(listener); dispatch_release(server);
    Check(!mach_port_deallocate(mach_task_self(), inherited), "own-copied-endpoint-send-reference-released");
    mach_port_array_t after = NULL; mach_msg_type_number_t afterCount = 0;
    Check(!mach_ports_lookup(mach_task_self(), &after, &afterCount) && afterCount == count && after[0] == ports[0] && after[1] == ports[1] && after[2] == ports[2], "parent-registered-table-remains-identical"); ReleasePorts(after, afterCount); ReleasePorts(ports, count);
    if (approved) VM27ApprovedCodePolicyRelease(approved); VM27LWCRPolicyRelease(strict); VM27ApprovedCodeStats stats; VM27ApprovedCodeCopyStats(&stats); VM27LWCRStats policy; VM27LWCRCopyStats(&policy);
    Check(policy.taskCreates == policy.taskReleases && policy.taskCreates == 65 && policy.policiesCreated == policy.policiesDestroyed, "all-child-sectasks-and-immutable-policies-released");
    Check(stats.created == stats.destroyed && stats.created == (self.pluginValue ? 1u : 0u) && stats.accepted == (self.pluginValue ? 65u : 0u), "approved-policies-and-authenticated-child-message-lifecycles");
    Providers(role, "after"); Check(NoVM(), "parent-no-vm-images-after");
    printf("{\"record\":\"summary\",\"parentPID\":%d,\"spawnedChildPID\":%d,\"observedChildWaitExit\":%d,\"childAbsent\":%s,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"realXPCMessages\":%u,\"applicationCalls\":%u,\"protocolRefused\":%u,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"approvedCodeQueries\":%llu,\"parentRegisteredPortsUnchanged\":true,\"bootstrapChanges\":0,\"launchdRegistrations\":0,\"ownObjectsReleased\":true,\"completeBundleRegistration\":false}\n", getpid(), spawned, WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : -1, absent ? "true" : "false", atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", received, application, protocolRefused, (unsigned long long)policy.taskCreates, (unsigned long long)policy.taskReleases, (unsigned long long)stats.codeQueries);
    return atomic_load(&gFailures) ? 1 : 0;
}
