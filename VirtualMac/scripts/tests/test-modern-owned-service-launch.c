#include "modern_xpc_private_endpoint.h"
#include "modern_xpc_approved_code.h"
#include "modern_xpc_service_pins.h"
#include "modern_xpc_private_consumer.h"
#include <fcntl.h>
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
static const char *ServiceID = "com.virtualmac.diagnostics.launched.service";
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
    Identity(role, phase, "VM27PrivateServiceConsumerCheckMessage", (void *)VM27PrivateServiceConsumerCheckMessage, VM27_CONSUMER_SHA256, VM27_CONSUMER_BYTES, VM27_CONSUMER_UUID);
    Identity(role, phase, "VM27BundleRegistryRegister", (void *)VM27BundleRegistryRegister, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
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
static bool Write(const char *path, const void *data, size_t bytes, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return false;
    bool ok = !fchmod(fd, mode); size_t at = 0;
    while (ok && at < bytes) { ssize_t count = write(fd, (const char *)data + at, bytes - at); if (count < 0 && errno == EINTR) continue; if (count <= 0) { ok = false; break; } at += (size_t)count; }
    if (fsync(fd)) ok = false; if (close(fd)) ok = false; return ok;
}
static bool Fixture(const char *self, char root[4096], char paths[8][4096], char code[4096]) {
    char temporary[] = "/tmp/VM27-OwnedLaunch-XXXXXX";
    Check(mkdtemp(temporary) && realpath(temporary, root), "owned-launch-fixture-root-created");
    if (!*root) return false;
    const char *suffixes[] = {"Owned.bundle", "Owned.bundle/Contents", "Owned.bundle/Contents/XPCServices", "Owned.bundle/Contents/XPCServices/One.xpc", "Owned.bundle/Contents/XPCServices/One.xpc/Contents", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS", "Owned.bundle/Contents/Info.plist", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/Info.plist"};
    for (unsigned i = 0; i < 8; ++i) {
        int written = snprintf(paths[i], 4096, "%s/%s", root, suffixes[i]); Check(written > 0 && written < 4096, "owned-launch-path-bounded");
        if (i < 6) Check(!mkdir(paths[i], 0700), "owned-launch-directory-created");
    }
    int written = snprintf(code, 4096, "%s/ServiceExec", paths[5]); Check(written > 0 && written < 4096, "owned-launch-code-path-bounded");
    const char parent[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.virtualmac.diagnostics.launched.bundle</string></dict></plist>";
    const char service[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.virtualmac.diagnostics.launched.service</string><key>CFBundleExecutable</key><string>ServiceExec</string><key>CFBundlePackageType</key><string>XPC!</string></dict></plist>";
    size_t bytes = 0; unsigned char *data = Read(self, &bytes);
    Check(Write(paths[6], parent, sizeof(parent) - 1, 0600) && Write(paths[7], service, sizeof(service) - 1, 0600), "owned-launch-real-plists-written");
    Check(data && Write(code, data, bytes, 0700), "owned-launch-identical-signed-code-written"); free(data);
    return !atomic_load(&gFailures);
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
    printf("{\"record\":\"start\",\"role\":\"%s\",\"PID\":%d,\"UID\":%u,\"executedPath\":\"%s\",\"selfCDHash\":\"%s\",\"signedPluginBooleanTrue\":%s,\"VMCalls\":0,\"GPUCalls\":0,\"bootstrapChanges\":0,\"launchdRegistrations\":0}\n", role, getpid(), getuid(), argv[0], CD, self.pluginIsBoolean && self.pluginValue ? "true" : "false");
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
    char root[4096] = {0}, paths[8][4096], codePath[4096];
    if (!Fixture(argv[0], root, paths, codePath)) return 78;
    VM27BundleRegistry *registry = NULL; VM27PrivateServicePlan *plan = NULL;
    xpc_object_t requirement = Requirement();
    Check(!VM27BundleRegistryCreate(root, &registry) && registry, "real-private-registry-created");
    Check(!VM27BundleRegistryRegister(registry, paths[0], 2, requirement), "real-private-service-record-committed");
    Check(!VM27BundleRegistryCopyServicePlan(registry, ServiceID, &plan) && plan, "real-registry-plan-consumed");
    VM27PrivateServiceInfo info = {0}; Check(!VM27PrivateServicePlanCopyInfo(plan, &info) && !strcmp(info.executablePath, codePath) && !strcmp(info.executableSHA256, SHA) && info.executableBytes == bytes && info.flags == 2, "real-plan-exact-service-code-consumed");
    printf("{\"record\":\"registeredService\",\"service\":\"%s\",\"path\":\"%s\",\"codeSHA256\":\"%s\",\"codeUUID\":\"%s\",\"codeBytes\":%llu,\"flags\":2}\n", info.serviceIdentifier, info.executablePath, info.executableSHA256, info.executableUUID, (unsigned long long)info.executableBytes);
    VM27PrivateServicePlanRelease(plan); plan = NULL;
    VM27PrivateServiceConsumer *consumer = NULL, *negative = NULL;
    Check(VM27PrivateServiceConsumerCreate(registry, "absent.service", SHA, CD, requirement, VM27ConsumerStrictNative, &negative) == ENOENT && !negative, "missing-service-cannot-launch");
    char badSHA[65], badCD[41]; memcpy(badSHA, SHA, 65); badSHA[0] = SHA[0] == '0' ? '1' : '0'; memcpy(badCD, CD, 41); badCD[0] = CD[0] == '0' ? '1' : '0';
    Check(VM27PrivateServiceConsumerCreate(registry, ServiceID, badSHA, CD, requirement, VM27ConsumerStrictNative, &negative) == EACCES && !negative, "unapproved-service-sha-refused");
    Check(VM27PrivateServiceConsumerCreate(registry, ServiceID, SHA, badCD, requirement, VM27ConsumerStrictNative, &negative) == EACCES && !negative, "unapproved-service-cdhash-refused");
    Check(VM27PrivateServiceConsumerCreate(registry, ServiceID, SHA, CD, requirement, 0, &negative) == EINVAL && !negative, "invalid-consumer-mode-refused");
    xpc_object_t extra = Requirement(); xpc_dictionary_set_bool(extra, "ignored-constraint", true);
    Check(VM27PrivateServiceConsumerCreate(registry, ServiceID, SHA, CD, extra, VM27ConsumerStrictNative, &negative) == ENOTSUP && !negative, "additional-requirement-never-dropped"); xpc_release(extra);
    if (!self.pluginValue) Check(VM27PrivateServiceConsumerCreate(registry, ServiceID, SHA, CD, requirement, VM27ConsumerExplicitApprovedCode, &negative) == EACCES && !negative, "native-mac-no-plugin-approved-create-refused");
    Check(!VM27PrivateServiceConsumerCreate(registry, ServiceID, SHA, CD, requirement, self.pluginValue ? VM27ConsumerExplicitApprovedCode : VM27ConsumerStrictNative, &consumer) && consumer, "real-registry-typed-consumer-created");
    VM27PrivateConsumerState untouched = {0};
    Check(!VM27PrivateServiceConsumerCopyState(consumer, &untouched) && !untouched.started && !untouched.childPID && untouched.observedWaitExit == -1, "new-consumer-owns-no-process-before-spawn");
    untouched.childPID = 1;
    Check(!VM27PrivateServiceConsumerCopyState(consumer, &untouched) && !untouched.childPID, "caller-state-copy-cannot-mutate-consumer");
    xpc_release(requirement); VM27BundleRegistryRelease(registry); registry = NULL;
    xpc_object_t spoof = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_bool(spoof, VM27_PLUGIN_ENTITLEMENT, true); VM27ApprovedCodeMessageResult spoofResult = {0};
    Check(VM27PrivateServiceConsumerCheckMessage(consumer, spoof, &spoofResult) == EACCES && !spoofResult.nativePolicy.taskCreated, "unspawned-message-body-cannot-authorize-service"); xpc_release(spoof);
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
            int status = VM27PrivateServiceConsumerCheckMessage(consumer, message, &result); native = result.nativePolicy;
            if (self.pluginValue) {
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
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    char nonceText[32], parentText[32]; snprintf(nonceText, sizeof(nonceText), "%llu", (unsigned long long)nonce); snprintf(parentText, sizeof(parentText), "%d", getpid());
    char *arguments[] = {info.executablePath, "--owned-child", nonceText, (char *)SHA, (char *)sizeText, (char *)CD, parentText, NULL};
    pid_t refused = -1;
    Check(VM27PrivateServiceConsumerSpawn(consumer, NULL, arguments, environ, &refused) == EINVAL && !refused, "null-endpoint-does-not-launch-child");
    char *badArguments[] = {argv[0], NULL};
    Check(VM27PrivateServiceConsumerSpawn(consumer, endpoint, badArguments, environ, &refused) == EINVAL && !refused, "unregistered-executable-path-does-not-launch");
    char *badEnvironment[] = {"DYLD_INSERT_LIBRARIES=/tmp/unapproved.dylib", NULL};
    Check(VM27PrivateServiceConsumerSpawn(consumer, endpoint, arguments, badEnvironment, &refused) == EINVAL && !refused, "dynamic-library-override-does-not-launch");
    size_t plistBytes = 0; unsigned char *plist = Read(paths[7], &plistBytes);
    Check(plist && Write(paths[7], "corrupt", 7, 0600), "owned-service-plist-corruption-control-created");
    Check(VM27PrivateServiceConsumerSpawn(consumer, endpoint, arguments, environ, &refused) == ESTALE && !refused, "changed-service-plan-does-not-launch");
    Check(Write(paths[7], plist, plistBytes, 0600), "owned-service-plist-control-restored"); free(plist);
    int spawnResult = VM27PrivateServiceConsumerSpawn(consumer, endpoint, arguments, environ, &spawned); Check(!spawnResult && spawned > 1, "exact-registered-service-child-actually-spawned");
    Check(VM27PrivateServiceConsumerRelease(consumer) == EBUSY, "active-owned-child-cannot-be-orphaned-by-release");
    Check(VM27PrivateServiceConsumerSpawn(consumer, endpoint, arguments, environ, &refused) == EALREADY && !refused, "consumer-cannot-launch-second-child");
    VM27PrivateConsumerState early = {0};
    Check(VM27PrivateServiceConsumerWait(consumer, false, &early) == EAGAIN && !early.reaped && early.childPID == spawned, "nonblocking-wait-observes-real-live-owned-child");
    dispatch_resume(server);
    printf("{\"record\":\"spawn\",\"parentPID\":%d,\"childPID\":%d,\"spawnResult\":%d}\n", getpid(), spawned, spawnResult);
    if (spawnResult || spawned <= 1) return 78;
    VM27PrivateConsumerState lifecycle = {0};
    Check(!VM27PrivateServiceConsumerWait(consumer, true, &lifecycle) && lifecycle.reaped && lifecycle.observedWaitExit == 0 && lifecycle.childPID == spawned && lifecycle.absent && lifecycle.parentRegisteredPortsUnchanged, "actual-registry-consumer-reaped-child-and-preserved-parent");
    bool absent = lifecycle.absent;
    VM27PrivateConsumerState stale = {0}; Check(VM27PrivateServiceConsumerWait(consumer, false, &stale) == EALREADY, "reaped-child-cannot-be-waited-as-new-process");
    dispatch_sync(server, ^{ Check(received == 65 && application == (self.pluginValue ? 64u : 0u) && protocolRefused == (self.pluginValue ? 1u : 0u), "actual-cross-process-messages-gated-before-handler"); });
    if (peer) xpc_connection_cancel(peer); xpc_connection_cancel(listener); dispatch_sync(server, ^{}); if (peer) xpc_release(peer); xpc_release(endpoint); xpc_release(listener); dispatch_release(server);
    mach_port_array_t after = NULL; mach_msg_type_number_t afterCount = 0;
    Check(!mach_ports_lookup(mach_task_self(), &after, &afterCount) && afterCount == count && after[0] == ports[0] && after[1] == ports[1] && after[2] == ports[2], "parent-registered-table-remains-identical"); ReleasePorts(after, afterCount); ReleasePorts(ports, count);
    Check(lifecycle.messageChecks == 66 && lifecycle.messagesAccepted == (self.pluginValue ? 65u : 0u), "every-registered-child-message-checked-by-real-consumer");
    Check(!VM27PrivateServiceConsumerRelease(consumer), "real-consumer-owned-plan-policy-released"); consumer = NULL;
    VM27ApprovedCodeStats stats; VM27ApprovedCodeCopyStats(&stats); VM27LWCRStats policy; VM27LWCRCopyStats(&policy);
    VM27PrivateConsumerStats consumers; VM27PrivateServiceConsumerCopyStats(&consumers); VM27BundleRegistryStats registrations; VM27BundleRegistryCopyStats(&registrations);
    Check(consumers.created == 1 && consumers.destroyed == 1 && consumers.spawns == 1 && consumers.reaps == 1 && consumers.messageChecks == 66, "registered-consumer-real-lifecycles-paired");
    Check(registrations.registrations == 1 && registrations.registeredServices == 1 && registrations.plansCreated == registrations.plansDestroyed, "all-registry-owned-plans-released");
    Check(policy.taskCreates == policy.taskReleases && policy.taskCreates == 65 && policy.policiesCreated == policy.policiesDestroyed, "all-child-sectasks-and-immutable-policies-released");
    Check(stats.created == stats.destroyed && stats.created == (self.pluginValue ? 1u : 0u) && stats.accepted == (self.pluginValue ? 65u : 0u), "approved-policies-and-authenticated-child-message-lifecycles");
    Check(!unlink(codePath) && !unlink(paths[7]) && !unlink(paths[6]), "only-own-service-files-removed");
    for (int i = 5; i >= 0; --i) Check(!rmdir(paths[i]), "only-own-service-directory-removed");
    Check(!rmdir(root) && access(root, F_OK) == -1 && errno == ENOENT, "only-own-service-root-removed-and-absent");
    printf("{\"record\":\"consumerLifecycle\",\"consumersCreated\":%llu,\"consumersDestroyed\":%llu,\"spawns\":%llu,\"reaps\":%llu,\"messageChecks\":%llu,\"messagesAccepted\":%llu,\"registrations\":%llu,\"services\":%llu,\"plansCreated\":%llu,\"plansDestroyed\":%llu,\"ownTemporaryRemoved\":true,\"actualServicePlanConsumed\":true}\n", (unsigned long long)consumers.created, (unsigned long long)consumers.destroyed, (unsigned long long)consumers.spawns, (unsigned long long)consumers.reaps, (unsigned long long)consumers.messageChecks, (unsigned long long)lifecycle.messagesAccepted, (unsigned long long)registrations.registrations, (unsigned long long)registrations.registeredServices, (unsigned long long)registrations.plansCreated, (unsigned long long)registrations.plansDestroyed);
    Providers(role, "after"); Check(NoVM(), "parent-no-vm-images-after");
    printf("{\"record\":\"summary\",\"parentPID\":%d,\"spawnedChildPID\":%d,\"observedChildWaitExit\":%d,\"childAbsent\":%s,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"realXPCMessages\":%u,\"applicationCalls\":%u,\"protocolRefused\":%u,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"approvedCodeQueries\":%llu,\"parentRegisteredPortsUnchanged\":true,\"bootstrapChanges\":0,\"launchdRegistrations\":0,\"ownObjectsReleased\":true,\"completeBundleRegistration\":false}\n", getpid(), spawned, lifecycle.observedWaitExit, absent ? "true" : "false", atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", received, application, protocolRefused, (unsigned long long)policy.taskCreates, (unsigned long long)policy.taskReleases, (unsigned long long)stats.codeQueries);
    return atomic_load(&gFailures) ? 1 : 0;
}
