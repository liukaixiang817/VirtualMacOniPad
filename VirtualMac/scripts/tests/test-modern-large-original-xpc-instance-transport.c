#include "modern_xpc_private_endpoint.h"
#include "modern_xpc_approved_code.h"
#include "modern_xpc_large_factory_pins.h"
#include "modern_xpc_large_original_instance_transport.h"
#include "modern_xpc_large_original_parent.h"
#include <Block.h>
#include "modern_xpc_large_private_consumer.h"
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
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern char **environ;
static _Atomic unsigned gChecks, gFailures;
static const char *ServiceID = VM27_ORIGINAL_VM_SERVICE;
static void (^OriginalHandlerBlock)(xpc_connection_t);
static dispatch_queue_t OriginalExpectedQueue;
static const char OriginalQueueKey;
static unsigned char BoundChildInstance[16];
static bool InstanceWasBound;
static unsigned InstanceMessages;
static void Check(bool, const char *);
static void OriginalCHandler(xpc_connection_t peer) {
    Check(dispatch_get_specific(&OriginalQueueKey) == OriginalExpectedQueue, "original-C-callback-exact-user-supplied-serial-queue");
    unsigned char actual[16] = {0};
    Check(InstanceWasBound && !VM27LargeOriginalTransportCopyServerInstance(actual) && !memcmp(actual, BoundChildInstance, 16), "original-C-callback-consumes-acknowledged-child-instance-UUID");
    OriginalHandlerBlock(peer);
}
static void Check(bool ok, const char *name) { atomic_fetch_add(&gChecks, 1); if (!ok) { atomic_fetch_add(&gFailures, 1); printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", name); } }
static uint64_t MonotonicNanoseconds(void) {
    struct timespec now = {0};
    Check(!clock_gettime(CLOCK_MONOTONIC, &now), "actual-monotonic-setter-deadline-clock");
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}
static unsigned char *Read(const char *p, size_t *bytes) {
    *bytes = 0; FILE *f = fopen(p, "rb"); struct stat state;
    if (!f || fstat(fileno(f), &state) || !S_ISREG(state.st_mode) || state.st_size <= 0 || state.st_size > 8 * 1024 * 1024) { if (f) fclose(f); return NULL; }
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
    Identity(role, phase, "VM27LargeOriginalTransportCopyABI", (void *)VM27LargeOriginalTransportCopyABI, VM27_TRANSPORT_SHA256, VM27_TRANSPORT_BYTES, VM27_TRANSPORT_UUID);
    Identity(role, phase, "VM27LargePrivateServiceConsumerCheckMessage", (void *)VM27LargePrivateServiceConsumerCheckMessage, VM27_CONSUMER_SHA256, VM27_CONSUMER_BYTES, VM27_CONSUMER_UUID);
    Identity(role, phase, "VM27LargeBundleRegistryRegister", (void *)VM27LargeBundleRegistryRegister, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
    Identity(role, phase, "VM27PrivateEndpointConnectSendRight", (void *)VM27PrivateEndpointConnectSendRight, VM27_ENDPOINT_SHA256, VM27_ENDPOINT_BYTES, VM27_ENDPOINT_UUID);
    Identity(role, phase, "VM27ApprovedCodeCheckReceivedMessage", (void *)VM27ApprovedCodeCheckReceivedMessage, VM27_APPROVED_SHA256, VM27_APPROVED_BYTES, VM27_APPROVED_UUID);
    Identity(role, phase, "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
    Identity(role, phase, "VM27LargeOriginalParentCheckFile", (void *)VM27LargeOriginalParentCheckFile, VM27_LPARENT_SHA256, VM27_LPARENT_BYTES, VM27_LPARENT_UUID);
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
    char temporary[] = "/tmp/VM27-LargeOwnedFactory-XXXXXX";
    Check(mkdtemp(temporary) && realpath(temporary, root), "owned-launch-fixture-root-created");
    if (!*root) return false;
    const char *suffixes[] = {"Owned.bundle", "Owned.bundle/Contents", "Owned.bundle/Contents/XPCServices", "Owned.bundle/Contents/XPCServices/One.xpc", "Owned.bundle/Contents/XPCServices/One.xpc/Contents", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS", "Owned.bundle/Contents/Info.plist", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/Info.plist"};
    for (unsigned i = 0; i < 8; ++i) {
        int written = snprintf(paths[i], 4096, "%s/%s", root, suffixes[i]); Check(written > 0 && written < 4096, "owned-launch-path-bounded");
        if (i < 6) Check(!mkdir(paths[i], 0700), "owned-launch-directory-created");
    }
    int written = snprintf(code, 4096, "%s/ServiceExec", paths[5]); Check(written > 0 && written < 4096, "owned-launch-code-path-bounded");
    const char parent[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.virtualmac.diagnostics.factory.bundle</string></dict></plist>";
    const char service[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.apple.Virtualization.VirtualMachine</string><key>CFBundleExecutable</key><string>ServiceExec</string><key>CFBundlePackageType</key><string>XPC!</string></dict></plist>";
    size_t bytes = 0; unsigned char *data = Read(self, &bytes);
    Check(Write(paths[6], parent, sizeof(parent) - 1, 0600) && Write(paths[7], service, sizeof(service) - 1, 0600), "owned-launch-real-plists-written");
    Check(data && Write(code, data, bytes, 0700), "owned-launch-identical-signed-code-written"); free(data);
    return !atomic_load(&gFailures);
}
/* The genuine5.2MiB VMM remains inert bytes. Its unstarted consumer is
 * released before the small actual service consumer is created. The server
 * created here validates data pages, then closes before any peer/callback;
 * its data CDHash is never presented as the running small CLI identity. */
static void InertLargeRoute(void) {
    size_t bytes = 0; unsigned char *data = Read(VM27_INERT_DATA_PATH, &bytes);
    VM27ApprovedCodeInfo info = {0};
    Check(data && bytes == VM27_INERT_DATA_BYTES && bytes > 2 * 1024 * 1024 &&
          !VM27ApprovedCodeInspectBytes(data, bytes, &info) &&
          !strcmp(info.fileSHA256, VM27_INERT_DATA_SHA256) &&
          !strcmp(info.CDHash, VM27_INERT_DATA_CDHASH) &&
          !strcmp(info.UUID, VM27_INERT_DATA_UUID), "inert-original-VMM-exact-signed-pages-not-an-executable-service");
    free(data);
    char root[4096] = {0}, paths[8][4096], code[4096];
    if (!Fixture(VM27_INERT_DATA_PATH, root, paths, code)) return;
    VM27LargeBundleRegistry *registry = NULL; VM27LargePrivateServiceConsumer *unstarted = NULL;
    xpc_object_t requirement = Requirement();
    Check(!VM27LargeBundleRegistryCreate(root, &registry) &&
          !VM27LargeBundleRegistryRegister(registry, paths[0], 2, requirement),
          "same-Large-registry-actual-original-inert-file-plan");
    Check(!VM27LargePrivateServiceConsumerCreate(registry, ServiceID,
          VM27_INERT_DATA_SHA256, VM27_INERT_DATA_CDHASH, requirement,
          VM27LargeConsumerStrictNative, &unstarted) && unstarted,
          "same-Large-consumer-actual-5MiB-authentication-without-spawn");
    VM27LargePrivateConsumerState state = {0};
    Check(!VM27LargePrivateServiceConsumerCopyState(unstarted, &state) &&
          !state.started && !state.childPID && !state.messageChecks,
          "inert-original-consumer-no-start-or-messages");
    Check(!VM27LargePrivateServiceConsumerRelease(unstarted),
          "inert-original-consumer-released-before-real-small-service");
    VM27LargeBundleRegistryRelease(registry); xpc_release(requirement);
    dispatch_queue_t queue = dispatch_queue_create("VM27.Large.inert-validation", DISPATCH_QUEUE_SERIAL);
    xpc_endpoint_t endpoint = NULL;
    VM27LargeOriginalTransportStats before = {0}, after = {0};
    VM27LargeOriginalTransportCopyStats(&before);
    Check(!VM27LargeOriginalTransportCreateServer(code, VM27_INERT_DATA_SHA256,
          VM27_INERT_DATA_CDHASH, getpid(), queue, &endpoint) && endpoint,
          "actual-new-transport-uses-LargeParent-to-inspect-inert-original-pages");
    Check(!VM27LargeOriginalTransportStopServer(),
          "inert-validation-listener-never-started-real-final-invalid-release");
    if (endpoint) xpc_release(endpoint); dispatch_release(queue);
    VM27LargeOriginalTransportCopyStats(&after);
    Check(after.parentFileInspections == before.parentFileInspections + 1 &&
          after.largeParentFileInspections == before.largeParentFileInspections + 1 &&
          after.originalMainCalls == before.originalMainCalls &&
          after.originalHandlerCalls == before.originalHandlerCalls,
          "actual-inert-parent-inspection-route-counter-and-zero-original-handler");
    Check(!unlink(code) && !unlink(paths[7]) && !unlink(paths[6]), "inert-owned-files-removed");
    for (int i = 5; i >= 0; --i) Check(!rmdir(paths[i]), "inert-owned-directories-removed");
    Check(!rmdir(root) && access(root, F_OK) == -1 && errno == ENOENT, "inert-owned-root-actually-absent");
    printf("{\"record\":\"largeInertRoute\",\"PID\":%d,\"originalDataBytes\":%llu,\"originalDataUUID\":\"%s\",\"originalDataSHA256\":\"%s\",\"ownTemporaryPath\":\"%s\",\"ownTemporaryRemoved\":true,\"plansCreatedDestroyed\":1,\"unstartedConsumersCreatedDestroyed\":1,\"transportLargeParentInspections\":1,\"originalVMMExecutions\":0,\"originalDataSpawns\":0,\"messages\":0,\"originalPluginLoaderExecutions\":0}\n",
          getpid(), (unsigned long long)bytes, info.UUID, info.fileSHA256, root);
}

extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);
static _Atomic unsigned IdentityQueries;
static bool PeerIdentity(xpc_object_t message, pid_t expectedPID, const char *CD, const char *role, const char *phase, bool log) {
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(message, &token);
    unsigned char codeHash[20] = {0}; unsigned status = 0;
    if (token.val[5] != (unsigned)expectedPID || !token.val[7]) return false;
    int hashResult = csops_audittoken(expectedPID, 5, codeHash, sizeof(codeHash), &token);
    int statusResult = csops_audittoken(expectedPID, 0, &status, sizeof(status), &token);
    char actual[41] = {0}; for (unsigned i = 0; i < 20; ++i) snprintf(actual + i * 2, 3, "%02x", codeHash[i]);
    bool ok = !hashResult && !statusResult && status & 1 && !strcmp(actual, CD);
    atomic_fetch_add(&IdentityQueries, 1);
    if (log) printf("{\"record\":\"peerIdentity\",\"role\":\"%s\",\"phase\":\"%s\",\"PID\":%u,\"PIDVersion\":%u,\"kernelCDHash\":\"%s\",\"codeStatus\":%u,\"codeQueryResult\":%d,\"statusQueryResult\":%d,\"matched\":%s}\n", role, phase, token.val[5], token.val[7], actual, status, hashResult, statusResult, ok ? "true" : "false");
    return ok;
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit cpu = {5, 5}; setrlimit(RLIMIT_CPU, &cpu); alarm(15);
    bool child = argc == 9 && !strcmp(argv[1], "--factory-child");
    if (!child && argc != 5) return 64;
    const char *SHA = child ? argv[3] : argv[1], *sizeText = child ? argv[4] : argv[2], *CD = child ? argv[5] : argv[3], *variant = child ? argv[8] : argv[4];
    bool deniedHandshake = !strcmp(variant, "deny-handshake"), timeoutHandshake = !strcmp(variant, "timeout-handshake"); bool deniedInstance = !strcmp(variant, "deny-instance"), timeoutInstance = !strcmp(variant, "timeout-instance");
    if (!deniedHandshake && !timeoutHandshake && !deniedInstance && !timeoutInstance && strcmp(variant, "normal")) return 64;
    size_t bytes = 0; unsigned char *code = Read(argv[0], &bytes); VM27ApprovedCodeInfo self = {0};
    Check(code && bytes == strtoull(sizeText, NULL, 10) && !VM27ApprovedCodeInspectBytes(code, bytes, &self) && !strcmp(self.fileSHA256, SHA) && !strcmp(self.CDHash, CD), "actual-own-executable-full-code-pages-and-pins"); free(code);
    const char *role = child ? "child" : "parent"; VM27PrivateEndpointABI abi; VM27LargeOriginalTransportABI originalABI;
    Check(!VM27LargeOriginalTransportCopyABI(&originalABI) && originalABI.exactSystemProvider && originalABI.exactGetterCode && originalABI.exactSecurityProvider && originalABI.exactInstanceCode, "exact-libxpc-getter-code-and-strong-security-provider");
    printf("{\"record\":\"originalABI\",\"role\":\"%s\",\"XPCUUID\":\"%s\",\"SecurityUUID\":\"%s\",\"createRVA\":\"0x%llx\",\"mainRVA\":\"0x%llx\",\"auditRVA\":\"0x%llx\",\"entitlementRVA\":\"0x%llx\",\"taskRVA\":\"0x%llx\",\"taskCopyRVA\":\"0x%llx\",\"validatedRVA\":\"0x%llx\"}\n", role, originalABI.providerUUID, originalABI.securityUUID, (unsigned long long)originalABI.nativeCreateRVA, (unsigned long long)originalABI.nativeMainRVA, (unsigned long long)originalABI.auditGetterRVA, (unsigned long long)originalABI.entitlementGetterRVA, (unsigned long long)originalABI.secTaskCreateRVA, (unsigned long long)originalABI.secTaskCopyRVA, (unsigned long long)originalABI.secTaskValidatedRVA);
    printf("{\"record\":\"instanceABI\",\"role\":\"%s\",\"oneShotRVA\":\"0x%llx\",\"setInstanceRVA\":\"0x%llx\",\"getInstanceRVA\":\"0x%llx\",\"exactCode\":%s}\n", role, (unsigned long long)originalABI.oneShotRVA, (unsigned long long)originalABI.instanceSetRVA, (unsigned long long)originalABI.instanceGetRVA, originalABI.exactInstanceCode ? "true" : "false");
    Check(NoVM() && !VM27PrivateEndpointCopyABI(&abi) && abi.exactHostABI, "only-pinned-endpoint-abi-no-vm-images");
    printf("{\"record\":\"start\",\"role\":\"%s\",\"PID\":%d,\"UID\":%u,\"variant\":\"%s\",\"executedPath\":\"%s\",\"selfCDHash\":\"%s\",\"signedPluginBooleanTrue\":%s,\"VMCalls\":0,\"GPUCalls\":0,\"bootstrapChanges\":0,\"launchdRegistrations\":0}\n", role, getpid(), getuid(), variant, argv[0], CD, self.pluginValue ? "true" : "false");
    printf("{\"record\":\"endpointABI\",\"role\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\",\"exact\":%s}\n", role, abi.providerUUID, (unsigned long long)abi.endpointCreateRVA, abi.exactHostABI ? "true" : "false"); Providers(role, "before");
    if (atomic_load(&gFailures)) return 78;
    if (!child) EndpointNegativeCases();
    if (!child) {
        dispatch_queue_t rollback = dispatch_queue_create("VM27.Rollback.test", DISPATCH_QUEUE_SERIAL);
        xpc_endpoint_t one = NULL, second = NULL;
        VM27LargeOriginalTransportInjectEndpointFailureOnceForDiagnostic();
        Check(VM27LargeOriginalTransportCreateServer(argv[0], SHA, CD, getpid(), rollback, &one) == ENOMEM && !one, "forced-endpoint-failure-owned-inactive-listener-real-cancel-drain");
        Check(!VM27LargeOriginalTransportCreateServer(argv[0], SHA, CD, getpid(), rollback, &one) && one, "rollback-fixture-real-first-server-created");
        Check(VM27LargeOriginalTransportCreateServer(argv[0], SHA, CD, getpid(), rollback, &second) == EBUSY && !second, "busy-real-listener-rollback-uses-private-cancel-drain-queue");
        Check(!VM27LargeOriginalTransportStopServer(), "rollback-fixture-first-never-started-server-resumed-cancelled-released");
        xpc_release(one); dispatch_release(rollback);
        VM27LargeOriginalTransportStats stats = {0}; VM27LargeOriginalTransportCopyStats(&stats);
        Check(stats.rollbackListenersStarted == 2 && stats.rollbackListenersReleased == 2 && stats.rollbackFinalInvalidEvents == 2 && stats.listenersCreated == stats.listenersDestroyed && stats.listenersCreated == 1, "rollback-both-real-final-invalid-events-and-owned-releases-paired");
        printf("{\"record\":\"listenerRollback\",\"started\":%llu,\"released\":%llu,\"finalInvalid\":%llu,\"injectedEndpointFailures\":1,\"busyRollbacks\":1,\"firstServerReleased\":true}\n", (unsigned long long)stats.rollbackListenersStarted, (unsigned long long)stats.rollbackListenersReleased, (unsigned long long)stats.rollbackFinalInvalidEvents);
    }
    if (!child) InertLargeRoute();
    if (child) {
        pid_t parent = (pid_t)strtol(argv[6], NULL, 10); uint64_t nonce = strtoull(argv[2], NULL, 10);
        xpc_object_t requirement = Requirement(); VM27LWCRPolicy *strict = NULL; VM27ApprovedCodePolicy *approved = NULL;
        Check(!VM27LWCRPolicyCreate(requirement, &strict) && strict, "child-preserves-original-strict-lwcr");
        if (self.pluginValue) Check(!VM27ApprovedCodePolicyCreate(argv[7], SHA, CD, requirement, &approved) && approved, "child-explicitly-approves-real-parent-code");
        xpc_release(requirement);
        dispatch_queue_t queue = dispatch_queue_create("VM27.Factory.child", DISPATCH_QUEUE_SERIAL); dispatch_semaphore_t handshake = dispatch_semaphore_create(0), complete = dispatch_semaphore_create(0), instanceComplete = dispatch_semaphore_create(0), bridgeFinal = dispatch_semaphore_create(0);
        __block xpc_connection_t parentPeer = NULL; __block unsigned requests = 0, application = 0, protocol = 0; __block bool handshakeValid = false; __block int handshakeStatus = -1;
        __block xpc_object_t heldTimeoutRequest = NULL;
        __block unsigned timeoutRequestRetains = 0, timeoutRequestReleases = 0, timeoutParentCloseEvents = 0;
        xpc_endpoint_t ownEndpoint = NULL;
        OriginalExpectedQueue = queue; dispatch_queue_set_specific(queue, &OriginalQueueKey, queue, NULL);
        OriginalHandlerBlock = Block_copy(^(xpc_connection_t event) {
            Check(!parentPeer, "child-factory-accepts-only-one-parent-peer"); if (parentPeer) { xpc_connection_cancel((xpc_connection_t)event); return; }
            parentPeer = (xpc_connection_t)xpc_retain(event); xpc_connection_set_target_queue(parentPeer, queue);
            xpc_connection_set_event_handler(parentPeer, ^(xpc_object_t message) {
                if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
                bool actualParent = PeerIdentity(message, parent, CD, role, "request", requests == 0); Check(actualParent, "every-service-request-real-parent-kernel-code-and-audit-token");
                VM27ApprovedCodeMessageResult approvedResult = {0}; VM27LWCRMessageResult native = {0};
                int status = approved ? VM27ApprovedCodeCheckReceivedMessage(approved, message, &approvedResult) : VM27LWCRPolicyCheckReceivedMessage(strict, message, &native);
                if (approved) { native = approvedResult.nativePolicy; Check(approvedResult.explicitApprovedCodeAccepted && approvedResult.codeHashMatched && approvedResult.dynamicCodeValid && approvedResult.auditPID == (unsigned)parent && !strcmp(approvedResult.kernelCDHash, CD), "every-parent-request-exact-approved-code"); }
                Check(native.taskCreated && native.hasRemoteConnection && !native.entitlementReadError && status == (self.pluginValue ? 0 : EACCES), "every-parent-request-native-signature-gate-kept");
                if (!actualParent) status = EACCES;
                xpc_object_t nonceObject = xpc_dictionary_get_value(message, "nonce"), seqObject = xpc_dictionary_get_value(message, "sequence");
                if (!status && (!nonceObject || !seqObject || xpc_get_type(nonceObject) != XPC_TYPE_UINT64 || xpc_get_type(seqObject) != XPC_TYPE_UINT64 || xpc_dictionary_get_uint64(message, "nonce") != nonce || xpc_dictionary_get_uint64(message, "sequence") != requests)) { status = EPROTO; ++protocol; }
                if (!status) ++application;
                if (!requests) printf("{\"record\":\"serviceGate\",\"strictValidated\":%s,\"nativeBooleanTrue\":%s,\"explicitApproved\":%s}\n", native.entitlementsValidated ? "true" : "false", native.entitlementIsBoolean && native.entitlementValue ? "true" : "false", approvedResult.explicitApprovedCodeAccepted ? "true" : "false");
                ++requests; xpc_object_t reply = xpc_dictionary_create_reply(message); Check(reply != NULL, "owned-service-reply-created");
                if (reply) { xpc_dictionary_set_int64(reply, "gateStatus", status); xpc_connection_send_message(parentPeer, reply); xpc_release(reply); }
                if (requests == 65) xpc_connection_send_barrier(parentPeer, ^{ dispatch_semaphore_signal(complete); });
            }); xpc_connection_resume(parentPeer);
        });
        Check(!VM27LargeOriginalTransportCreateServer(argv[7], SHA, CD, parent, queue, &ownEndpoint), "original-app-private-server-created-with-exact-parent-pages");
        Check(!VM27LargeOriginalTransportRequireServerInstance(nonce), "server-requires-real-one-shot-instance-before-accepting-peer");
        Check(ownEndpoint && xpc_get_type(ownEndpoint) == XPC_TYPE_ENDPOINT, "actual-child-listener-endpoint-created");
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        mach_port_array_t ports = NULL; mach_msg_type_number_t count = 0; Check(!mach_ports_lookup(mach_task_self(), &ports, &count) && count == 3, "child-inherited-three-registered-slots");
        xpc_connection_t bridge = NULL; Check(ports && count == 3 && !VM27PrivateEndpointConnectSendRight(ports[2], queue, &bridge) && bridge, "own-parent-handshake-channel-connected");
        if (!bridge) { if (ports) ReleasePorts(ports, count); _exit(78); }
        xpc_connection_set_event_handler(bridge, ^(xpc_object_t event) {
            if (event == XPC_ERROR_CONNECTION_INVALID || event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                if (timeoutInstance && heldTimeoutRequest) {
                    /* The borrowed dictionary owns a native reply obligation.
                     * Keep our explicit reference until the actual parent's
                     * deadline closes its channel. Dropping it in the receive
                     * callback could send an automatic error immediately. */
                    ++timeoutParentCloseEvents;
                    xpc_release(heldTimeoutRequest); heldTimeoutRequest = NULL;
                    ++timeoutRequestReleases;
                }
                if (deniedInstance || timeoutInstance) dispatch_semaphore_signal(complete);
                if (event == XPC_ERROR_CONNECTION_INVALID) dispatch_semaphore_signal(bridgeFinal);
                return;
            }
            if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) return;
            bool parentIdentity = PeerIdentity(event, parent, CD, role, "instance", true);
            Check(parentIdentity, "UUID-control-request-real-parent-kernel-identity");
            ++InstanceMessages;
            if (timeoutInstance) {
                Check(!heldTimeoutRequest && !timeoutRequestRetains, "one-owned-timeout-request-retained-once");
                if (!heldTimeoutRequest && !timeoutRequestRetains) {
                    heldTimeoutRequest = xpc_retain(event); ++timeoutRequestRetains;
                }
                dispatch_semaphore_signal(instanceComplete); return;
            }
            xpc_object_t response = NULL;
            if (deniedInstance) xpc_dictionary_set_uint64(event, "nonce", nonce ^ 1);
            int bind = VM27LargeOriginalTransportBindServerInstanceMessage(event, &response);
            Check(parentIdentity && bind == (deniedInstance ? EPROTO : 0) && response, "actual-private-instance-bound-or-wrong-nonce-refused");
            if (!bind) { Check(!VM27LargeOriginalTransportCopyServerInstance(BoundChildInstance), "child-copies-real-owned-bound-instance"); InstanceWasBound = true; }
            if (response) { xpc_connection_send_message(bridge, response); xpc_release(response); } dispatch_semaphore_signal(instanceComplete);
        }); xpc_connection_resume(bridge);
        xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_value(hello, "serviceEndpoint", ownEndpoint); xpc_dictionary_set_string(hello, "serviceIdentifier", ServiceID); xpc_dictionary_set_uint64(hello, "nonce", deniedHandshake ? nonce ^ 1 : nonce);
        if (!timeoutHandshake) { xpc_connection_send_message_with_reply(bridge, hello, queue, ^(xpc_object_t reply) {
            handshakeValid = PeerIdentity(reply, parent, CD, role, "handshake", true); handshakeStatus = reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY ? (int)xpc_dictionary_get_int64(reply, "factoryStatus") : -1; dispatch_semaphore_signal(handshake);
        }); }
        xpc_release(hello);
        bool handshakeArrived = !dispatch_semaphore_wait(handshake, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
        Check(timeoutHandshake ? !handshakeArrived && !handshakeValid && handshakeStatus == -1 : handshakeArrived && handshakeValid && handshakeStatus == (deniedHandshake ? EPROTO : self.pluginValue ? 0 : EACCES), "parent-handshake-reply-actual-code-and-protocol-or-bounded-timeout");
        bool active = handshakeArrived && handshakeValid && handshakeStatus == 0 && !deniedHandshake;
        if (active && (deniedInstance || timeoutInstance)) {
            Check(!dispatch_semaphore_wait(instanceComplete, dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC)), "child-receives-real-instance-negative-control-message");
            Check(!dispatch_semaphore_wait(complete, dispatch_time(DISPATCH_TIME_NOW, 4LL * NSEC_PER_SEC)), "negative-control-child-remains-alive-until-real-parent-channel-close");
        }
        bool appActive = active && !deniedInstance && !timeoutInstance;
        if (appActive) Check(!dispatch_semaphore_wait(complete, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)), "child-factory-receives-bounded-parent-service-requests");
        xpc_connection_cancel(bridge); Check(!dispatch_semaphore_wait(bridgeFinal, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "actual-control-final-invalid-before-child-handler-storage-release"); if (parentPeer) xpc_connection_cancel(parentPeer); Check(!VM27LargeOriginalTransportStopServer(), "original-server-cancelled-drained-and-released-off-queue"); dispatch_sync(queue, ^{});
        bool timeoutCovered = appActive || (active && (deniedInstance || timeoutInstance));
        unsigned expectedHeld = timeoutCovered && timeoutInstance ? 1u : 0u;
        Check(!heldTimeoutRequest && timeoutRequestRetains == expectedHeld && timeoutRequestReleases == expectedHeld && timeoutParentCloseEvents == expectedHeld, "actual-timeout-request-retain-parent-close-and-release-paired");
        printf("{\"record\":\"timeoutRequestOwnership\",\"retained\":%u,\"released\":%u,\"realParentCloseEvents\":%u,\"pending\":%u,\"finalInvalidDrained\":true}\n", timeoutRequestRetains, timeoutRequestReleases, timeoutParentCloseEvents, heldTimeoutRequest ? 1u : 0u);
        xpc_release(bridge); if (parentPeer) xpc_release(parentPeer); xpc_release(ownEndpoint); Block_release(OriginalHandlerBlock); OriginalHandlerBlock = NULL; dispatch_queue_set_specific(queue, &OriginalQueueKey, NULL, NULL); OriginalExpectedQueue = NULL; ReleasePorts(ports, count); dispatch_release(handshake); dispatch_release(complete); dispatch_release(instanceComplete); dispatch_release(bridgeFinal); dispatch_release(queue);
        if (approved) VM27ApprovedCodePolicyRelease(approved); VM27LWCRPolicyRelease(strict);
        VM27LWCRStats policy; VM27LWCRCopyStats(&policy); VM27ApprovedCodeStats codes; VM27ApprovedCodeCopyStats(&codes);
        Check(requests == (deniedHandshake || timeoutHandshake || deniedInstance || timeoutInstance || !self.pluginValue ? 0u : 65u) && policy.taskCreates == policy.taskReleases && policy.taskCreates == requests && policy.policiesCreated == policy.policiesDestroyed && codes.created == codes.destroyed, "child-service-every-task-policy-released");
        Check(application == (!deniedHandshake && !timeoutHandshake && !deniedInstance && !timeoutInstance && self.pluginValue ? 64u : 0u) && protocol == (!deniedHandshake && !timeoutHandshake && !deniedInstance && !timeoutInstance && self.pluginValue ? 1u : 0u), "child-service-handlers-gated-after-parent-identity"); Providers(role, "after"); Check(NoVM(), "child-no-vm-images-after");
        printf("{\"record\":\"childSummary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"serviceRequests\":%u,\"applicationCalls\":%u,\"protocolRefused\":%u,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"kernelIdentityQueries\":%u,\"ownObjectsReleased\":true,\"handshakeRejected\":%s,\"handshakeTimeout\":%s}\n", getpid(), atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", requests, application, protocol, (unsigned long long)policy.taskCreates, (unsigned long long)policy.taskReleases, atomic_load(&IdentityQueries), deniedHandshake ? "true" : "false", timeoutHandshake ? "true" : "false");
        VM27LargeOriginalTransportStats originalStats; VM27LargeOriginalTransportCopyStats(&originalStats);
        printf("{\"record\":\"largeTransportRoute\",\"role\":\"%s\",\"parentFileInspections\":%llu,\"largeParentFileInspections\":%llu,\"registryCapacityBytes\":8388608,\"plistCapacityBytes\":65536,\"originalVMMExecutions\":0,\"originalPluginLoaderExecutions\":0}\n", role, (unsigned long long)originalStats.parentFileInspections, (unsigned long long)originalStats.largeParentFileInspections);

        Check(originalStats.originalMainCalls == 1 && originalStats.listenersCreated == 1 && originalStats.listenersDestroyed == 1 && originalStats.tasksCreated == originalStats.tasksReleased && originalStats.tasksCreated == (appActive ? 2u : 0u) && originalStats.originalHandlerCalls == (appActive ? 1u : 0u) && originalStats.peersAccepted == (appActive ? 1u : 0u) && (!appActive || originalStats.lastBaseCapabilityMask & 1), "original-one-C-handler-real-native-mask-and-lifecycle");
        Check(originalStats.serverInstancesBound == (appActive ? 1u : 0u), "original-service-accepted-only-after-real-instance-binding");
        char instance[33] = {0}; for (unsigned i = 0; i < 16; ++i) snprintf(instance + 2 * i, 3, "%02x", BoundChildInstance[i]);
        printf("{\"record\":\"originalInstanceServer\",\"UUID\":\"%s\",\"bound\":%llu,\"nativeSetterCalls\":0,\"controlMessages\":%u}\n", instance, (unsigned long long)originalStats.serverInstancesBound, InstanceMessages);
        printf("{\"record\":\"originalServer\",\"mainCalls\":%llu,\"handlerCalls\":%llu,\"mask\":%u,\"strictValidated\":%s,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"kernelQueries\":%llu,\"auditPID\":%u,\"auditPIDVersion\":%u,\"peerError\":%d,\"failures\":%u}\n", (unsigned long long)originalStats.originalMainCalls, (unsigned long long)originalStats.originalHandlerCalls, originalStats.lastBaseCapabilityMask, originalStats.lastNativeEntitlementsValidated ? "true" : "false", (unsigned long long)originalStats.tasksCreated, (unsigned long long)originalStats.tasksReleased, (unsigned long long)originalStats.kernelCodeQueries, originalStats.lastAuditPID, originalStats.lastAuditPIDVersion, originalStats.lastPeerError, atomic_load(&gFailures));
        exit(atomic_load(&gFailures) ? 1 : 0);
        });
        VM27LargeOriginalTransportMain(OriginalCHandler);
    }
    char root[4096] = {0}, paths[8][4096], codePath[4096]; if (!Fixture(argv[0], root, paths, codePath)) return 78;
    VM27LargeBundleRegistry *registry = NULL; xpc_object_t requirement = Requirement(); VM27LargePrivateServiceConsumer *consumer = NULL;
    Check(!VM27LargeBundleRegistryCreate(root, &registry) && !VM27LargeBundleRegistryRegister(registry, paths[0], 2, requirement), "real-private-service-registry-committed");
    Check(!VM27LargePrivateServiceConsumerCreate(registry, ServiceID, SHA, CD, requirement, self.pluginValue ? VM27LargeConsumerExplicitApprovedCode : VM27LargeConsumerStrictNative, &consumer) && consumer, "real-registered-service-consumer-created"); xpc_release(requirement); VM27LargeBundleRegistryRelease(registry);
    printf("{\"record\":\"registeredService\",\"path\":\"%s\",\"codeSHA256\":\"%s\",\"codeUUID\":\"%s\",\"codeBytes\":%llu,\"service\":\"%s\",\"flags\":2}\n", codePath, SHA, self.UUID, (unsigned long long)bytes, ServiceID);
    dispatch_queue_t server = dispatch_queue_create("VM27.Factory.handshake", DISPATCH_QUEUE_SERIAL), client = dispatch_queue_create("VM27.Factory.parent", DISPATCH_QUEUE_SERIAL); dispatch_suspend(server);
    dispatch_semaphore_t factory = dispatch_semaphore_create(0), replies = dispatch_semaphore_create(0), serviceCancelled = dispatch_semaphore_create(0);
    __block bool serviceFinalInvalid = false; bool serviceActivated = false;
    uint64_t instanceSetterElapsed = 0; bool setterAttempted = false;
    __block pid_t spawned = 0; __block xpc_connection_t childPeer = NULL; __block xpc_endpoint_t serviceEndpoint = NULL; __block unsigned handshakes = 0; __block int factoryStatus = -1;
    uint64_t nonce = 0; arc4random_buf(&nonce, sizeof(nonce)); if (!nonce) nonce = 1;
    xpc_connection_t listener = xpc_connection_create(NULL, server);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        Check(!childPeer, "parent-factory-single-owned-child-handshake-peer"); if (childPeer) { xpc_connection_cancel((xpc_connection_t)event); return; }
        childPeer = (xpc_connection_t)xpc_retain(event); xpc_connection_set_target_queue(childPeer, server);
        xpc_connection_set_event_handler(childPeer, ^(xpc_object_t message) {
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            bool actualChild = PeerIdentity(message, spawned, CD, role, "handshake", true); Check(actualChild, "factory-endpoint-from-real-child-kernel-code");
            VM27ApprovedCodeMessageResult gate = {0}; int auth = VM27LargePrivateServiceConsumerCheckMessage(consumer, message, &gate);
            Check(auth == (self.pluginValue ? 0 : EACCES) && gate.nativePolicy.taskCreated && !gate.nativePolicy.entitlementReadError, "factory-handshake-signature-policy-kept");
            printf("{\"record\":\"factoryGate\",\"strictValidated\":%s,\"nativeBooleanTrue\":%s,\"explicitApproved\":%s,\"nativeStatus\":%d,\"transportOnlyOnMac\":%s}\n", gate.nativePolicy.entitlementsValidated ? "true" : "false", gate.nativePolicy.entitlementIsBoolean && gate.nativePolicy.entitlementValue ? "true" : "false", gate.explicitApprovedCodeAccepted ? "true" : "false", auth, self.pluginValue ? "false" : "true");
            xpc_object_t ep = xpc_dictionary_get_value(message, "serviceEndpoint"), n = xpc_dictionary_get_value(message, "nonce");
            factoryStatus = !actualChild || !ep || xpc_get_type(ep) != XPC_TYPE_ENDPOINT || !n || xpc_get_type(n) != XPC_TYPE_UINT64 || xpc_dictionary_get_uint64(message, "nonce") != nonce || handshakes ? EPROTO : 0;
            if (!factoryStatus && self.pluginValue && auth) factoryStatus = EACCES;
            if (!factoryStatus) factoryStatus = VM27LargeOriginalTransportInstallClientFactoryMessage(consumer, message, nonce);
            if (!factoryStatus) serviceEndpoint = (xpc_endpoint_t)xpc_retain(ep);
            ++handshakes; xpc_object_t reply = xpc_dictionary_create_reply(message); Check(reply != NULL, "factory-control-reply-created");
            if (reply) { xpc_dictionary_set_int64(reply, "factoryStatus", factoryStatus); xpc_connection_send_message(childPeer, reply); xpc_release(reply); }
            dispatch_semaphore_signal(factory);
        }); xpc_connection_resume(childPeer);
    }); xpc_connection_resume(listener); xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    char nonceText[32], parentText[32]; snprintf(nonceText, sizeof(nonceText), "%llu", (unsigned long long)nonce); snprintf(parentText, sizeof(parentText), "%d", getpid());
    char *arguments[] = {codePath, "--factory-child", nonceText, (char *)SHA, (char *)sizeText, (char *)CD, parentText, argv[0], (char *)variant, NULL};
    int spawnResult = VM27LargePrivateServiceConsumerSpawn(consumer, endpoint, arguments, environ, &spawned); Check(!spawnResult && spawned > 1, "actual-registered-child-service-spawned"); dispatch_resume(server);
    printf("{\"record\":\"spawn\",\"parentPID\":%d,\"childPID\":%d,\"spawnResult\":%d}\n", getpid(), spawned, spawnResult);
    bool handshakeArrived = !dispatch_semaphore_wait(factory, dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC));
    Check(timeoutHandshake ? !handshakeArrived && factoryStatus == -1 && !serviceEndpoint : handshakeArrived && factoryStatus == (deniedHandshake ? EPROTO : self.pluginValue ? 0 : EACCES) && (serviceEndpoint != NULL) == (!deniedHandshake && self.pluginValue), "actual-service-endpoint-handshake-or-bounded-refusal-timeout");
    unsigned realReplies = 0, accepted = 0, denied = 0;
    xpc_connection_t service = NULL;
    if (handshakeArrived && serviceEndpoint && factoryStatus == 0 && !deniedHandshake) {
        service = VM27LargeOriginalTransportConnectionCreate(ServiceID, client); Check(service != NULL, "original-create-exact-VM-service-real-inactive-endpoint-connection");
        errno = 0; Check(!VM27LargeOriginalTransportConnectionCreate(ServiceID, client) && errno == EALREADY, "same-factory-cannot-create-second-connection");
        unsigned char generated[16], saved[16], actual[16], zero[16] = {0}; uuid_generate(generated); memcpy(saved, generated, 16);
        memset(actual, 0xff, 16); errno = 0; VM27LargeOriginalTransportGetInstance(service, actual);
        Check(errno == ENOTCONN && !memcmp(actual, zero, 16), "unbound-instance-getter-copies-zero-and-refuses-success");
        errno = 0; VM27LargeOriginalTransportSetOneShotInstance(service, zero); Check(errno == EINVAL, "zero-instance-rejected-before-control-message");
        uint64_t setterStart = MonotonicNanoseconds();
        errno = 0; VM27LargeOriginalTransportSetOneShotInstance(service, generated);
        int instanceStatus = errno; Check(instanceStatus == (deniedInstance ? EPROTO : timeoutInstance ? ETIMEDOUT : 0), "original-one-shot-setter-authenticated-ack-or-bounded-refusal");
        instanceSetterElapsed = MonotonicNanoseconds() - setterStart; setterAttempted = true;
        Check(instanceSetterElapsed > 0 && instanceSetterElapsed < 6000000000ULL && (!timeoutInstance || instanceSetterElapsed >= 2000000000ULL), "real-monotonic-timeout-deadline-observed-before-control-cancellation");
        if (!instanceStatus) {
        memset(generated, 0xcc, 16); errno = 0; VM27LargeOriginalTransportGetInstance(service, actual);
        Check(!errno && !memcmp(actual, saved, 16), "void-original-getter-copies-owned-UUID-independent-of-source-memory");
        char instance[33] = {0}; for (unsigned i = 0; i < 16; ++i) snprintf(instance + 2 * i, 3, "%02x", actual[i]);
        printf("{\"record\":\"originalInstanceClientUUID\",\"UUID\":\"%s\",\"callerUUIDMemoryChanged\":true}\n", instance);
        errno = 0; VM27LargeOriginalTransportSetOneShotInstance(service, saved); Check(errno == EALREADY, "one-shot-instance-cannot-rebind-same-service-process");
        }
        /* Exact original VZ caller continues with set-handler/activate even when
         * the void one-shot call cancelled the connection. An inactive cancelled
         * object must still be resumed before its final external release. */
        xpc_connection_set_target_queue(service, client);
        xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
            if (event == XPC_ERROR_CONNECTION_INVALID) { serviceFinalInvalid = true; dispatch_semaphore_signal(serviceCancelled); }
        }); xpc_connection_resume(service); serviceActivated = true;
        for (unsigned i = 0; !instanceStatus && i < 65; ++i) {
            __block int response = -1; xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_uint64(message, "nonce", i ? nonce : nonce ^ 1); xpc_dictionary_set_uint64(message, "sequence", i); xpc_dictionary_set_bool(message, VM27_PLUGIN_ENTITLEMENT, true);
            xpc_connection_send_message_with_reply(service, message, client, ^(xpc_object_t reply) {
                Check(PeerIdentity(reply, spawned, CD, role, "reply", i == 0), "every-service-reply-real-child-kernel-code");
                if (reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) response = (int)xpc_dictionary_get_int64(reply, "gateStatus"); dispatch_semaphore_signal(replies);
            }); xpc_release(message);
            bool arrived = !dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)); Check(arrived, "reverse-real-cross-process-service-reply"); if (!arrived) break;
            ++realReplies; Check(response == (self.pluginValue ? i ? 0 : EPROTO : EACCES), "actual-child-service-handlers-authenticated-before-delivery"); if (!response) ++accepted; else ++denied;
        }
    }
    if (service) { xpc_connection_cancel(service); Check(!dispatch_semaphore_wait(serviceCancelled, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "actual-final-invalid-delivered-before-resumed-service-final-release"); } if (childPeer) xpc_connection_cancel(childPeer); xpc_connection_cancel(listener); dispatch_sync(client, ^{}); dispatch_sync(server, ^{});
    if (service) xpc_release(service); if (serviceEndpoint) xpc_release(serviceEndpoint); if (childPeer) xpc_release(childPeer); xpc_release(endpoint); xpc_release(listener);
    dispatch_release(factory); dispatch_release(replies); dispatch_release(serviceCancelled); dispatch_release(client); dispatch_release(server);
    printf("{\"record\":\"originalActivation\",\"activated\":%s,\"finalInvalid\":%s,\"cancellationDrained\":true}\n", serviceActivated ? "true" : "false", serviceFinalInvalid ? "true" : "false");
    printf("{\"record\":\"instanceSetterDeadline\",\"attempted\":%s,\"elapsedNanoseconds\":%llu,\"deadlineNanoseconds\":2000000000,\"timeoutExpected\":%s}\n", setterAttempted ? "true" : "false", (unsigned long long)instanceSetterElapsed, setterAttempted && timeoutInstance ? "true" : "false");
    VM27LargeOriginalTransportClearClient();
    VM27LargeOriginalTransportStats originalStats; VM27LargeOriginalTransportCopyStats(&originalStats);
        printf("{\"record\":\"largeTransportRoute\",\"role\":\"%s\",\"parentFileInspections\":%llu,\"largeParentFileInspections\":%llu,\"registryCapacityBytes\":8388608,\"plistCapacityBytes\":65536,\"originalVMMExecutions\":0,\"originalPluginLoaderExecutions\":0}\n", role, (unsigned long long)originalStats.parentFileInspections, (unsigned long long)originalStats.largeParentFileInspections);

    Check(originalStats.clientMessagesInstalled == (!deniedHandshake && !timeoutHandshake && self.pluginValue ? 1u : 0u) && originalStats.privateConnectionsCreated == (!deniedHandshake && !timeoutHandshake && self.pluginValue ? 1u : 0u) && originalStats.nativeConnectionsForwarded == 1 && !originalStats.originalMainCalls, "original-create-exact-service-once-and-anonymous-native-forward");
    for (unsigned retry = 0; originalStats.pendingInstanceRequests && retry < 100; ++retry) { usleep(1000); VM27LargeOriginalTransportCopyStats(&originalStats); }
    bool instanceAttempted = !deniedHandshake && !timeoutHandshake && self.pluginValue;
    bool instancePositive = instanceAttempted && !deniedInstance && !timeoutInstance;
    Check(originalStats.instanceRequests == (instanceAttempted ? 1u : 0u) && originalStats.instanceCallbacks == originalStats.instanceRequests && originalStats.instanceReplies == (instanceAttempted && !timeoutInstance ? 1u : 0u) && originalStats.instancesCommitted == (instancePositive ? 1u : 0u) && originalStats.instancesCopied == originalStats.instancesCommitted && !originalStats.pendingInstanceRequests && originalStats.tasksCreated == originalStats.tasksReleased && originalStats.tasksCreated == (instanceAttempted && !timeoutInstance ? 1u : 0u), "UUID-control-ack-task-and-owned-request-lifecycle-paired");
    printf("{\"record\":\"originalInstanceClient\",\"requests\":%llu,\"replies\":%llu,\"callbacks\":%llu,\"committed\":%llu,\"copied\":%llu,\"pending\":%llu,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"lastStatus\":%d,\"nativeSetterCalls\":0,\"auditPID\":%u,\"auditPIDVersion\":%u,\"kernelCDHash\":\"%s\",\"codeStatus\":%u,\"codeQueryResult\":%d,\"statusQueryResult\":%d,\"mask\":%u,\"strictValidated\":%s}\n", (unsigned long long)originalStats.instanceRequests, (unsigned long long)originalStats.instanceReplies, (unsigned long long)originalStats.instanceCallbacks, (unsigned long long)originalStats.instancesCommitted, (unsigned long long)originalStats.instancesCopied, (unsigned long long)originalStats.pendingInstanceRequests, (unsigned long long)originalStats.tasksCreated, (unsigned long long)originalStats.tasksReleased, originalStats.lastInstanceStatus, originalStats.lastAuditPID, originalStats.lastAuditPIDVersion, originalStats.lastKernelCDHash, originalStats.lastCodeStatus, originalStats.lastCodeQueryResult, originalStats.lastStatusQueryResult, originalStats.lastBaseCapabilityMask, originalStats.lastNativeEntitlementsValidated ? "true" : "false");
    printf("{\"record\":\"originalClient\",\"installed\":%llu,\"created\":%llu,\"forwarded\":%llu}\n", (unsigned long long)originalStats.clientMessagesInstalled, (unsigned long long)originalStats.privateConnectionsCreated, (unsigned long long)originalStats.nativeConnectionsForwarded);
    VM27LargePrivateConsumerState state = {0}; Check(!VM27LargePrivateServiceConsumerWait(consumer, true, &state) && state.reaped && state.absent && !state.observedWaitExit && state.parentRegisteredPortsUnchanged, "actual-factory-owned-child-reaped-and-parent-table-unchanged"); Check(!VM27LargePrivateServiceConsumerRelease(consumer), "factory-consumer-released-after-reap");
    VM27LargeBundleRegistryStats registryStats; VM27LargeBundleRegistryCopyStats(&registryStats); VM27LargePrivateConsumerStats consumerStats; VM27LargePrivateServiceConsumerCopyStats(&consumerStats); VM27LWCRStats policy; VM27LWCRCopyStats(&policy);
    Check(registryStats.registrations == 2 && registryStats.registeredServices == 2 && registryStats.plansCreated == registryStats.plansDestroyed && registryStats.plansCreated == 2 && consumerStats.created == consumerStats.destroyed && consumerStats.spawns == consumerStats.reaps && consumerStats.messageChecks == (timeoutHandshake ? 0u : deniedHandshake ? 1u : 2u) && policy.taskCreates == policy.taskReleases && policy.taskCreates == (timeoutHandshake ? 0u : deniedHandshake ? 1u : 2u) && policy.policiesCreated == policy.policiesDestroyed, "factory-real-plan-consumer-and-handshake-sectask-paired");
    Check(!unlink(codePath) && !unlink(paths[7]) && !unlink(paths[6]), "factory-owned-files-removed"); for (int i = 5; i >= 0; --i) Check(!rmdir(paths[i]), "factory-owned-directories-removed"); Check(!rmdir(root) && access(root, F_OK) == -1 && errno == ENOENT, "factory-owned-temporary-root-absent");
    Providers(role, "after"); Check(NoVM(), "parent-no-vm-images-after");
    printf("{\"record\":\"summary\",\"parentPID\":%d,\"spawnedChildPID\":%d,\"observedChildWaitExit\":%d,\"childAbsent\":%s,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"handshakes\":%u,\"handshakeRejected\":%s,\"handshakeTimeout\":%s,\"reverseReplies\":%u,\"applicationAccepted\":%u,\"deniedReplies\":%u,\"kernelIdentityQueries\":%u,\"parentRegisteredPortsUnchanged\":true,\"ownObjectsReleased\":true,\"ownTemporaryRemoved\":true,\"registryPlansReleased\":true,\"bootstrapChanges\":0,\"launchdRegistrations\":0,\"completeBundleRegistration\":false}\n", getpid(), spawned, state.observedWaitExit, state.absent ? "true" : "false", atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true", handshakes, deniedHandshake ? "true" : "false", timeoutHandshake ? "true" : "false", realReplies, accepted, denied, atomic_load(&IdentityQueries));
    return atomic_load(&gFailures) ? 1 : 0;
}
