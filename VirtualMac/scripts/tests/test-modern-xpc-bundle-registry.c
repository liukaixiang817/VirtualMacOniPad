#include "modern_xpc_bundle_registry.h"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "modern_xpc_registry_pins.h"

static _Atomic unsigned gChecks, gFailures;
static const char *ServiceIdentifier = "com.virtualmac.diagnostics.owned.service";
static void Check(bool value, const char *label) {
    atomic_fetch_add(&gChecks, 1);
    if (!value) { atomic_fetch_add(&gFailures, 1); printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", label); }
}
static bool Write(const char *path, const void *bytes, size_t length, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return false;
    bool ok = fchmod(fd, mode) == 0; size_t at = 0;
    while (ok && at < length) {
        ssize_t count = write(fd, (const char *)bytes + at, length - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = false; break; } at += (size_t)count;
    }
    if (fsync(fd)) ok = false;
    if (close(fd)) ok = false;
    return ok;
}
static unsigned char *Read(const char *path, size_t *length) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat state;
    if (fd < 0) return NULL;
    if (fstat(fd, &state) || state.st_size <= 0 || state.st_size > 2 * 1024 * 1024) { close(fd); return NULL; }
    unsigned char *data = malloc((size_t)state.st_size);
    if (!data) { close(fd); return NULL; }
    size_t at = 0;
    while (at < (size_t)state.st_size) {
        ssize_t count = read(fd, data + at, (size_t)state.st_size - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { free(data); close(fd); return NULL; } at += (size_t)count;
    }
    close(fd); *length = at; return data;
}
static void Identity(const char *phase, const char *name, void *function,
                     const char *expectedSHA, uint64_t expectedBytes,
                     const char *expectedUUID) {
    Dl_info info = {0}; void *raw = ptrauth_strip(function, ptrauth_key_function_pointer);
    Check(dladdr(raw, &info) && info.dli_fbase && info.dli_fname, "actual-provider-dladdr");
    const struct mach_header_64 *header = info.dli_fbase; const unsigned char *uuid = NULL;
    Check(header && header->magic == MH_MAGIC_64 && header->sizeofcmds <= 16384, "actual-provider-header");
    if (header) {
        const struct load_command *command = (const void *)(header + 1);
        for (unsigned i = 0; i < header->ncmds; ++i) {
            if (command->cmd == LC_UUID && command->cmdsize == 24) uuid = (const unsigned char *)command + 8;
            command = (const void *)((const char *)command + command->cmdsize);
        }
    }
    char uuidHex[33] = {0}; if (uuid) for (unsigned i = 0; i < 16; ++i) snprintf(uuidHex + i * 2, 3, "%02x", uuid[i]);
    Check(uuid && !strcmp(uuidHex, expectedUUID), "actual-provider-uuid");
    size_t bytes = 0; unsigned char *data = info.dli_fname ? Read(info.dli_fname, &bytes) : NULL;
    unsigned char digest[32]; char hex[65] = {0}; bool hadData = data != NULL;
    if (data) { CC_SHA256(data, (CC_LONG)bytes, digest); for (unsigned i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", digest[i]); free(data); }
    Check(hadData && bytes == expectedBytes && !strcmp(hex, expectedSHA), "actual-provider-file-pin");
    printf("{\"record\":\"provider\",\"phase\":\"%s\",\"symbol\":\"%s\",\"path\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\",\"SHA256\":\"%s\"}\n",
        phase, name, info.dli_fname ? info.dli_fname : "", uuidHex, (unsigned long long)((uintptr_t)raw - (uintptr_t)info.dli_fbase), hex);
}
static bool NoVMImages(void) {
    const char *names[] = {"/Virtualization.framework/", "/Hypervisor.framework/", "/ParavirtualizedGraphics.framework/", "/VirtualMachine.xpc/"};
    bool result = true;
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *name = _dyld_get_image_name(i); if (!name) { result = false; continue; }
        for (unsigned j = 0; j < sizeof(names) / sizeof(names[0]); ++j) if (strstr(name, names[j])) result = false;
    }
    return result;
}
static xpc_object_t Requirement(void) {
    xpc_object_t root = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t entitlements = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t query = xpc_array_create(NULL, 0), select = xpc_array_create(NULL, 0), match = xpc_array_create(NULL, 0);
    xpc_object_t one = xpc_int64_create(1), five = xpc_int64_create(5);
    xpc_object_t key = xpc_string_create(VM27_PLUGIN_ENTITLEMENT), truth = xpc_bool_create(true);
    xpc_array_append_value(select, one); xpc_array_append_value(select, key);
    xpc_array_append_value(match, five); xpc_array_append_value(match, truth);
    xpc_array_append_value(query, select); xpc_array_append_value(query, match);
    xpc_dictionary_set_value(entitlements, "$query", query); xpc_dictionary_set_value(root, "entitlements", entitlements);
    xpc_release(entitlements); xpc_release(query); xpc_release(select); xpc_release(match);
    xpc_release(one); xpc_release(five); xpc_release(key); xpc_release(truth); return root;
}
static void *Worker(void *argument) {
    VM27BundleRegistry *registry = argument;
    for (unsigned i = 0; i < 64; ++i) {
        VM27PrivateServicePlan *plan = NULL; VM27PrivateServiceInfo info = {0};
        Check(VM27BundleRegistryCopyServicePlan(registry, ServiceIdentifier, &plan) == 0 && plan, "concurrent-owned-plan-copy");
        if (!plan) continue;
        Check(VM27PrivateServicePlanCopyInfo(plan, &info) == 0 && !strcmp(info.serviceIdentifier, ServiceIdentifier), "concurrent-consumer-reads-real-record");
        Check(VM27PrivateServicePlanVerify(plan) == 0, "concurrent-real-file-pins");
        VM27PrivateServicePlanRelease(plan);
    }
    return NULL;
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit cpu = {5, 5}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 78; alarm(15);
    if (argc != 3 || strlen(argv[1]) != 64) return 64;
    char *end = NULL; uint64_t expectedBytes = strtoull(argv[2], &end, 10);
    if (!end || *end || end == argv[2]) return 64;
    size_t executableBytes = 0; unsigned char *selfBytes = Read(argv[0], &executableBytes);
    Check(selfBytes && executableBytes == expectedBytes, "self-executable-read");
    if (!selfBytes) return 78;
    unsigned char digest[32]; CC_SHA256(selfBytes, (CC_LONG)executableBytes, digest); char selfSHA[65];
    for (unsigned i = 0; i < 32; ++i) snprintf(selfSHA + i * 2, 3, "%02x", digest[i]);
    Check(!strcmp(selfSHA, argv[1]), "exact-self-file-pin"); if (atomic_load(&gFailures)) { free(selfBytes); return 78; }
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"VMCalls\":0,\"GPUCalls\":0,\"launchdRegistrations\":0,\"childLaunches\":0}\n", getpid(), getuid());
    Check(NoVMImages(), "no-vm-framework-images-before");
    Identity("before", "VM27BundleRegistryRegister", (void *)VM27BundleRegistryRegister, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
    Identity("before", "VM27PrivateServicePlanCheckReceivedMessage", (void *)VM27PrivateServicePlanCheckReceivedMessage, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
    Identity("before", "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
    char temporary[] = "/tmp/VM27-OwnedBundle-XXXXXX";
    Check(mkdtemp(temporary) != NULL, "owned-temporary-root-created");
    char root[4096]; Check(realpath(temporary, root) != NULL, "owned-canonical-root");
    char paths[8][4096];
    const char *suffixes[] = {"Owned.bundle", "Owned.bundle/Contents", "Owned.bundle/Contents/XPCServices",
        "Owned.bundle/Contents/XPCServices/One.xpc", "Owned.bundle/Contents/XPCServices/One.xpc/Contents",
        "Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS",
        "Owned.bundle/Contents/Info.plist", "Owned.bundle/Contents/XPCServices/One.xpc/Contents/Info.plist"};
    for (unsigned i = 0; i < 8; ++i) {
        int count = snprintf(paths[i], sizeof(paths[i]), "%s/%s", root, suffixes[i]);
        Check(count > 0 && (size_t)count < sizeof(paths[i]), "owned-fixture-path-bounded");
        if (i < 6) Check(mkdir(paths[i], 0700) == 0, "owned-fixture-directory-created");
    }
    char codePath[4096]; int count = snprintf(codePath, sizeof(codePath), "%s/ServiceExec", paths[5]);
    Check(count > 0 && (size_t)count < sizeof(codePath), "owned-code-path-bounded");
    const char parentPlist[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.virtualmac.diagnostics.owned.bundle</string></dict></plist>";
    const char servicePlist[] = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.virtualmac.diagnostics.owned.service</string><key>CFBundleExecutable</key><string>ServiceExec</string><key>CFBundlePackageType</key><string>XPC!</string></dict></plist>";
    Check(Write(paths[6], parentPlist, sizeof(parentPlist) - 1, 0600), "real-parent-plist-written");
    Check(Write(paths[7], servicePlist, sizeof(servicePlist) - 1, 0600), "real-service-plist-written");
    Check(Write(codePath, selfBytes, executableBytes, 0700), "real-service-code-copied");
    VM27BundleRegistry *registry = NULL;
    Check(VM27BundleRegistryCreate(root, &registry) == 0 && registry, "private-registry-created");
    if (!registry) return 78;
    xpc_object_t requirement = Requirement();
    Check(VM27BundleRegistryRegister(registry, paths[0], 0, requirement) == ENOTSUP, "wrong-flags-rejected");
    Check(VM27BundleRegistryRegister(registry, "/System/Library/Owned.bundle", 2, requirement) == EACCES, "outside-root-rejected");
    char escape[4096]; snprintf(escape, sizeof(escape), "%s/../Owned.bundle", root);
    Check(VM27BundleRegistryRegister(registry, escape, 2, requirement) == EINVAL, "path-traversal-rejected");
    xpc_object_t extra = Requirement(); xpc_dictionary_set_bool(extra, "ignored-fact", true);
    Check(VM27BundleRegistryRegister(registry, paths[0], 2, extra) == ENOTSUP, "extra-constraint-not-ignored"); xpc_release(extra);
    /* Real code path replaced by a symlink before staging must not register. */
    Check(unlink(codePath) == 0 && symlink(argv[0], codePath) == 0, "owned-symlink-control-created");
    Check(VM27BundleRegistryRegister(registry, paths[0], 2, requirement) != 0, "symlink-code-rejected");
    Check(unlink(codePath) == 0 && Write(codePath, selfBytes, executableBytes, 0700), "owned-code-restored");
    Check(VM27BundleRegistryRegister(registry, paths[0], 2, requirement) == 0, "actual-private-service-record-committed");
    Check(VM27BundleRegistryRegister(registry, paths[0], 2, requirement) == EEXIST, "duplicate-registration-rejected");
    xpc_object_t inner = xpc_dictionary_get_value(requirement, "entitlements");
    xpc_dictionary_set_bool(inner, "post-commit-change", true); xpc_release(requirement);
    VM27PrivateServicePlan *plan = NULL, *missing = (VM27PrivateServicePlan *)(uintptr_t)1;
    Check(VM27BundleRegistryCopyServicePlan(registry, "absent.service", &missing) == ENOENT && !missing, "missing-service-no-fake-plan");
    Check(VM27BundleRegistryCopyServicePlan(registry, ServiceIdentifier, &plan) == 0 && plan, "registered-service-plan-consumed");
    if (!plan) return 78;
    VM27PrivateServiceInfo info = {0};
    Check(VM27PrivateServicePlanCopyInfo(plan, &info) == 0, "consumer-reads-immutable-info");
    Check(!strcmp(info.executablePath, codePath) && !strcmp(info.executableSHA256, selfSHA) &&
          info.executableBytes == executableBytes && info.flags == 2 && strlen(info.executableUUID) == 32, "consumer-sees-exact-real-code");
    printf("{\"record\":\"registeredService\",\"service\":\"%s\",\"codeSHA256\":\"%s\",\"codeUUID\":\"%s\",\"codeBytes\":%llu,\"flags\":2}\n", info.serviceIdentifier, info.executableSHA256, info.executableUUID, (unsigned long long)info.executableBytes);
    info.flags = 0; info.executableSHA256[0] = 'x';
    Check(VM27PrivateServicePlanCopyInfo(plan, &info) == 0 && info.flags == 2 && !strcmp(info.executableSHA256, selfSHA), "caller-info-mutation-not-shared");
    Check(Write(paths[7], "corrupt", 7, 0600), "owned-plist-corruption-created");
    Check(VM27PrivateServicePlanVerify(plan) == ESTALE, "modified-plist-pin-rejected");
    Check(Write(paths[7], servicePlist, sizeof(servicePlist) - 1, 0600), "owned-plist-restored");
    Check(VM27PrivateServicePlanVerify(plan) == 0, "restored-identical-owned-plist-valid");
    selfBytes[40] ^= 1;
    Check(Write(codePath, selfBytes, executableBytes, 0700), "owned-code-corruption-created");
    Check(VM27PrivateServicePlanVerify(plan) == ESTALE, "modified-code-pin-rejected");
    selfBytes[40] ^= 1;
    Check(Write(codePath, selfBytes, executableBytes, 0700), "owned-code-restored-again"); free(selfBytes);
    Check(VM27PrivateServicePlanVerify(plan) == 0, "restored-identical-owned-code-valid");
    pthread_t workers[4]; unsigned started = 0;
    for (unsigned i = 0; i < 4; ++i) { int status = pthread_create(&workers[i], NULL, Worker, registry); Check(status == 0, "registry-worker-created"); if (status) break; ++started; }
    for (unsigned i = 0; i < started; ++i) Check(pthread_join(workers[i], NULL) == 0, "registry-worker-joined");
    VM27BundleRegistryRelease(registry); registry = NULL;
    Check(VM27PrivateServicePlanVerify(plan) == 0, "plan-survives-registry-release");
    xpc_object_t spoof = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_bool(spoof, VM27_PLUGIN_ENTITLEMENT, true);
    VM27LWCRMessageResult detail = {0};
    Check(VM27PrivateServicePlanCheckReceivedMessage(plan, spoof, &detail) == EACCES && !detail.taskCreated, "unsigned-body-cannot-authorize-service"); xpc_release(spoof);
    dispatch_queue_t serverQueue = dispatch_queue_create("VM27.Registry.owned.server", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t clientQueue = dispatch_queue_create("VM27.Registry.owned.client", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t replies = dispatch_semaphore_create(0);
    __block xpc_connection_t peer = NULL; __block unsigned received = 0, applicationCalls = 0; __block int replyResult = -1;
    xpc_connection_t listener = xpc_connection_create(NULL, serverQueue);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        Check(peer == NULL, "single-owned-service-peer"); if (peer) return;
        peer = (xpc_connection_t)xpc_retain(event);
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            VM27LWCRMessageResult checked = {0}; int status = VM27PrivateServicePlanCheckReceivedMessage(plan, message, &checked);
            ++received;
            Check(status == EACCES && checked.hasRemoteConnection && checked.taskCreated &&
                  !checked.entitlementPresent && !checked.entitlementReadError, "registered-consumer-authenticates-each-native-message");
            if (status == 0) ++applicationCalls;
            xpc_object_t reply = xpc_dictionary_create_reply(message);
            Check(reply != NULL, "private-control-reply");
            if (reply) { xpc_dictionary_set_int64(reply, "gateStatus", status); xpc_connection_send_message(peer, reply); xpc_release(reply); }
        }); xpc_connection_resume(peer);
    }); xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = (xpc_endpoint_t)xpc_endpoint_create(listener);
    xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
    xpc_connection_set_target_queue(client, clientQueue); xpc_connection_set_event_handler(client, ^(xpc_object_t event) { (void)event; }); xpc_connection_resume(client);
    for (unsigned i = 0; i < 64; ++i) {
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(message, "service", ServiceIdentifier); xpc_dictionary_set_bool(message, VM27_PLUGIN_ENTITLEMENT, true);
        xpc_connection_send_message_with_reply(client, message, clientQueue, ^(xpc_object_t reply) {
            replyResult = xpc_get_type(reply) == XPC_TYPE_DICTIONARY ? (int)xpc_dictionary_get_int64(reply, "gateStatus") : -1; dispatch_semaphore_signal(replies);
        }); xpc_release(message);
        long wait = dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
        Check(wait == 0, "real-registered-private-message-reply"); if (wait) break;
        Check(replyResult == EACCES, "untrusted-service-message-not-forwarded");
    }
    dispatch_sync(serverQueue, ^{
        Check(received == 64 && applicationCalls == 0, "registered-service-native-negative-message-counts");
        if (peer) { xpc_connection_set_event_handler(peer, ^(xpc_object_t ignored) { (void)ignored; }); xpc_connection_cancel(peer); xpc_release(peer); peer = NULL; }
    });
    xpc_connection_cancel(client); xpc_connection_cancel(listener); dispatch_sync(clientQueue, ^{}); dispatch_sync(serverQueue, ^{});
    xpc_release(client); xpc_release(endpoint); xpc_release(listener);
    dispatch_release(replies); dispatch_release(serverQueue); dispatch_release(clientQueue);
    VM27PrivateServicePlanRelease(plan);
    VM27BundleRegistryStats stats = {0}; VM27BundleRegistryCopyStats(&stats); VM27LWCRStats policyStats = {0}; VM27LWCRCopyStats(&policyStats);
    Check(stats.registrations == 1 && stats.registeredServices == 1, "actual-registered-table-counts");
    Check(stats.plansCreated == stats.plansDestroyed && stats.plansCreated == 257, "plans-balanced");
    Check(stats.messageChecks == 65 && policyStats.taskCreates == 64 && policyStats.taskReleases == 64, "consumer-native-task-lifetimes-balanced");
    Check(policyStats.policiesCreated == policyStats.policiesDestroyed, "all-immutable-policies-released");
    Check(unlink(codePath) == 0 && unlink(paths[7]) == 0 && unlink(paths[6]) == 0, "only-owned-fixture-files-removed");
    for (int i = 5; i >= 0; --i) Check(rmdir(paths[i]) == 0, "only-owned-fixture-directory-removed");
    Check(rmdir(root) == 0 && access(root, F_OK) != 0 && errno == ENOENT, "owned-temporary-root-absent");
    Identity("after", "VM27BundleRegistryRegister", (void *)VM27BundleRegistryRegister, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
    Identity("after", "VM27PrivateServicePlanCheckReceivedMessage", (void *)VM27PrivateServicePlanCheckReceivedMessage, VM27_REGISTRY_SHA256, VM27_REGISTRY_BYTES, VM27_REGISTRY_UUID);
    Identity("after", "VM27LWCRPolicyCheckReceivedMessage", (void *)VM27LWCRPolicyCheckReceivedMessage, VM27_POLICY_SHA256, VM27_POLICY_BYTES, VM27_POLICY_UUID);
    Check(NoVMImages(), "no-vm-framework-images-after");
    printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"passed\":%s,\"registrations\":%llu,\"services\":%llu,\"plansCreated\":%llu,\"plansDestroyed\":%llu,\"messageChecks\":%llu,\"receivedMessages\":%u,\"applicationCalls\":%u,\"tasksCreated\":%llu,\"tasksReleased\":%llu,\"workersJoined\":%u,\"ownTemporaryRemoved\":true,\"childLaunches\":0,\"launchdRegistrations\":0,\"completeBundleRegistration\":false}\n",
        atomic_load(&gChecks), atomic_load(&gFailures), atomic_load(&gFailures) ? "false" : "true",
        (unsigned long long)stats.registrations, (unsigned long long)stats.registeredServices,
        (unsigned long long)stats.plansCreated, (unsigned long long)stats.plansDestroyed,
        (unsigned long long)stats.messageChecks, received, applicationCalls,
        (unsigned long long)policyStats.taskCreates, (unsigned long long)policyStats.taskReleases, started);
    alarm(0); return atomic_load(&gFailures) ? 78 : 0;
}
