/* Genuine27's two original service ABI entry points, app-private transport.
 * Actual strong closure/original wire protocol is a separate prerequisite. */
#include "modern_xpc_original_instance_transport.h"
#include "modern_xpc_original_instance_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef, audit_token_t);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef, CFStringRef, CFErrorRef *);
extern Boolean SecTaskEntitlementsValidated(SecTaskRef);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);
typedef xpc_connection_t (*NativeCreate)(const char *, dispatch_queue_t);
typedef void (*NativeMain)(VM27OriginalServiceHandler);
typedef void (*NativeAudit)(xpc_connection_t, audit_token_t *);
typedef xpc_object_t (*NativeEntitlement)(xpc_connection_t, const char *);
typedef void (*NativeInstance)(xpc_connection_t, const unsigned char *);
typedef void (*NativeInstanceGet)(xpc_connection_t, unsigned char *);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
static NativeInstance SystemOneShot, SystemInstance;
static NativeInstanceGet SystemInstanceGet;

static pthread_once_t NativeOnce = PTHREAD_ONCE_INIT;
static pthread_mutex_t Lock = PTHREAD_MUTEX_INITIALIZER;
static NativeCreate SystemCreate;
static NativeMain SystemMain;
static NativeAudit SystemAudit;
static NativeEntitlement SystemEntitlement;
static VM27OriginalTransportABI ABI;
static VM27OriginalTransportStats Stats;
static int NativeError = ENOTSUP;
static xpc_endpoint_t ClientEndpoint;
static bool ClientConnectionMade;
static xpc_connection_t ClientConnection, ClientControl;
static pid_t ClientPID;
static char ClientCD[41];
static uint64_t ClientNonce, ClientGeneration;
static bool ClientBinding, ClientInstanceReady;
static unsigned char ClientInstance[16];
static const void *ServerQueueKey = &ServerQueueKey;
typedef struct {
    xpc_connection_t listener;
    dispatch_queue_t queue;
    dispatch_semaphore_t cancelled;
    dispatch_queue_t rollbackQueue;
    _Atomic unsigned rollbackReferences;
    pid_t expectedPID;
    char expectedCDHash[41];
    VM27OriginalServiceHandler handler;
    bool started, stopping, stopWaiting, delivered;
    unsigned callbacks;
    uint64_t instanceNonce;
    bool instanceBound;
    unsigned char instance[16];
} Server;
static Server *ActiveServer;

static bool Hex(const char *p, size_t n) {
    if (!p || strlen(p) != n) return false;
    for (size_t i = 0; i < n; ++i) if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}
static void Digest(const unsigned char *b, size_t n, char hex[65]) {
    unsigned char digest[32]; CC_SHA256(b, (CC_LONG)n, digest);
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) { hex[2 * i] = digits[digest[i] >> 4]; hex[2 * i + 1] = digits[digest[i] & 15]; }
    hex[64] = 0;
}
static bool NativeSymbol(void *entry, uintptr_t *RVA, void **base, const char *codeSHA,
                         const char *path, const char *expectedUUID, char resultUUID[33], size_t codeBytes) {
    void *raw = ptrauth_strip(entry, ptrauth_key_function_pointer); Dl_info d = {0};
    if (!entry || !dladdr(raw, &d) || !d.dli_fbase || !d.dli_fname || strcmp(d.dli_fname, path)) return false;
    const struct mach_header_64 *h = d.dli_fbase;
    if (h->magic != MH_MAGIC_64 || (uint32_t)h->cputype != 0x100000c || h->filetype != MH_DYLIB || !h->ncmds || h->ncmds > 256 || !h->sizeofcmds || h->sizeofcmds > 16384) return false;
    const unsigned char *commands = (const void *)(h + 1); size_t at = 0;
    char uuid[33] = {0}; unsigned uuids = 0; bool contains = false;
    for (unsigned i = 0; i < h->ncmds; ++i) {
        if (at > h->sizeofcmds || h->sizeofcmds - at < sizeof(struct load_command)) return false;
        const struct load_command *c = (const void *)(commands + at);
        if (c->cmdsize < 8 || c->cmdsize & 7 || c->cmdsize > h->sizeofcmds - at) return false;
        if (c->cmd == LC_UUID) {
            if (c->cmdsize != 24 || ++uuids != 1) return false;
            const unsigned char *bytes = commands + at + 8;
            for (unsigned j = 0; j < 16; ++j) { static const char digits[] = "0123456789abcdef"; uuid[2 * j] = digits[bytes[j] >> 4]; uuid[2 * j + 1] = digits[bytes[j] & 15]; }
        } else if (c->cmd == LC_SEGMENT_64) {
            if (c->cmdsize < sizeof(struct segment_command_64)) return false;
            const struct segment_command_64 *segment = (const void *)c;
            if (segment->nsects > 128 || c->cmdsize != sizeof(*segment) + segment->nsects * sizeof(struct section_64)) return false;
            if (!memcmp(segment->segname, "__TEXT\0", 7)) {
                if (!(segment->initprot & VM_PROT_READ) || !(segment->initprot & VM_PROT_EXECUTE) || segment->initprot & VM_PROT_WRITE) return false;
                for (unsigned j = 0; j < segment->nsects; ++j) {
                    const struct section_64 *section = (const void *)((const char *)segment + sizeof(*segment) + j * sizeof(*section));
                    if (memcmp(section->sectname, "__text\0", 7)) continue;
                    if (section->addr < segment->vmaddr || section->size > segment->vmsize || section->addr - segment->vmaddr > segment->vmsize - section->size) return false;
                    uintptr_t start = (uintptr_t)d.dli_fbase + section->addr - segment->vmaddr, target = (uintptr_t)raw;
                    size_t readBytes = codeSHA ? codeBytes : 4;
                    if (section->size >= readBytes && target >= start && target - start <= section->size - readBytes) contains = true;
                }
            }
        }
        at += c->cmdsize;
    }
    if (at != h->sizeofcmds || uuids != 1 || strcmp(uuid, expectedUUID) || !contains || (*base && *base != d.dli_fbase)) return false;
    if (codeSHA) { char actual[65]; Digest(raw, codeBytes, actual); if (strcmp(actual, codeSHA)) return false; }
    *base = d.dli_fbase; *RVA = (uintptr_t)raw - (uintptr_t)d.dli_fbase; memcpy(resultUUID, uuid, sizeof(uuid));
    return true;
}
static void InitNative(void) {
    /* Exact RTLD_LOCAL provider lookup, so our same-named exports cannot recur. */
    void *library = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) return;
    SystemCreate = (NativeCreate)dlsym(library, "xpc_connection_create");
    SystemMain = (NativeMain)dlsym(library, "xpc_main");
    SystemAudit = (NativeAudit)dlsym(library, "xpc_connection_get_audit_token");
    SystemEntitlement = (NativeEntitlement)dlsym(library, "xpc_connection_copy_entitlement_value");
    SystemOneShot = (NativeInstance)dlsym(library, "xpc_connection_set_oneshot_instance");
    SystemInstance = (NativeInstance)dlsym(library, "xpc_connection_set_instance");
    SystemInstanceGet = (NativeInstanceGet)dlsym(library, "xpc_connection_get_instance");
    void *base = NULL;
    const char *path = "/usr/lib/system/libxpc.dylib";
    bool valid = NativeSymbol((void *)SystemCreate, &ABI.nativeCreateRVA, &base, NULL, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 64) &&
        NativeSymbol((void *)SystemMain, &ABI.nativeMainRVA, &base, NULL, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 64) &&
        NativeSymbol((void *)SystemAudit, &ABI.auditGetterRVA, &base, VM27_ORIGINAL_AUDIT_SHA64, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 64) &&
        NativeSymbol((void *)SystemEntitlement, &ABI.entitlementGetterRVA, &base, VM27_ORIGINAL_ENTITLEMENT_SHA64, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 64);
    ABI.exactInstanceCode = NativeSymbol((void *)SystemOneShot, &ABI.oneShotRVA, &base, VM27_INSTANCE_ONESHOT_SHA, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 16) &&
        NativeSymbol((void *)SystemInstance, &ABI.instanceSetRVA, &base, VM27_INSTANCE_SET_SHA, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 92) &&
        NativeSymbol((void *)SystemInstanceGet, &ABI.instanceGetRVA, &base, VM27_INSTANCE_GET_SHA, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID, 16);
    valid = valid && ABI.exactInstanceCode;
    ABI.exactSystemProvider = ABI.exactGetterCode = valid;
    base = NULL;
    ABI.exactSecurityProvider = NativeSymbol((void *)SecTaskCreateWithAuditToken, &ABI.secTaskCreateRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID, 64) &&
        NativeSymbol((void *)SecTaskCopyValueForEntitlement, &ABI.secTaskCopyRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID, 64) &&
        NativeSymbol((void *)SecTaskEntitlementsValidated, &ABI.secTaskValidatedRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID, 64);
    if (valid && ABI.exactSecurityProvider) NativeError = 0;
    /* Keep this exact system cache handle for process lifetime. No unload while
     * a caller/queue may own one of its native objects or callback entry points. */
}
int VM27OriginalTransportCopyABI(VM27OriginalTransportABI *out) {
    if (!out) return EINVAL; pthread_once(&NativeOnce, InitNative); *out = ABI; return NativeError;
}
void VM27OriginalTransportCopyStats(VM27OriginalTransportStats *out) {
    if (!out) return; pthread_mutex_lock(&Lock); *out = Stats; pthread_mutex_unlock(&Lock);
}
int VM27OriginalTransportInstallClientFactoryMessage(VM27PrivateServiceConsumer *consumer, xpc_object_t message, uint64_t nonce) {
    pthread_once(&NativeOnce, InitNative); if (NativeError) return NativeError;
    if (!consumer || !nonce || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EINVAL;
    xpc_object_t ep = xpc_dictionary_get_value(message, "serviceEndpoint"), n = xpc_dictionary_get_value(message, "nonce"), name = xpc_dictionary_get_value(message, "serviceIdentifier");
    if (!ep || xpc_get_type(ep) != XPC_TYPE_ENDPOINT || !n || xpc_get_type(n) != XPC_TYPE_UINT64 || xpc_dictionary_get_uint64(message, "nonce") != nonce ||
        !name || xpc_get_type(name) != XPC_TYPE_STRING || strcmp(xpc_string_get_string_ptr(name), VM27_ORIGINAL_VM_SERVICE)) return EPROTO;
    VM27ApprovedCodeMessageResult gate = {0}; int status = VM27PrivateServiceConsumerCheckMessage(consumer, message, &gate);
    if (status) return status;
    VM27PrivateConsumerState state = {0};
    xpc_connection_t control = xpc_dictionary_get_remote_connection(message);
    if (VM27PrivateServiceConsumerCopyState(consumer, &state) || !state.started || state.reaped || state.childPID <= 1 || !control || !Hex(gate.kernelCDHash, 40) || gate.auditPID != (unsigned)state.childPID) return EACCES;
    pthread_mutex_lock(&Lock);
    if (ClientEndpoint) status = EBUSY;
    else { ClientEndpoint = (xpc_endpoint_t)xpc_retain(ep); ClientConnectionMade = false; ClientControl = (xpc_connection_t)xpc_retain(control); ClientPID = state.childPID; memcpy(ClientCD, gate.kernelCDHash, 41); ClientNonce = nonce; ++ClientGeneration; ++Stats.clientMessagesInstalled; }
    pthread_mutex_unlock(&Lock); return status;
}
void VM27OriginalTransportClearClient(void) {
    pthread_mutex_lock(&Lock); xpc_endpoint_t ep = ClientEndpoint; xpc_connection_t connection = ClientConnection, control = ClientControl;
    ClientEndpoint = NULL; ClientConnection = ClientControl = NULL; ClientConnectionMade = ClientBinding = ClientInstanceReady = false; ClientNonce = 0; ClientPID = 0; memset(ClientCD, 0, sizeof(ClientCD)); memset(ClientInstance, 0, sizeof(ClientInstance)); ++ClientGeneration; pthread_mutex_unlock(&Lock);
    if (ep) xpc_release(ep); if (connection) xpc_release(connection); if (control) xpc_release(control);
}
xpc_connection_t VM27OriginalTransportConnectionCreate(const char *name, dispatch_queue_t queue) {
    pthread_once(&NativeOnce, InitNative); if (NativeError) { errno = NativeError; return NULL; }
    if (!name || strcmp(name, VM27_ORIGINAL_VM_SERVICE)) {
        xpc_connection_t native = SystemCreate(name, queue);
        pthread_mutex_lock(&Lock); ++Stats.nativeConnectionsForwarded; pthread_mutex_unlock(&Lock); return native;
    }
    pthread_mutex_lock(&Lock);
    if (!ClientEndpoint || ClientConnectionMade) { errno = ClientEndpoint ? EALREADY : ENOTCONN; pthread_mutex_unlock(&Lock); return NULL; }
    xpc_connection_t result = xpc_connection_create_from_endpoint(ClientEndpoint);
    if (result) { xpc_connection_set_target_queue(result, queue); ClientConnectionMade = true; ClientConnection = (xpc_connection_t)xpc_retain(result); ++Stats.privateConnectionsCreated; }
    pthread_mutex_unlock(&Lock); return result;
}

static int ParentFile(const char *path, const char *SHA, const char *CD) {
    if (!path || path[0] != '/' || strlen(path) >= 4096 || !Hex(SHA, 64) || !Hex(CD, 40)) return EINVAL;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return errno;
    struct stat st; int status = 0; unsigned char *data = NULL;
    if (fstat(fd, &st)) status = errno;
    else if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size <= 0 || st.st_size > 2 * 1024 * 1024 || st.st_mode & 0022) status = EPERM;
    if (!status && !(data = malloc((size_t)st.st_size))) status = ENOMEM;
    size_t at = 0;
    while (!status && at < (size_t)st.st_size) { ssize_t n = pread(fd, data + at, (size_t)st.st_size - at, (off_t)at); if (n < 0 && errno == EINTR) continue; if (n <= 0) status = n < 0 ? errno : EIO; else at += (size_t)n; }
    VM27ApprovedCodeInfo actual = {0};
    if (!status) status = VM27ApprovedCodeInspectBytes(data, at, &actual);
    if (!status && (strcmp(actual.fileSHA256, SHA) || strcmp(actual.CDHash, CD))) status = EACCES;
    free(data); if (close(fd) && !status) status = errno; return status;
}
static bool NativeBoolean(xpc_connection_t peer, SecTaskRef task, const char *key, int *status) {
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
    CFErrorRef error = NULL; CFTypeRef value = name ? SecTaskCopyValueForEntitlement(task, name, &error) : NULL;
    bool secBool = value && !error && CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)value);
    if (error) { *status = EACCES; CFRelease(error); } if (value) CFRelease(value); if (name) CFRelease(name);
    xpc_object_t native = SystemEntitlement(peer, key);
    bool connectionBool = native && xpc_get_type(native) == XPC_TYPE_BOOL && xpc_bool_get_value(native);
    if (native) xpc_release(native);
    return secBool && connectionBool;
}
static int GatePeer(Server *server, xpc_connection_t peer) {
    audit_token_t token = {{0}}; SystemAudit(peer, &token);
    if (token.val[5] != (unsigned)server->expectedPID || !token.val[7]) return EACCES;
    unsigned char digest[20] = {0}; unsigned flags = 0;
    int codeRC = csops_audittoken(server->expectedPID, 5, digest, sizeof(digest), &token);
    int flagsRC = csops_audittoken(server->expectedPID, 0, &flags, sizeof(flags), &token);
    char CD[41] = {0}; static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 20; ++i) { CD[2 * i] = digits[digest[i] >> 4]; CD[2 * i + 1] = digits[digest[i] & 15]; }
    pthread_mutex_lock(&Lock); ++Stats.kernelCodeQueries; Stats.lastAuditPID = token.val[5]; Stats.lastAuditPIDVersion = token.val[7]; memcpy(Stats.lastKernelCDHash, CD, 41); Stats.lastCodeStatus = flags; Stats.lastCodeQueryResult = codeRC; Stats.lastStatusQueryResult = flagsRC; pthread_mutex_unlock(&Lock);
    if (codeRC || flagsRC || !(flags & 1) || strcmp(CD, server->expectedCDHash)) return EACCES;
    SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, token); if (!task) return EACCES;
    pthread_mutex_lock(&Lock); ++Stats.tasksCreated; pthread_mutex_unlock(&Lock);
    bool validated = SecTaskEntitlementsValidated(task); int error = 0; uint32_t mask = 0;
    if (NativeBoolean(peer, task, "com.apple.private.virtualization", &error)) mask = 3;
    else if (NativeBoolean(peer, task, "com.apple.security.virtualization", &error)) mask = 1;
    CFRelease(task);
    pthread_mutex_lock(&Lock); ++Stats.tasksReleased; Stats.lastBaseCapabilityMask = mask; Stats.lastNativeEntitlementsValidated = validated; pthread_mutex_unlock(&Lock);
    return !error && mask & 1 ? 0 : EACCES;
}
#if VM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE
static bool DiagnosticEndpointFailure;
void VM27OriginalTransportInjectEndpointFailureOnceForDiagnostic(void) {
    pthread_mutex_lock(&Lock); DiagnosticEndpointFailure = true; pthread_mutex_unlock(&Lock);
}
#endif
static void RollbackRelease(Server *server) {
    if (atomic_fetch_sub(&server->rollbackReferences, 1) != 1) return;
    xpc_release(server->listener); dispatch_release(server->cancelled);
    dispatch_release(server->queue); dispatch_release(server->rollbackQueue); free(server);
    pthread_mutex_lock(&Lock); ++Stats.rollbackListenersReleased; pthread_mutex_unlock(&Lock);
}
/* Only a never-published own inactive listener. Private cleanup queue was
 * allocated before the listener, so a failed allocation cannot leave a raw
 * suspended object that must be incorrectly cancelled/released. */
static int RollbackInactiveListener(Server *server) {
    atomic_init(&server->rollbackReferences, 2);
    pthread_mutex_lock(&Lock); ++Stats.rollbackListenersStarted; pthread_mutex_unlock(&Lock);
    xpc_connection_set_target_queue(server->listener, server->rollbackQueue);
    xpc_connection_set_event_handler(server->listener, ^(xpc_object_t event) {
        if (event != XPC_ERROR_CONNECTION_INVALID) return;
        pthread_mutex_lock(&Lock); ++Stats.rollbackFinalInvalidEvents; pthread_mutex_unlock(&Lock);
        dispatch_semaphore_signal(server->cancelled); RollbackRelease(server);
    });
    xpc_connection_resume(server->listener); xpc_connection_cancel(server->listener);
    bool final = !dispatch_semaphore_wait(server->cancelled, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
    if (final) dispatch_sync(server->rollbackQueue, ^{});
    /* Timeout keeps the callback's explicit +1 reference. The real final event
     * eventually releases it; no borrowed stack semaphore or freed storage. */
    RollbackRelease(server); return final ? 0 : ETIMEDOUT;
}
int VM27OriginalTransportCreateServer(const char *parent, const char *SHA, const char *CD, pid_t PID, dispatch_queue_t queue, xpc_endpoint_t *out) {
    if (out) *out = NULL; if (!out || PID <= 1 || !queue) return EINVAL;
    pthread_once(&NativeOnce, InitNative); if (NativeError) return NativeError;
    int status = ParentFile(parent, SHA, CD); if (status) return status;
    Server *server = calloc(1, sizeof(*server)); if (!server) return ENOMEM;
    server->expectedPID = PID; memcpy(server->expectedCDHash, CD, 41); server->queue = queue; dispatch_retain(queue);
    server->cancelled = dispatch_semaphore_create(0);
    server->rollbackQueue = dispatch_queue_create("VM27.Original.listener.rollback", DISPATCH_QUEUE_SERIAL);
    if (!server->cancelled || !server->rollbackQueue) {
        if (server->cancelled) dispatch_release(server->cancelled); if (server->rollbackQueue) dispatch_release(server->rollbackQueue);
        dispatch_release(queue); free(server); return ENOMEM;
    }
    server->listener = SystemCreate(NULL, queue);
    if (!server->listener) { dispatch_release(server->rollbackQueue); dispatch_release(server->cancelled); dispatch_release(queue); free(server); return ENOMEM; }
    /* Create before binding a callback that borrows server's storage. Failure
     * cannot leave a queued callback referring to storage that was freed. */
    bool failEndpoint = false;
#if VM27_ENABLE_DIAGNOSTIC_ENDPOINT_FAILURE
    pthread_mutex_lock(&Lock); failEndpoint = DiagnosticEndpointFailure; DiagnosticEndpointFailure = false; pthread_mutex_unlock(&Lock);
#endif
    xpc_endpoint_t endpoint = failEndpoint ? NULL : xpc_endpoint_create(server->listener);
    if (!endpoint) { int cleanup = RollbackInactiveListener(server); return cleanup ? cleanup : ENOMEM; }
    pthread_mutex_lock(&Lock);
    if (ActiveServer) { pthread_mutex_unlock(&Lock); xpc_release(endpoint); int cleanup = RollbackInactiveListener(server); return cleanup ? cleanup : EBUSY; }
    ActiveServer = server; ++Stats.listenersCreated;
    dispatch_queue_set_specific(queue, ServerQueueKey, server, NULL);
    xpc_connection_set_event_handler(server->listener, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) { dispatch_semaphore_signal(server->cancelled); return; }
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t peer = (xpc_connection_t)event;
        pthread_mutex_lock(&Lock); ++Stats.peersReceived; bool possible = server->started && !server->stopping && !server->delivered && server->handler && server->instanceBound; ++server->callbacks; pthread_mutex_unlock(&Lock);
        int error = possible ? GatePeer(server, peer) : EBUSY;
        pthread_mutex_lock(&Lock); if (server->stopping || server->delivered) error = EBUSY;
        VM27OriginalServiceHandler handler = error ? NULL : server->handler;
        if (handler) { server->delivered = true; ++Stats.peersAccepted; ++Stats.originalHandlerCalls; } else ++Stats.peersDenied;
        Stats.lastPeerError = error; pthread_mutex_unlock(&Lock);
        /* Borrowed native connection, exactly the original void callback ABI;
         * callback controls its actual target queue, event handler and retain.
         * No private memory/ownership/PAC forging and no synthetic message. */
        if (handler) handler(peer); else xpc_connection_cancel(peer);
        pthread_mutex_lock(&Lock); --server->callbacks; pthread_mutex_unlock(&Lock);
    });
    *out = endpoint;
    pthread_mutex_unlock(&Lock); return 0;
}
int VM27OriginalTransportStartServer(VM27OriginalServiceHandler handler) {
    if (!handler) return EINVAL; pthread_mutex_lock(&Lock); Server *server = ActiveServer;
    int error = !server ? ENOTCONN : server->started || server->stopping ? EALREADY : 0;
    if (!error) { server->handler = handler; server->started = true; xpc_connection_resume(server->listener); }
    pthread_mutex_unlock(&Lock); return error;
}
int VM27OriginalTransportStopServer(void) {
    pthread_mutex_lock(&Lock); Server *server = ActiveServer;
    if (!server) { pthread_mutex_unlock(&Lock); return ENOTCONN; }
    if (dispatch_get_specific(ServerQueueKey) == server || (server->queue == dispatch_get_main_queue() && pthread_main_np())) { pthread_mutex_unlock(&Lock); return EDEADLK; }
    if (server->stopWaiting || server->callbacks) { pthread_mutex_unlock(&Lock); return EBUSY; }
    server->stopWaiting = true;
    if (!server->stopping) {
        server->stopping = true;
        if (!server->started) xpc_connection_resume(server->listener);
        xpc_connection_cancel(server->listener);
    }
    pthread_mutex_unlock(&Lock);
    /* INVALID is libxpc's final event. A serial-queue barrier alone would not
     * establish that its internal delivery queue cannot enqueue another event.
     * Timeout leaves owned storage live and permits a later bounded retry. */
    if (dispatch_semaphore_wait(server->cancelled, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC))) {
        pthread_mutex_lock(&Lock); server->stopWaiting = false; pthread_mutex_unlock(&Lock); return ETIMEDOUT;
    }
    dispatch_sync(server->queue, ^{});
    pthread_mutex_lock(&Lock); ActiveServer = NULL; ++Stats.listenersDestroyed; pthread_mutex_unlock(&Lock);
    dispatch_queue_set_specific(server->queue, ServerQueueKey, NULL, NULL);
    xpc_release(server->listener); dispatch_release(server->cancelled); dispatch_release(server->queue); dispatch_release(server->rollbackQueue); free(server); return 0;
}
__attribute__((noreturn)) void VM27OriginalTransportMain(VM27OriginalServiceHandler handler) {
    pthread_once(&NativeOnce, InitNative);
    if (NativeError || !handler) _exit(78);
    pthread_mutex_lock(&Lock); ++Stats.originalMainCalls; bool private = ActiveServer != NULL; pthread_mutex_unlock(&Lock);
    if (!private) { SystemMain(handler); __builtin_trap(); }
    if (VM27OriginalTransportStartServer(handler)) _exit(78);
    dispatch_main(); __builtin_trap();
}

static bool NonzeroUUID(const unsigned char uuid[16]) {
    if (!uuid) return false; unsigned char bits = 0; for (unsigned i = 0; i < 16; ++i) bits |= uuid[i]; return bits != 0;
}
/* The received dictionary's kernel token and native remote connection must
 * agree. The identity gate uses real csops/SecTask/native CF/XPC Booleans. */
static int GateInstanceMessage(Server *identity, xpc_object_t message) {
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EPROTO;
    audit_token_t token = {{0}}, connection = {{0}};
    xpc_dictionary_get_audit_token(message, &token);
    xpc_connection_t peer = xpc_dictionary_get_remote_connection(message);
    if (!peer || token.val[5] != (unsigned)identity->expectedPID || !token.val[7]) return EACCES;
    SystemAudit(peer, &connection);
    if (memcmp(&token, &connection, sizeof(token))) return EACCES;
    return GatePeer(identity, peer);
}
int VM27OriginalTransportRequireServerInstance(uint64_t nonce) {
    if (!nonce) return EINVAL;
    pthread_mutex_lock(&Lock); Server *server = ActiveServer;
    int status = !server ? ENOTCONN : server->started || server->stopping || server->instanceNonce ? EALREADY : 0;
    if (!status) server->instanceNonce = nonce;
    pthread_mutex_unlock(&Lock); return status;
}
int VM27OriginalTransportCopyServerInstance(unsigned char out[16]) {
    if (!out) return EINVAL; memset(out, 0, 16);
    pthread_mutex_lock(&Lock); Server *server = ActiveServer;
    int status = !server || !server->instanceBound ? ENOTCONN : 0;
    if (!status) memcpy(out, server->instance, 16);
    pthread_mutex_unlock(&Lock); return status;
}
int VM27OriginalTransportBindServerInstanceMessage(xpc_object_t message, xpc_object_t *out) {
    if (out) *out = NULL;
    if (!out || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EINVAL;
    pthread_mutex_lock(&Lock); Server *server = ActiveServer;
    int status = !server ? ENOTCONN : server->stopping || !server->instanceNonce || server->instanceBound ? EALREADY : 0;
    if (!status && dispatch_get_specific(ServerQueueKey) != server) status = EDEADLK;
    if (!status) ++server->callbacks;
    pthread_mutex_unlock(&Lock); if (status) return status;
    unsigned char uuid[16] = {0}; size_t bytes = 0;
    const void *data = xpc_dictionary_get_data(message, "instanceUUID", &bytes);
    xpc_object_t method = xpc_dictionary_get_value(message, "privateMethod"), n = xpc_dictionary_get_value(message, "nonce");
    if (!method || xpc_get_type(method) != XPC_TYPE_STRING || strcmp(xpc_string_get_string_ptr(method), "VM27.bind-one-shot-instance.v1") ||
        !n || xpc_get_type(n) != XPC_TYPE_UINT64 || xpc_dictionary_get_uint64(message, "nonce") != server->instanceNonce || !data || bytes != 16) status = EPROTO;
    if (!status) { memcpy(uuid, data, 16); if (!NonzeroUUID(uuid)) status = EINVAL; }
    if (!status) status = GateInstanceMessage(server, message);
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (!reply && !status) status = ENOMEM;
    pthread_mutex_lock(&Lock);
    if (!status && (server != ActiveServer || server->stopping || server->instanceBound)) status = EALREADY;
    if (!status) { memcpy(server->instance, uuid, 16); server->instanceBound = true; ++Stats.serverInstancesBound; }
    uint64_t nonce = server->instanceNonce; --server->callbacks; pthread_mutex_unlock(&Lock);
    if (reply) {
        xpc_dictionary_set_int64(reply, "instanceStatus", status);
        xpc_dictionary_set_uint64(reply, "nonce", nonce);
        xpc_dictionary_set_data(reply, "instanceUUID", uuid, 16); *out = reply;
    }
    return status;
}

typedef struct {
    _Atomic unsigned references;
    pthread_mutex_t mutex;
    dispatch_semaphore_t done;
    dispatch_queue_t queue;
    xpc_connection_t control;
    Server identity;
    unsigned char uuid[16];
    uint64_t nonce;
    int status;
} InstanceRequest;
static void RequestRelease(InstanceRequest *request) {
    if (atomic_fetch_sub(&request->references, 1) != 1) return;
    xpc_release(request->control); dispatch_release(request->queue); dispatch_release(request->done);
    pthread_mutex_destroy(&request->mutex); free(request);
    pthread_mutex_lock(&Lock); --Stats.pendingInstanceRequests; pthread_mutex_unlock(&Lock);
}
void VM27OriginalTransportSetOneShotInstance(xpc_connection_t connection, const unsigned char *uuid) {
    pthread_once(&NativeOnce, InitNative);
    if (NativeError || !connection) { errno = NativeError ? NativeError : EINVAL; return; }
    pthread_mutex_lock(&Lock); bool private = connection == ClientConnection;
    if (!private) { pthread_mutex_unlock(&Lock); SystemOneShot(connection, uuid); return; }
    int status = !NonzeroUUID(uuid) ? EINVAL : ClientBinding || ClientInstanceReady ? EALREADY : !ClientControl ? ENOTCONN : 0;
    uint64_t generation = ClientGeneration;
    InstanceRequest *request = status ? NULL : calloc(1, sizeof(*request));
    if (!status && !request) status = ENOMEM;
    if (!status) {
        /* Copy the expected identity and retain actual native transport. No
         * callback can borrow a caller-owned consumer, stack UUID or queue. */
        request->control = (xpc_connection_t)xpc_retain(ClientControl);
        request->identity.expectedPID = ClientPID; memcpy(request->identity.expectedCDHash, ClientCD, 41);
        memcpy(request->uuid, uuid, 16); request->nonce = ClientNonce; request->status = ETIMEDOUT;
        request->queue = dispatch_queue_create("VM27.Original.instance.reply", DISPATCH_QUEUE_SERIAL);
        request->done = dispatch_semaphore_create(0);
        int mutex = pthread_mutex_init(&request->mutex, NULL);
        if (!request->queue || !request->done || mutex) {
            if (request->queue) dispatch_release(request->queue); if (request->done) dispatch_release(request->done);
            if (!mutex) pthread_mutex_destroy(&request->mutex); xpc_release(request->control); free(request); request = NULL; status = ENOMEM;
        } else { atomic_init(&request->references, 2); ClientBinding = true; ++Stats.instanceRequests; ++Stats.pendingInstanceRequests; }
    }
    Stats.lastInstanceStatus = status; pthread_mutex_unlock(&Lock);
    if (!request) { errno = status; return; }
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    if (!message) {
        pthread_mutex_lock(&Lock); if (generation == ClientGeneration) ClientBinding = false; Stats.lastInstanceStatus = ENOMEM; pthread_mutex_unlock(&Lock);
        RequestRelease(request); RequestRelease(request); xpc_connection_cancel(connection); errno = ENOMEM; return;
    }
    xpc_dictionary_set_string(message, "privateMethod", "VM27.bind-one-shot-instance.v1");
    xpc_dictionary_set_uint64(message, "nonce", request->nonce); xpc_dictionary_set_data(message, "instanceUUID", request->uuid, 16);
    xpc_connection_send_message_with_reply(request->control, message, request->queue, ^(xpc_object_t reply) {
        int result = GateInstanceMessage(&request->identity, reply);
        if (!result) {
            size_t bytes = 0; const void *data = xpc_dictionary_get_data(reply, "instanceUUID", &bytes);
            xpc_object_t n = xpc_dictionary_get_value(reply, "nonce"), s = xpc_dictionary_get_value(reply, "instanceStatus");
            if (!n || xpc_get_type(n) != XPC_TYPE_UINT64 || !s || xpc_get_type(s) != XPC_TYPE_INT64 ||
                xpc_dictionary_get_uint64(reply, "nonce") != request->nonce || !data || bytes != 16 || memcmp(data, request->uuid, 16)) result = EPROTO;
            else result = (int)xpc_dictionary_get_int64(reply, "instanceStatus");
        }
        pthread_mutex_lock(&request->mutex); request->status = result; pthread_mutex_unlock(&request->mutex);
        pthread_mutex_lock(&Lock); ++Stats.instanceCallbacks; if (reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) ++Stats.instanceReplies; pthread_mutex_unlock(&Lock);
        dispatch_semaphore_signal(request->done); RequestRelease(request);
    }); xpc_release(message);
    bool arrived = !dispatch_semaphore_wait(request->done, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
    if (arrived) { pthread_mutex_lock(&request->mutex); status = request->status; pthread_mutex_unlock(&request->mutex); }
    else { status = ETIMEDOUT; xpc_connection_cancel(request->control);
        /* Cancellation must complete the native reply/error callback. Caller
         * and callback retain independent storage if delivery is delayed. */
        (void)dispatch_semaphore_wait(request->done, dispatch_time(DISPATCH_TIME_NOW, 1LL * NSEC_PER_SEC));
    }
    pthread_mutex_lock(&Lock);
    if (generation != ClientGeneration || connection != ClientConnection) status = ECANCELED;
    else { ClientBinding = false; if (!status) { memcpy(ClientInstance, request->uuid, 16); ClientInstanceReady = true; ++Stats.instancesCommitted; } }
    Stats.lastInstanceStatus = status; pthread_mutex_unlock(&Lock);
    if (status) xpc_connection_cancel(connection);
    RequestRelease(request); errno = status;
}
void VM27OriginalTransportGetInstance(xpc_connection_t connection, unsigned char *out) {
    pthread_once(&NativeOnce, InitNative);
    if (NativeError || !connection || !out) { errno = NativeError ? NativeError : EINVAL; return; }
    pthread_mutex_lock(&Lock);
    if (connection != ClientConnection) { pthread_mutex_unlock(&Lock); SystemInstanceGet(connection, out); return; }
    int status = ClientInstanceReady ? 0 : ENOTCONN;
    if (!status) { memcpy(out, ClientInstance, 16); ++Stats.instancesCopied; } else memset(out, 0, 16);
    pthread_mutex_unlock(&Lock); errno = status;
}
