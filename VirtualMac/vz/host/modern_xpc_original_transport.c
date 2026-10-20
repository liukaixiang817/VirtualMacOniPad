/* Genuine27's two original service ABI entry points, app-private transport.
 * Actual strong closure/original wire protocol is a separate prerequisite. */
#include "modern_xpc_original_transport.h"
#include "modern_xpc_original_transport_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <ptrauth.h>
#include <stdbool.h>
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
static const void *ServerQueueKey = &ServerQueueKey;
typedef struct {
    xpc_connection_t listener;
    dispatch_queue_t queue;
    dispatch_semaphore_t cancelled;
    pid_t expectedPID;
    char expectedCDHash[41];
    VM27OriginalServiceHandler handler;
    bool started, stopping, stopWaiting, delivered;
    unsigned callbacks;
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
                         const char *path, const char *expectedUUID, char resultUUID[33]) {
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
                    size_t readBytes = codeSHA ? 64 : 4;
                    if (section->size >= readBytes && target >= start && target - start <= section->size - readBytes) contains = true;
                }
            }
        }
        at += c->cmdsize;
    }
    if (at != h->sizeofcmds || uuids != 1 || strcmp(uuid, expectedUUID) || !contains || (*base && *base != d.dli_fbase)) return false;
    if (codeSHA) { char actual[65]; Digest(raw, 64, actual); if (strcmp(actual, codeSHA)) return false; }
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
    void *base = NULL;
    const char *path = "/usr/lib/system/libxpc.dylib";
    bool valid = NativeSymbol((void *)SystemCreate, &ABI.nativeCreateRVA, &base, NULL, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID) &&
        NativeSymbol((void *)SystemMain, &ABI.nativeMainRVA, &base, NULL, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID) &&
        NativeSymbol((void *)SystemAudit, &ABI.auditGetterRVA, &base, VM27_ORIGINAL_AUDIT_SHA64, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID) &&
        NativeSymbol((void *)SystemEntitlement, &ABI.entitlementGetterRVA, &base, VM27_ORIGINAL_ENTITLEMENT_SHA64, path, VM27_ORIGINAL_XPC_UUID, ABI.providerUUID);
    ABI.exactSystemProvider = ABI.exactGetterCode = valid;
    base = NULL;
    ABI.exactSecurityProvider = NativeSymbol((void *)SecTaskCreateWithAuditToken, &ABI.secTaskCreateRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID) &&
        NativeSymbol((void *)SecTaskCopyValueForEntitlement, &ABI.secTaskCopyRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID) &&
        NativeSymbol((void *)SecTaskEntitlementsValidated, &ABI.secTaskValidatedRVA, &base, NULL, VM27_ORIGINAL_SECURITY_PATH, VM27_ORIGINAL_SECURITY_UUID, ABI.securityUUID);
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
    pthread_mutex_lock(&Lock);
    if (ClientEndpoint) status = EBUSY;
    else { ClientEndpoint = (xpc_endpoint_t)xpc_retain(ep); ClientConnectionMade = false; ++Stats.clientMessagesInstalled; }
    pthread_mutex_unlock(&Lock); return status;
}
void VM27OriginalTransportClearClient(void) {
    pthread_mutex_lock(&Lock); xpc_endpoint_t ep = ClientEndpoint; ClientEndpoint = NULL; ClientConnectionMade = false; pthread_mutex_unlock(&Lock);
    if (ep) xpc_release(ep);
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
    if (result) { xpc_connection_set_target_queue(result, queue); ClientConnectionMade = true; ++Stats.privateConnectionsCreated; }
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
    pthread_mutex_lock(&Lock); ++Stats.kernelCodeQueries; Stats.lastAuditPID = token.val[5]; Stats.lastAuditPIDVersion = token.val[7]; pthread_mutex_unlock(&Lock);
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
int VM27OriginalTransportCreateServer(const char *parent, const char *SHA, const char *CD, pid_t PID, dispatch_queue_t queue, xpc_endpoint_t *out) {
    if (out) *out = NULL; if (!out || PID <= 1 || !queue) return EINVAL;
    pthread_once(&NativeOnce, InitNative); if (NativeError) return NativeError;
    int status = ParentFile(parent, SHA, CD); if (status) return status;
    Server *server = calloc(1, sizeof(*server)); if (!server) return ENOMEM;
    server->expectedPID = PID; memcpy(server->expectedCDHash, CD, 41); server->queue = queue; dispatch_retain(queue);
    server->cancelled = dispatch_semaphore_create(0);
    if (!server->cancelled) { dispatch_release(queue); free(server); return ENOMEM; }
    server->listener = SystemCreate(NULL, queue);
    if (!server->listener) { dispatch_release(server->cancelled); dispatch_release(queue); free(server); return ENOMEM; }
    /* Create before binding a callback that borrows server's storage. Failure
     * cannot leave a queued callback referring to storage that was freed. */
    xpc_endpoint_t endpoint = xpc_endpoint_create(server->listener);
    if (!endpoint) { xpc_connection_cancel(server->listener); xpc_release(server->listener); dispatch_release(server->cancelled); dispatch_release(queue); free(server); return ENOMEM; }
    pthread_mutex_lock(&Lock);
    if (ActiveServer) { pthread_mutex_unlock(&Lock); xpc_release(endpoint); xpc_connection_cancel(server->listener); xpc_release(server->listener); dispatch_release(server->cancelled); dispatch_release(queue); free(server); return EBUSY; }
    ActiveServer = server; ++Stats.listenersCreated;
    dispatch_queue_set_specific(queue, ServerQueueKey, server, NULL);
    xpc_connection_set_event_handler(server->listener, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) { dispatch_semaphore_signal(server->cancelled); return; }
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t peer = (xpc_connection_t)event;
        pthread_mutex_lock(&Lock); ++Stats.peersReceived; bool possible = server->started && !server->stopping && !server->delivered && server->handler; ++server->callbacks; pthread_mutex_unlock(&Lock);
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
    xpc_release(server->listener); dispatch_release(server->cancelled); dispatch_release(server->queue); free(server); return 0;
}
__attribute__((noreturn)) void VM27OriginalTransportMain(VM27OriginalServiceHandler handler) {
    pthread_once(&NativeOnce, InitNative);
    if (NativeError || !handler) _exit(78);
    pthread_mutex_lock(&Lock); ++Stats.originalMainCalls; bool private = ActiveServer != NULL; pthread_mutex_unlock(&Lock);
    if (!private) { SystemMain(handler); __builtin_trap(); }
    if (VM27OriginalTransportStartServer(handler)) _exit(78);
    dispatch_main(); __builtin_trap();
}
