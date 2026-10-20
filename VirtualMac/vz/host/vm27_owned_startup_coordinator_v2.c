#include "vm27_owned_startup_coordinator_v2.h"
#include "vm27_headless_checkin_v1.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Private in this one provider image. No constructors, original-symbol exports,
 * bootstrap/launchd/global LS registration, native CPU or kernel operations. */
struct VM27OwnedStartupChildV2 {
    pthread_mutex_t lock;
    pid_t ownerPID;
    uid_t ownerUID;
    dispatch_queue_t queue;
    xpc_endpoint_t endpoint;
    CFDictionaryRef checkIn;
    bool stopInFlight;
    VM27OwnedStartupStateV2 state;
};
static _Atomic(pid_t) EntryPID;
static pthread_mutex_t ProcessLock = PTHREAD_MUTEX_INITIALIZER;
static bool ProcessAttempted;
static char QueueKey;

static bool SameProcess(void) {
    pid_t actual = getpid(), unset = 0;
    atomic_compare_exchange_strong_explicit(&EntryPID, &unset, actual,
        memory_order_relaxed, memory_order_relaxed);
    return atomic_load_explicit(&EntryPID, memory_order_relaxed) == actual;
}
static int Owner(VM27OwnedStartupChildV2 *child) {
    /* Reject inherited state before touching a parent's possibly locked mutex. */
    if (!SameProcess()) return EPERM;
    if (!child) return EINVAL;
    return child->ownerPID == getpid() && child->ownerUID == geteuid() ? 0 : EPERM;
}
static bool Hex(const char *value, size_t count) {
    if (!value || strnlen(value, count + 1) != count) return false;
    for (size_t i = 0; i < count; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return false;
    return true;
}
/* Shape preconditions only. Genuine file/signature inspection is still the
 * directly called V9 provider's responsibility; no caller validation flag. */
static bool ValidParentConfiguration(const VM27OriginalV9ParentConfiguration *parent) {
    if (!parent || parent->formatVersion!=1 || parent->expectedParentPID<=1) return false;
    if (parent->kind==VM27OriginalV9ParentCodeOnlyDiagnostic) {
        const char *path=parent->source.codeOnlyDiagnostic.actualParentCodePath;
        return path && path[0]=='/' && strnlen(path,4096)<4096 &&
            Hex(parent->source.codeOnlyDiagnostic.reviewedSHA256,64) &&
            Hex(parent->source.codeOnlyDiagnostic.reviewedCDHash,40);
    }
    if (parent->kind==VM27OriginalV9ParentFlatBundle) {
        const VM27BundleParentConfigurationV1 *selected=&parent->source.flatBundle;
        const char *path=selected->bundlePath, *name=selected->executableName;
        size_t bytes=path?strnlen(path,4096):0;
        size_t nameBytes=name?strnlen(name,256):0;
        return bytes>=6 && bytes<4096 && path[0]=='/' && path[bytes-1]!='/' &&
            !strcmp(path+bytes-4,".app") && nameBytes>0 && nameBytes<=255 &&
            !strchr(name,'/') && strcmp(name,".") && strcmp(name,"..") &&
            Hex(selected->reviewedExecutableSHA256,64) && Hex(selected->reviewedExecutableCDHash,40);
    }
    return false;
}
static bool NumberEquals(CFTypeRef value, int64_t actual) {
    if (!value || CFGetTypeID(value) != CFNumberGetTypeID() ||
        CFNumberIsFloatType((CFNumberRef)value)) return false;
    int64_t copied = 0;
    return CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &copied) && copied == actual;
}
static int PrepareCheckIn(VM27OwnedStartupChildV2 *child) {
    CFBundleRef bundle = CFBundleGetMainBundle();
    CFDictionaryRef info = bundle ? CFBundleGetInfoDictionary(bundle) : NULL;
    if (!info || CFGetTypeID(info) != CFDictionaryGetTypeID()) return ENOENT;
    /* This is exactly the original main's proven borrowed input. It must stay
     * live/unmodified throughout the calls, as required by the old helper. */
    errno = 0;
    CFTypeRef borrowed = _LSApplicationCheckIn(-2, info);
    if (!borrowed) return errno ? errno : EIO;
    CFDictionaryRef retained = NULL;
    if (VM27CopyPrivateHeadlessCheckInState(&retained) || !retained)
        return errno ? errno : EIO;
    if (CFGetTypeID(retained) != CFDictionaryGetTypeID()) {
        CFRelease(retained); return EPROTO;
    }
    const void *scope = CFDictionaryGetValue(retained, CFSTR("Scope"));
    const void *instance = CFDictionaryGetValue(retained, CFSTR("Instance"));
    const void *bundleInfo = CFDictionaryGetValue(retained, CFSTR("BundleInfo"));
    bool valid = CFDictionaryGetCount(retained) == 5 && borrowed == retained &&
        scope && CFGetTypeID(scope) == CFStringGetTypeID() &&
        CFEqual(scope, CFSTR("VM27 private headless application check-in")) &&
        NumberEquals(CFDictionaryGetValue(retained, CFSTR("PID")), getpid()) &&
        NumberEquals(CFDictionaryGetValue(retained, CFSTR("UID")), geteuid()) &&
        instance && CFGetTypeID(instance) == CFUUIDGetTypeID() &&
        bundleInfo && CFGetTypeID(bundleInfo) == CFDictionaryGetTypeID() &&
        CFEqual(bundleInfo, info);
    if (!valid) { CFRelease(retained); return EPROTO; }
    child->checkIn = retained;
    child->state.privateCheckInVerified = true;
    return 0;
}

int VM27OwnedStartupChildPrepareV2(const VM27OwnedStartupConfigurationV2 *configuration,
    VM27OwnedStartupChildV2 **output, xpc_object_t *helloOutput) {
    if (!SameProcess()) return EPERM;
    if (!output || *output || !helloOutput || *helloOutput || !configuration ||
        !ValidParentConfiguration(&configuration->parent) || !configuration->bootstrapNonce) return EINVAL;
    int status = pthread_mutex_lock(&ProcessLock);
    if (status) return status;
    bool already = ProcessAttempted;
    if (!already) ProcessAttempted = true;
    int unlocked = pthread_mutex_unlock(&ProcessLock);
    if (unlocked) return unlocked;
    if (already) return EALREADY;

    VM27OwnedStartupChildV2 *child = calloc(1, sizeof(*child));
    if (!child) return ENOMEM;
    status = pthread_mutex_init(&child->lock, NULL);
    if (status) { free(child); return status; }
    child->ownerPID = getpid(); child->ownerUID = geteuid();
    child->state.phase = VM27OwnedStartupPreparingV2;
    child->state.ownerPID = child->ownerPID;
    child->state.expectedParentPID = configuration->parent.expectedParentPID;
    child->state.bootstrapNonce = configuration->bootstrapNonce;
    *output = child;
    child->queue = dispatch_queue_create("VM27.owned.startup.control.v2", DISPATCH_QUEUE_SERIAL);
    if (!child->queue) status = ENOMEM;
    if (!status) dispatch_queue_set_specific(child->queue, &QueueKey, child, NULL);
    if (!status) status = PrepareCheckIn(child);
    if (!status) status = VM27OriginalV9TransportCreateServerWithParent(
        &configuration->parent, child->queue, &child->endpoint);
    if (!status) {
        child->state.transportCreated = true;
        status = VM27OriginalV9TransportRequireServerInstance(configuration->bootstrapNonce);
        if (!status) child->state.registryConfigured = true;
    }
    xpc_object_t hello = NULL;
    if (!status) {
        if (!child->endpoint || xpc_get_type(child->endpoint) != XPC_TYPE_ENDPOINT) status = EPROTO;
        else if (!(hello = xpc_dictionary_create(NULL, NULL, 0))) status = ENOMEM;
    }
    if (!status) {
        xpc_dictionary_set_value(hello, "serviceEndpoint", child->endpoint);
        xpc_dictionary_set_string(hello, "serviceIdentifier", VM27_ORIGINAL_VM_SERVICE);
        xpc_dictionary_set_uint64(hello, "nonce", configuration->bootstrapNonce);
        child->state.phase = VM27OwnedStartupPreparedV2;
        child->state.helloReturned = true;
        *helloOutput = hello;
    } else {
        if (hello) xpc_release(hello);
        child->state.preparationStatus = status;
        child->state.phase = child->state.transportCreated ?
            VM27OwnedStartupClosingV2 : VM27OwnedStartupStoppedV2;
        /* Preserve any created server/endpoint for explicit bounded cleanup.
         * CreateServer's own inactive-listener rollback remains its own contract;
         * a failed Create does not establish that all provider callbacks drained. */
    }
    return status;
}

int VM27OwnedStartupChildCopyControlQueueV2(VM27OwnedStartupChildV2 *child,
    dispatch_queue_t *output) {
    int status = Owner(child);
    if (status) return status;
    if (!output || *output) return EINVAL;
    status = pthread_mutex_lock(&child->lock);
    if (status) return status;
    if (!child->queue || child->state.phase != VM27OwnedStartupPreparedV2) status = ENOTCONN;
    else { dispatch_retain(child->queue); *output = child->queue; }
    int unlocked = pthread_mutex_unlock(&child->lock);
    return status ? status : unlocked;
}
int VM27OwnedStartupChildReceiveControlV2(VM27OwnedStartupChildV2 *child,
    xpc_object_t message, xpc_object_t *reply) {
    int status = Owner(child);
    if (status) return status;
    if (!reply || *reply || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EINVAL;
    if (dispatch_get_specific(&QueueKey) != child) return EDEADLK;
    status = pthread_mutex_lock(&child->lock);
    if (status) return status;
    if (child->state.phase != VM27OwnedStartupPreparedV2) status = ECANCELED;
    else if (child->state.activeControlCalls == UINT_MAX || child->state.controlMessages == UINT64_MAX)
        status = EOVERFLOW;
    else { ++child->state.activeControlCalls; ++child->state.controlMessages; }
    int unlocked = pthread_mutex_unlock(&child->lock);
    if (status || unlocked) return status ? status : unlocked;
    xpc_object_t methodObject = xpc_dictionary_get_value(message, "privateMethod");
    const char *method = methodObject && xpc_get_type(methodObject) == XPC_TYPE_STRING ?
        xpc_string_get_string_ptr(methodObject) : NULL;
    bool registration = method && !strcmp(method, "VM27.register-client-title.v1");
    bool binding = method && !strcmp(method, "VM27.bind-one-shot-instance.v1");
    bool routed = (registration || binding) && xpc_dictionary_get_count(message) == 3;
    if (!registration && !binding) status = ENOTSUP;
    else if (xpc_dictionary_get_count(message) != 3) status = EPROTO;
    else status = registration ? VM27OriginalV9TransportReceiveServerClientRegistrationMessage(message, reply) :
        VM27OriginalV9TransportBindServerInstanceMessage(message, reply);
    int locked = pthread_mutex_lock(&child->lock);
    if (locked) return locked;
    --child->state.activeControlCalls;
    if (routed && registration && child->state.registrationRoutes < UINT64_MAX) ++child->state.registrationRoutes;
    if (routed && binding && child->state.bindingRoutes < UINT64_MAX) ++child->state.bindingRoutes;
    if (status && child->state.refusedControlMessages < UINT64_MAX) ++child->state.refusedControlMessages;
    child->state.lastControlStatus = status;
    unlocked = pthread_mutex_unlock(&child->lock);
    return status ? status : unlocked;
}
int VM27OwnedStartupChildCopyStateV2(VM27OwnedStartupChildV2 *child, VM27OwnedStartupStateV2 *output) {
    int status = Owner(child);
    if (status) return status;
    if (!output) return EINVAL;
    status = pthread_mutex_lock(&child->lock);
    if (status) return status;
    *output = child->state;
    return pthread_mutex_unlock(&child->lock);
}
int VM27OwnedStartupChildStopV2(VM27OwnedStartupChildV2 *child) {
    int status = Owner(child);
    if (status) return status;
    if (dispatch_get_specific(&QueueKey) == child) return EDEADLK;
    status = pthread_mutex_lock(&child->lock);
    if (status) return status;
    if (child->state.phase == VM27OwnedStartupStoppedV2) {
        pthread_mutex_unlock(&child->lock); return 0;
    }
    if (child->stopInFlight) {
        pthread_mutex_unlock(&child->lock); return EBUSY;
    }
    child->state.phase = VM27OwnedStartupClosingV2;
    bool active = child->state.activeControlCalls != 0;
    bool created = child->state.transportCreated;
    if (active) {
        child->state.cleanupStatus = EBUSY;
        int unlocked = pthread_mutex_unlock(&child->lock);
        return unlocked ? unlocked : EBUSY;
    }
    child->stopInFlight = true;
    int unlocked = pthread_mutex_unlock(&child->lock);
    if (unlocked) return unlocked;
    status = created ? VM27OriginalV9TransportStopServer() : 0;
    int locked = pthread_mutex_lock(&child->lock);
    if (locked) return locked;
    child->stopInFlight = false;
    child->state.cleanupStatus = status;
    if (!status) child->state.phase = VM27OwnedStartupStoppedV2;
    unlocked = pthread_mutex_unlock(&child->lock);
    return status ? status : unlocked;
}
int VM27OwnedStartupChildReleaseV2(VM27OwnedStartupChildV2 **output) {
    if (!output || !*output) return EINVAL;
    VM27OwnedStartupChildV2 *child = *output;
    int status = Owner(child);
    if (status) return status;
    if (dispatch_get_specific(&QueueKey) == child) return EDEADLK;
    status = pthread_mutex_lock(&child->lock);
    if (status) return status;
    bool ready = child->state.phase == VM27OwnedStartupStoppedV2 &&
        !child->state.activeControlCalls && !child->stopInFlight;
    int unlocked = pthread_mutex_unlock(&child->lock);
    if (unlocked) return unlocked;
    if (!ready) return EBUSY;
    status = pthread_mutex_destroy(&child->lock);
    if (status) return status;
    /* External final INVALID/drain is deliberately a lifetime precondition.
     * The module never upgrades a caller-provided flag to native proof. */
    if (child->queue) dispatch_queue_set_specific(child->queue, &QueueKey, NULL, NULL);
    if (child->endpoint) xpc_release(child->endpoint);
    if (child->checkIn) CFRelease(child->checkIn);
    if (child->queue) dispatch_release(child->queue);
    free(child); *output = NULL; return 0;
}
int VM27OwnedStartupParentInstallFactoryV2(VM27LargePrivateServiceConsumer *consumer,
    xpc_object_t message, uint64_t expectedNonce) {
    if (!SameProcess()) return EPERM;
    if (!consumer || !expectedNonce || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY)
        return EINVAL;
    xpc_object_t endpoint = xpc_dictionary_get_value(message, "serviceEndpoint");
    xpc_object_t name = xpc_dictionary_get_value(message, "serviceIdentifier");
    xpc_object_t nonce = xpc_dictionary_get_value(message, "nonce");
    if (xpc_dictionary_get_count(message) != 3 || !endpoint || xpc_get_type(endpoint) != XPC_TYPE_ENDPOINT ||
        !name || xpc_get_type(name) != XPC_TYPE_STRING ||
        strcmp(xpc_string_get_string_ptr(name), VM27_ORIGINAL_VM_SERVICE) ||
        !nonce || xpc_get_type(nonce) != XPC_TYPE_UINT64 || xpc_uint64_get_value(nonce) != expectedNonce)
        return EPROTO;
    return VM27OriginalV9TransportInstallClientFactoryMessage(consumer, message, expectedNonce);
}
