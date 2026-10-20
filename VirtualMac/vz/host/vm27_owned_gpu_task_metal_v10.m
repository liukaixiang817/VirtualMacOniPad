/* Fresh narrow native task backports. No old transport, shader compiler,
 * feature advertisement, GPU work or completion response is copied here. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurfaceRef.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include "vm27_owned_gpu_task_transport_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void RequireV1(const void *caller, uintptr_t rva) {
    int status = VM27OwnedGPUTaskAdmitNativeCallerV1(caller, rva);
    if (status) {
        fprintf(stderr, "[Independent27GPU] native-Metal caller admission failed status=%d expectedRVA=0x%lx\n", status, (unsigned long)rva);
        _exit(70);
    }
}
/* The iPhoneOS SDK marks MTLCreateSystemDefaultDevice NS_RETURNS_RETAINED.
 * Preserve its existing +1 on a real exact registry match, release that one
 * ownership on mismatch, and never manufacture an unrelated GPU device. */
id MTLCopyDeviceForRegistryID(uint64_t registryID) __attribute__((ns_returns_retained));
id MTLCopyDeviceForRegistryID(uint64_t registryID) {
    RequireV1(__builtin_return_address(0), 0x2a074);
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    SEL selector = sel_registerName("registryID");
    if (!device || ![device respondsToSelector:selector] ||
        ((uint64_t (*)(id, SEL))objc_msgSend)(device, selector) != registryID) {
        [device release];
        fprintf(stderr, "[Independent27GPU] actual-default-Metal registry match=0 requested=0x%llx\n", (unsigned long long)registryID);
        return nil;
    }
    fprintf(stderr, "[Independent27GPU] actual-default-Metal registry match=1 requested=0x%llx\n", (unsigned long long)registryID);
    return device;
}
/* Exact classification already measured across all 65536 input values in
 * modern-gputask/native-rgb-format-contract.json. RGB-only semantics remain. */
/* Only three reviewed native handshake BLs enter this existing C stub with
 * a real MTLDevice in x0. BOOL and the original RGB bool both return in w0.
 * No class methods are added; absent native capabilities remain unsupported. */
static bool NativeCapabilityV2(id device, const char *name) {
    SEL selector = sel_registerName(name);
    Method method = device ? class_getInstanceMethod(object_getClass(device), selector) : NULL;
    if (!device) _exit(70);
    if (!method && ![device respondsToSelector:selector]) return false;
    char result[8] = {0}, receiver[8] = {0}, command[8] = {0};
    if (!method || ![device respondsToSelector:selector] || method_getNumberOfArguments(method) != 2) _exit(70);
    method_getReturnType(method, result, sizeof(result));
    method_getArgumentType(method, 0, receiver, sizeof(receiver));
    method_getArgumentType(method, 1, command, sizeof(command));
    if (strcmp(receiver, "@") || strcmp(command, ":")) _exit(70);
    if (!strcmp(result, "B")) return ((bool (*)(id, SEL))objc_msgSend)(device, selector);
    if (!strcmp(result, "c")) return ((signed char (*)(id, SEL))objc_msgSend)(device, selector) != 0;
    _exit(70);
}
bool isRGBPixelFormat(uint64_t format) {
    const void *caller = __builtin_return_address(0);
    static const struct { uintptr_t rva; const char *selector; } routes[] = {
        {0x2a488, "supportsBufferWithAddressRanges"},
        {0x2a4ac, "supportsHeapWithAddressRanges"},
        {0x2a4d0, "supportsResourceDetachBacking"}
    };
    for (unsigned i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
        if (!VM27OwnedGPUTaskAdmitNativeCallerV1(caller, routes[i].rva))
            return NativeCapabilityV2((id)(uintptr_t)format, routes[i].selector);
    }
    RequireV1(caller, 0);
    return (format >= 45 && format <= 48) || (format >= 95 && format <= 100) ||
        (format >= 120 && format <= 122);
}
/* Read-only observation of the unchanged PGMemoryMapSegment decoder.
 * Native1190 loads the XPC object;1194 passes self+0x28;1198 calls map.
 * Its PhysLength at self+0x20 is therefore exactly outRegion-8. Other actual
 * native callers are forwarded without inspecting adjacent fields. */
size_t VM27OwnedGPUTaskShmemMapV1(xpc_object_t object, void **outRegion) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    RequireV1(caller, 0);
    bool exactDecoder = !VM27OwnedGPUTaskAdmitNativeCallerV1(caller, 0x119c);
    uint64_t expected = 0;
    bool expectedKnown = exactDecoder && outRegion;
    if (expectedKnown) memcpy(&expected, (const unsigned char *)outRegion - 8, sizeof(expected));
    errno = incomingErrno;
    size_t actual = xpc_shmem_map(object, outRegion);
    int nativeErrno = errno;
    if (exactDecoder) {
        static _Atomic(unsigned) emitted = 0;
        unsigned ordinal = atomic_load_explicit(&emitted, memory_order_relaxed);
        while (ordinal < 16 && !atomic_compare_exchange_weak_explicit(&emitted, &ordinal, ordinal + 1,
               memory_order_relaxed, memory_order_relaxed)) {}
        if (ordinal < 16) {
            bool mappedPtrKnown = actual > 0 && outRegion;
            void *mapped = mappedPtrKnown ? *outRegion : NULL;
            fprintf(stderr, "[Independent27GPU] native-shmem-map sample=%u callerRVA=0x119c expectedKnown=%d expected=0x%llx returned=0x%llx mappedPtrKnown=%d mapped=%p errnoObserved=%d errnoDefinedByAPI=0 nativeCalls=1\n",
                ordinal + 1, expectedKnown, (unsigned long long)expected,
                (unsigned long long)actual, mappedPtrKnown, mapped, nativeErrno);
        }
    }
    errno = nativeErrno;
    return actual;
}
/* The three exact native IOSurface allocation returns are 4d24c, 4e494,
 * and 4ea24. Managed=1 is unavailable on iOS. Only the genuine unified
 * device may use Shared; the copy preserves all other fields and options. */
static void RequireStorageMethodV4(id receiver, SEL selector, const char *result, unsigned count) {
    Method method = receiver ? class_getInstanceMethod(object_getClass(receiver), selector) : NULL;
    char encoded[64] = {0};
    if (!method || method_getNumberOfArguments(method) != count) _exit(70);
    method_getReturnType(method, encoded, sizeof(encoded));
    if (strcmp(encoded, result)) _exit(70);
    const char *types[] = {"@", ":", @encode(NSUInteger)};
    for (unsigned i = 0; i < count; ++i) {
        method_getArgumentType(method, i, encoded, sizeof(encoded));
        if (strcmp(encoded, types[i])) _exit(70);
    }
}
static NSUInteger StorageUIntV4(id descriptor, const char *name) {
    SEL selector = sel_registerName(name);
    RequireStorageMethodV4(descriptor, selector, @encode(NSUInteger), 2);
    return ((NSUInteger (*)(id, SEL))objc_msgSend)(descriptor, selector);
}
id VM27OwnedGPUTaskNewTextureIOSurfaceV1(id device, SEL ignored, id descriptor,
    IOSurfaceRef surface, NSUInteger plane) __attribute__((ns_returns_retained));
id VM27OwnedGPUTaskNewTextureIOSurfaceV1(id device, SEL ignored, id descriptor,
    IOSurfaceRef surface, NSUInteger plane) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    static const uintptr_t admittedReturns[] = {0x4d24c, 0x4e494, 0x4ea24};
    uintptr_t callerRVA = 0;
    for (unsigned i = 0; i < sizeof(admittedReturns) / sizeof(admittedReturns[0]); ++i) {
        if (!VM27OwnedGPUTaskAdmitNativeCallerV1(caller, admittedReturns[i])) {
            callerRVA = admittedReturns[i];
            break;
        }
    }
    if (!callerRVA) RequireV1(caller, 0x4ea24);
    (void)ignored; /* The former objc stub supplied SEL; the C stub preserves x0..x4. */
    NSUInteger requested = StorageUIntV4(descriptor, "storageMode");
    NSUInteger options = StorageUIntV4(descriptor, "resourceOptions");
    bool converted = requested == 1 && NativeCapabilityV2(device, "hasUnifiedMemory");
    id actualDescriptor = descriptor;
    if (converted) {
        actualDescriptor = [descriptor copy];
        if (!actualDescriptor) _exit(70);
        SEL storage = sel_registerName("setStorageMode:");
        RequireStorageMethodV4(actualDescriptor, storage, "v", 3);
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(actualDescriptor, storage, MTLStorageModeShared);
        if (StorageUIntV4(actualDescriptor, "storageMode") != MTLStorageModeShared ||
            StorageUIntV4(actualDescriptor, "resourceOptions") != (options & ~(NSUInteger)MTLResourceStorageModeMask)) _exit(70);
    }
    SEL selector = sel_registerName("newTextureWithDescriptor:iosurface:plane:");
    errno = incomingErrno;
    id texture = ((id (*)(id, SEL, id, IOSurfaceRef, NSUInteger))objc_msgSend)(device,
        selector, actualDescriptor, surface, plane);
    int nativeErrno = errno;
    if (converted) [actualDescriptor release];
    static _Atomic(unsigned) emitted = 0;
    unsigned ordinal = atomic_load_explicit(&emitted, memory_order_relaxed);
    while (ordinal < 16 && !atomic_compare_exchange_weak_explicit(&emitted, &ordinal, ordinal + 1,
           memory_order_relaxed, memory_order_relaxed)) {}
    if (ordinal < 16) fprintf(stderr, "[Independent27GPU] native-iosurface-texture sample=%u callerRVA=0x%lx requestedStorage=%lu actualStorage=%lu originalOptions=0x%lx managedToShared=%d nativeAllocationCalls=1 texture=%p\n",
        ordinal + 1, (unsigned long)callerRVA, (unsigned long)requested,
        (unsigned long)(converted ? MTLStorageModeShared : requested),
        (unsigned long)options, converted, texture);
    errno = nativeErrno;
    return texture; /* Native new... +1 is returned without another retain. */
}
/* Native newSamplerStateDescriptor allocates a fresh MTLSamplerDescriptor and
 * passes one validated NSUInteger at exact return44e9c. iOS26 added this
 * property; the historical filtering default is WeightedAverage=0. Only that
 * default can remain implicit on an older descriptor without the setter. */
void VM27OwnedGPUTaskSetSamplerReductionModeV1(id descriptor, SEL ignored, NSUInteger mode) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    RequireV1(caller, 0x44e9c);
    (void)ignored; /* Proper C stub preserves x0 and x2; reconstruct only SEL. */
    if (!descriptor || ![descriptor isKindOfClass:[MTLSamplerDescriptor class]]) _exit(70);
    SEL setter = sel_registerName("setReductionMode:");
    Method setterMethod = class_getInstanceMethod(object_getClass(descriptor), setter);
    bool hasSetter = [descriptor respondsToSelector:setter];
    if ((setterMethod != NULL) != hasSetter) _exit(70);
    if (hasSetter) RequireStorageMethodV4(descriptor, setter, "v", 3);
    SEL getter = sel_registerName("reductionMode");
    Method getterMethod = class_getInstanceMethod(object_getClass(descriptor), getter);
    bool hasGetter = [descriptor respondsToSelector:getter];
    if ((getterMethod != NULL) != hasGetter) _exit(70);
    bool observedDefault = false;
    NSUInteger actualMode = 0;
    if (!hasSetter && mode == 0 && hasGetter) {
        actualMode = StorageUIntV4(descriptor, "reductionMode");
        observedDefault = true;
    }
    bool retainsDefault = !hasSetter && mode == 0 && (!observedDefault || actualMode == 0);
    static _Atomic(unsigned) emitted = 0;
    unsigned ordinal = atomic_load_explicit(&emitted, memory_order_relaxed);
    while (ordinal < 16 && !atomic_compare_exchange_weak_explicit(&emitted, &ordinal, ordinal + 1,
           memory_order_relaxed, memory_order_relaxed)) {}
    if (ordinal < 16) fprintf(stderr, "[Independent27GPU] native-sampler-reduction sample=%u callerRVA=0x44e9c requestedMode=%lu nativeSetterPresent=%d nativeGetterPresent=%d actualGetterObserved=%d actualGetterMode=%lu defaultWeightedAverageRetained=%d nativeSetterCallsPlanned=%d\n",
        ordinal + 1, (unsigned long)mode, hasSetter, hasGetter, observedDefault,
        (unsigned long)actualMode, retainsDefault, hasSetter);
    errno = incomingErrno;
    if (hasSetter) {
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(descriptor, setter, mode);
        return; /* Original setter exceptions and actual errno propagate. */
    }
    if (retainsDefault) return; /* Genuine old native filtering default; no property is invented. */
    [NSException raise:NSInvalidArgumentException
        format:@"Independent27 native sampler reduction mode %lu is unsupported by this OS descriptor", (unsigned long)mode];
}
/* Observe only genuine failure outputs from two exact native PSO creators.
 * Diagnostic text is bounded; no descriptor, reflection or NSError slot is
 * rewritten. The original native new... result remains +1 without a retain. */
static void ErrorTextV6(NSString *text, char out[2049]) {
    out[0] = 0;
    if (!text) return;
    NSString *prefix = text.length > 512 ? [text substringToIndex:512] : text;
    if (![prefix getCString:out maxLength:2049 encoding:NSUTF8StringEncoding])
        snprintf(out, 2049, "<diagnostic text conversion unavailable>");
    for (char *at = out; *at; ++at) if (*at == '\n' || *at == '\r') *at = ' ';
}
/* Preserve the real ordered GPU signal. Only the first eight actual native
 * buffers receive extra native lifecycle callbacks. These observe real status,
 * error and shared-event counter; they never write an event or complete work. */
static void RequireSignalMethodV10(id receiver, const char *name, const char *result,
    const char *third, const char *fourth) {
    SEL selector = sel_registerName(name);
    Method method = receiver ? class_getInstanceMethod(object_getClass(receiver), selector) : NULL;
    unsigned count = fourth ? 4 : (third ? 3 : 2);
    char actual[64] = {0};
    if (!method || ![receiver respondsToSelector:selector] || method_getNumberOfArguments(method) != count) _exit(70);
    method_getReturnType(method, actual, sizeof(actual));
    if (strcmp(actual, result)) _exit(70);
    const char *expected[] = {"@", ":", third, fourth};
    for (unsigned i = 0; i < count; ++i) {
        method_getArgumentType(method, i, actual, sizeof(actual));
        if (strcmp(actual, expected[i])) _exit(70);
    }
}
static __attribute__((noinline)) void ObserveSignalBufferV10(const char *stage,
    unsigned sample, id buffer, uintptr_t expectedBuffer, id event, uint64_t requested) {
    int savedErrno = errno;
    @try {
        NSUInteger status = ((NSUInteger (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("status"));
        NSError *error = ((id (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("error"));
        uint64_t actualValue = ((uint64_t (*)(id, SEL))objc_msgSend)(event, sel_registerName("signaledValue"));
        char domain[2049], message[2049];
        ErrorTextV6(error.domain, domain);
        ErrorTextV6(error.localizedDescription, message);
        fprintf(stderr, "[Independent27GPU] actual-command-buffer sample=%u stage=%s pid=%d callerRVA=0x2d43c buffer=%p callbackBufferMatches=%d event=%p requestedValue=%llu actualSignaledValue=%llu status=%lu actualNSError=%p errorDomain=%s errorCode=%ld errorDescription=%s eventWrites=0 originalCommitUnchanged=1\n",
            sample, stage, (int)getpid(), buffer, (uintptr_t)buffer == expectedBuffer,
            event, (unsigned long long)requested, (unsigned long long)actualValue,
            (unsigned long)status, error, domain, (long)error.code, message);
    } @catch (NSException *exception) {
        (void)exception;
        fprintf(stderr, "[Independent27GPU] actual-command-buffer sample=%u stage=%s pid=%d observationException=1 nativeSignalAndCompletionUnchanged=1 eventWrites=0\n",
            sample, stage, (int)getpid());
    }
    errno = savedErrno;
}
void VM27OwnedGPUTaskObserveSignalEventV1(id buffer, SEL ignored, id event, uint64_t value) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    RequireV1(caller, 0x2d43c);
    (void)ignored; /* Proper four-argument C stub preserves x0, x2 and x3. */
    RequireSignalMethodV10(buffer, "encodeSignalEvent:value:", "v", "@", @encode(uint64_t));
    static _Atomic(unsigned) admitted = 0;
    unsigned ordinal = atomic_load_explicit(&admitted, memory_order_relaxed);
    while (ordinal < 8 && !atomic_compare_exchange_weak_explicit(&admitted, &ordinal, ordinal + 1,
           memory_order_relaxed, memory_order_relaxed)) {}
    bool observe = ordinal < 8;
    if (observe) {
        RequireSignalMethodV10(buffer, "addScheduledHandler:", "v", "@?", NULL);
        RequireSignalMethodV10(buffer, "addCompletedHandler:", "v", "@?", NULL);
        RequireSignalMethodV10(buffer, "status", @encode(NSUInteger), NULL, NULL);
        RequireSignalMethodV10(buffer, "error", "@", NULL, NULL);
        RequireSignalMethodV10(event, "signaledValue", @encode(uint64_t), NULL, NULL);
        unsigned sample = ordinal + 1;
        uintptr_t expectedBuffer = (uintptr_t)buffer; /* Avoid a command-buffer retain cycle. */
        ObserveSignalBufferV10("before-encode", sample, buffer, expectedBuffer, event, value);
        ((void (*)(id, SEL, MTLCommandBufferHandler))objc_msgSend)(buffer,
            sel_registerName("addScheduledHandler:"), ^(id<MTLCommandBuffer> actualBuffer) {
                ObserveSignalBufferV10("scheduled", sample, actualBuffer, expectedBuffer, event, value);
            });
        ((void (*)(id, SEL, MTLCommandBufferHandler))objc_msgSend)(buffer,
            sel_registerName("addCompletedHandler:"), ^(id<MTLCommandBuffer> actualBuffer) {
                ObserveSignalBufferV10("completed", sample, actualBuffer, expectedBuffer, event, value);
            });
    }
    errno = incomingErrno;
    ((void (*)(id, SEL, id, uint64_t))objc_msgSend)(buffer,
        sel_registerName("encodeSignalEvent:value:"), event, value);
    int nativeErrno = errno;
    if (observe) ObserveSignalBufferV10("after-encode", ordinal + 1, buffer, (uintptr_t)buffer, event, value);
    errno = nativeErrno;
}
/* Keep large diagnostic buffers outside the exact-caller adapter. Its caller
 * capture must precede any compiler-emitted stack-probe call. */
static __attribute__((noinline)) void ObserveRenderPipelineFailureV7(
    bool ordinary, NSUInteger options, NSError **error) {
    static _Atomic(unsigned) emitted = 0;
    unsigned ordinal = atomic_load_explicit(&emitted, memory_order_relaxed);
    while (ordinal < 8 && !atomic_compare_exchange_weak_explicit(&emitted, &ordinal, ordinal + 1,
           memory_order_relaxed, memory_order_relaxed)) {}
    if (ordinal < 8) {
        @try {
            NSError *actualError = error ? *error : nil;
            char domain[2049], message[2049], info[2049], underlying[2049];
            ErrorTextV6(actualError.domain, domain);
            ErrorTextV6(actualError.localizedDescription, message);
            ErrorTextV6(actualError.userInfo.description, info);
            id underlyingError = [actualError.userInfo objectForKey:NSUnderlyingErrorKey];
            ErrorTextV6([underlyingError description], underlying);
            fprintf(stderr, "[Independent27GPU] actual-rps-failure sample=%u callerRVA=0x%lx tile=%d options=0x%lx nativeCalls=1 result=nil errorPointerPresent=%d actualNSError=%p domain=%s code=%ld description=%s userInfo=%s underlying=%s\n",
                ordinal + 1, (unsigned long)(ordinary ? 0x41114 : 0x41b08), !ordinary,
                (unsigned long)options, error != NULL, actualError, domain, (long)actualError.code,
                message, info, underlying);
        } @catch (NSException *diagnosticException) {
            (void)diagnosticException;
            fprintf(stderr, "[Independent27GPU] actual-rps-failure sample=%u diagnosticException=1 nativeResultAndErrorUnchanged=1\n", ordinal + 1);
        }
    }
}
id VM27OwnedGPUTaskCreateRenderPipelineV1(id device, SEL ignored, id descriptor,
    NSUInteger options, MTLRenderPipelineReflection **reflection, NSError **error)
    __attribute__((ns_returns_retained));
id VM27OwnedGPUTaskCreateRenderPipelineV1(id device, SEL ignored, id descriptor,
    NSUInteger options, MTLRenderPipelineReflection **reflection, NSError **error) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    bool ordinary = !VM27OwnedGPUTaskAdmitNativeCallerV1(caller, 0x41114);
    if (!ordinary) RequireV1(caller, 0x41b08);
    (void)ignored; /* Fresh authenticated C stub leaves x0..x5 unchanged. */
    SEL selector = sel_registerName(ordinary ?
        "newRenderPipelineStateWithDescriptor:options:reflection:error:" :
        "newRenderPipelineStateWithTileDescriptor:options:reflection:error:");
    errno = incomingErrno;
    id pipeline = ((id (*)(id, SEL, id, NSUInteger, MTLRenderPipelineReflection **, NSError **))objc_msgSend)(
        device, selector, descriptor, options, reflection, error);
    int nativeErrno = errno;
    if (!pipeline) ObserveRenderPipelineFailureV7(ordinary, options, error);
    errno = nativeErrno;
    return pipeline;
}
static bool SameFileV1(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int CopyMetallibV1(void **out, size_t *size) {
    *out = NULL; *size = 0;
    const VM27OwnedGPUTaskServerProfileV1 *p = &VM27OwnedGPUTaskPinnedServerProfileV1;
    if (!p->canonicalDefaultMetallibPath || !p->defaultMetallibSHA256 || strlen(p->defaultMetallibSHA256) != 64 ||
        !p->defaultMetallibBytes || p->defaultMetallibBytes > 1024U * 1024U) return EINVAL;
    int fd = open(p->canonicalDefaultMetallibPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return errno;
    struct stat before = {0}, after = {0}, named = {0};
    int status = fstat(fd, &before) ? errno : 0;
    if (!status && (!S_ISREG(before.st_mode) || before.st_uid != p->ownerUID || before.st_nlink != 1 ||
        (before.st_mode & 0022) || before.st_size <= 0 || (uint64_t)before.st_size != p->defaultMetallibBytes)) status = EACCES;
    void *bytes = !status ? malloc((size_t)before.st_size) : NULL;
    if (!status && !bytes) status = ENOMEM;
    size_t at = 0;
    while (!status && at < (size_t)before.st_size) {
        ssize_t n = pread(fd, (char *)bytes + at, (size_t)before.st_size - at, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) status = n < 0 ? errno : EIO;
        else at += (size_t)n;
    }
    if (!status && (fstat(fd, &after) || lstat(p->canonicalDefaultMetallibPath, &named))) status = errno;
    if (!status && (!SameFileV1(&before, &after) || !SameFileV1(&before, &named))) status = ESTALE;
    if (close(fd) && !status) status = errno;
    if (!status) {
        uint8_t digest[CC_SHA256_DIGEST_LENGTH]; char hex[65]; static const char digits[] = "0123456789abcdef";
        CC_SHA256(bytes, (CC_LONG)at, digest);
        for (unsigned i = 0; i < sizeof(digest); ++i) { hex[i * 2] = digits[digest[i] >> 4]; hex[i * 2 + 1] = digits[digest[i] & 15]; }
        hex[64] = 0; if (strcmp(hex, p->defaultMetallibSHA256)) status = EACCES;
    }
    if (status) free(bytes); else { *out = bytes; *size = at; }
    return status;
}
/* Only Apple's actual setupBlitPipelines call at2a6ac is rebound. The native
 * returned +1 library and actual NSError are preserved; its two subsequent
 * newFunctionWithName and compute-pipeline calls remain entirely native. */
id VM27OwnedGPUTaskDefaultLibraryV1(id device, SEL originalSelector, id macBundle, NSError **error)
    __attribute__((ns_returns_retained));
id VM27OwnedGPUTaskDefaultLibraryV1(id device, SEL originalSelector, id macBundle, NSError **error) {
    RequireV1(__builtin_return_address(0), 0x2a6b0);
    if (originalSelector != sel_registerName("newDefaultLibraryWithBundle:error:")) _exit(70);
    (void)macBundle; /* The exact native call's hardcoded macOS bundle is unavailable on iPad. */
    void *bytes = NULL; size_t size = 0;
    int status = CopyMetallibV1(&bytes, &size);
    if (status) {
        fprintf(stderr, "[Independent27GPU] actual-default-metallib read rejected status=%d\n", status);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:status userInfo:nil];
        return nil;
    }
    dispatch_data_t data = dispatch_data_create(bytes, size,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ free(bytes); });
    if (!data) { free(bytes); if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOMEM userInfo:nil]; return nil; }
    id library = ((id (*)(id, SEL, dispatch_data_t, NSError **))objc_msgSend)(device,
        sel_registerName("newLibraryWithData:error:"), data, error);
    dispatch_release(data);
    fprintf(stderr, "[Independent27GPU] actual-default-metallib bytes=%zu nativeLibrary=%p customShaderCompiler=0\n", size, library);
    return library;
}
