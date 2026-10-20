/* Fresh narrow native task backports. No old transport, shader compiler,
 * feature advertisement, GPU work or completion response is copied here. */
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include "vm27_owned_gpu_task_transport_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
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
