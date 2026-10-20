// Preserve the frozen Metal owned-array implementation and its native gate.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
#include "modern_metal_device_array.m"
#pragma clang diagnostic pop
#include "vm27_owned_pvg_pipeline_diagnostic_v1.h"
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char PVGChildPathV1[] = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static const char PVGImagePathV1[] = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/ParavirtualizedGraphics27.dylib";
static const uint8_t PVGChildUUIDV1[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
static const uint8_t PVGImageUUIDV1[16] = {0x9e,0x6a,0x66,0x7a,0xa7,0x75,0x32,0xde,0x8d,0xd5,0x68,0x72,0xef,0x6a,0x53,0xd9};
static unsigned PVGDiagnosticCountV1;
extern int csops(pid_t, unsigned int, void *, size_t);
extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

static BOOL PVGSelfReadV1(const void *address, size_t count, void *out) {
    if (!address || !out || !count || count > 65536 ||
        (uintptr_t)address > UINTPTR_MAX-count) return NO;
    mach_vm_size_t actual = 0;
    return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)address,
        count, (mach_vm_address_t)out, &actual) == KERN_SUCCESS && actual == count;
}

static BOOL PVGReadUUIDV1(const void *base, uint32_t type, uint8_t out[16]) {
    struct mach_header_64 header = {0};
    if (!PVGSelfReadV1(base, sizeof(header), &header) || header.magic != MH_MAGIC_64 ||
        (type && header.filetype != type) || !header.ncmds || header.ncmds > 2048 ||
        header.sizeofcmds > 65536) return NO;
    size_t offset = 0; unsigned count = 0;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        struct load_command command = {0};
        if (offset > header.sizeofcmds || sizeof(command) > header.sizeofcmds-offset ||
            !PVGSelfReadV1((const uint8_t *)base+sizeof(header)+offset, sizeof(command), &command) ||
            command.cmdsize < 8 || (command.cmdsize & 7) || command.cmdsize > header.sizeofcmds-offset) return NO;
        if (command.cmd == LC_UUID) {
            if (command.cmdsize != sizeof(struct uuid_command) || ++count != 1 ||
                !PVGSelfReadV1((const uint8_t *)base+sizeof(header)+offset+8, 16, out)) return NO;
        }
        offset += command.cmdsize;
    }
    return count == 1 && offset == header.sizeofcmds;
}

static BOOL PVGDiagnosticScopeV1(void *caller, uintptr_t *callerRVA) {
    uint32_t status = 0; uint8_t uuid[16];
    if (getuid() != 501 || geteuid() != 501 || getpid() <= 1 ||
        csops(getpid(), 0, &status, sizeof(status)) ||
        (status & UINT32_C(0x04000001)) != UINT32_C(0x04000001) ||
        !vm27_metal_device_array_profile_matches()) return NO;
    char path[4096] = {0}, canonical[4096] = {0}; uint32_t capacity = sizeof(path);
    if (_NSGetExecutablePath(path, &capacity) || capacity > sizeof(path) ||
        !memchr(path, 0, sizeof(path)) || !realpath(path, canonical) || strcmp(canonical, PVGChildPathV1)) return NO;
    unsigned mainCount = 0; uint32_t images = _dyld_image_count();
    if (!images || images > 4096) return NO;
    for (uint32_t i = 0; i < images; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name || strcmp(name, PVGChildPathV1)) continue;
        if (++mainCount != 1 || !PVGReadUUIDV1(_dyld_get_image_header(i), MH_EXECUTE, uuid) ||
            memcmp(uuid, PVGChildUUIDV1, 16)) return NO;
    }
    Dl_info owner = {0};
    if (mainCount != 1 || !caller || !dladdr(caller, &owner) || !owner.dli_fname ||
        strcmp(owner.dli_fname, PVGImagePathV1) || !PVGReadUUIDV1(owner.dli_fbase, MH_DYLIB, uuid) ||
        memcmp(uuid, PVGImageUUIDV1, 16) || (uintptr_t)caller < (uintptr_t)owner.dli_fbase) return NO;
    *callerRVA = (uintptr_t)caller-(uintptr_t)owner.dli_fbase;
    return *callerRVA == UINT64_C(0x21508) || *callerRVA == UINT64_C(0x21534);
}

static BOOL PVGAdmitDiagnosticV1(void) {
    unsigned count = __atomic_load_n(&PVGDiagnosticCountV1, __ATOMIC_RELAXED);
    while (count < 4) {
        if (__atomic_compare_exchange_n(&PVGDiagnosticCountV1, &count, count+1,
            NO, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) return YES;
    }
    return NO;
}

/* Bounded, one-line real descriptions. A diagnostic exception never replaces
 * the original native result, original NSError output, or native errno. */
static void PVGDescribeV1(id object, char out[769]) {
    out[0] = 0;
    @try {
        NSData *data = [[object description] dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
        NSUInteger count = MIN(data.length, (NSUInteger)768);
        if (count) memcpy(out, data.bytes, count);
        out[count] = 0;
        for (NSUInteger i = 0; i < count; ++i)
            if ((unsigned char)out[i] < 32 || out[i] == 127) out[i] = ' ';
    } @catch (NSException *exception) {
        (void)exception; strcpy(out, "(diagnostic-description-exception)");
    }
}

/* No swizzle, fake function, shader fallback, native retry, or error rewrite.
 * Resolve the very implementation selected for the original real device;
 * call it once using the SDK's four-argument ObjC ABI and +1 new-family result. */
__attribute__((visibility("default"), ns_returns_retained))
id VM27OwnedPVGNewComputePipelineStateWithFunctionV1(id device, SEL selector,
    id function, NSError * __autoreleasing *error) {
    int incomingErrno = errno;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    uintptr_t callerRVA = 0;
    BOOL traced = selector && sel_isEqual(selector, @selector(newComputePipelineStateWithFunction:error:)) &&
        PVGDiagnosticScopeV1(caller, &callerRVA) && PVGAdmitDiagnosticV1();
    Class deviceClass = object_getClass(device);
    IMP original = deviceClass ? class_getMethodImplementation(deviceClass, selector) : (IMP)objc_msgSend;
    if (!original) original = (IMP)objc_msgSend;
    Dl_info native = {0}; uint8_t nativeUUID[16] = {0}; BOOL nativeUUIDRead = NO;
    if (traced) {
        void *entry = ptrauth_strip((void *)original, ptrauth_key_function_pointer);
        if (dladdr(entry, &native) && native.dli_fbase) nativeUUIDRead = PVGReadUUIDV1(native.dli_fbase, 0, nativeUUID);
        dprintf(2, "[VM27OwnedPVGPipelineV1] phase=enter callerRVA=0x%lx device=%p deviceClass=%s function=%p functionNil=%u originalIMP=%p nativeImage=%s nativeUUIDRead=%u nativeUUID=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x nativeRVA=0x%lx\n",
            (unsigned long)callerRVA, device, deviceClass ? class_getName(deviceClass) : "(nil)",
            function, function ? 0U : 1U, entry, native.dli_fname ? native.dli_fname : "(none)",
            nativeUUIDRead ? 1U : 0U, nativeUUID[0],nativeUUID[1],nativeUUID[2],nativeUUID[3],nativeUUID[4],nativeUUID[5],nativeUUID[6],nativeUUID[7],nativeUUID[8],nativeUUID[9],nativeUUID[10],nativeUUID[11],nativeUUID[12],nativeUUID[13],nativeUUID[14],nativeUUID[15],
            (unsigned long)(native.dli_fbase ? (uintptr_t)entry-(uintptr_t)native.dli_fbase : 0));
    }
    typedef id (*PVGNativePipelineV1)(id, SEL, id, NSError * __autoreleasing *) __attribute__((ns_returns_retained));
    errno = incomingErrno;
    id result = ((PVGNativePipelineV1)original)(device, selector, function, error);
    int nativeErrno = errno;
    if (traced) {
        @try {
            NSError *actualError = error ? *error : nil;
            char name[769], domain[769], detail[769], debug[769], info[769], underlying[769];
            PVGDescribeV1(function ? [function name] : nil, name);
            PVGDescribeV1(actualError.domain, domain);
            PVGDescribeV1(actualError.localizedDescription, detail);
            PVGDescribeV1(actualError.debugDescription, debug);
            PVGDescribeV1(actualError.userInfo, info);
            PVGDescribeV1(actualError.userInfo[NSUnderlyingErrorKey], underlying);
            dprintf(2, "[VM27OwnedPVGPipelineV1] phase=return callerRVA=0x%lx result=%p function=%p functionName=%s error=%p errorDomain=%s errorCode=%ld description=%s debug=%s userInfo=%s underlying=%s nativeErrno=%d nativeCalledOnce=1 retainedNewResultUnmodified=1\n",
                (unsigned long)callerRVA, result, function, name, actualError, domain,
                (long)actualError.code, detail, debug, info, underlying, nativeErrno);
        } @catch (NSException *exception) {
            (void)exception;
            dprintf(2, "[VM27OwnedPVGPipelineV1] phase=return callerRVA=0x%lx result=%p diagnosticException=1 nativeErrno=%d nativeCalledOnce=1 retainedNewResultUnmodified=1\n", (unsigned long)callerRVA, result, nativeErrno);
        }
    }
    errno = nativeErrno;
    return result;
}
