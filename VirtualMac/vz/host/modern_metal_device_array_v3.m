// Preserve the frozen Metal owned-array implementation and its native gate.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
#include "modern_metal_device_array.m"
#pragma clang diagnostic pop
#include "vm27_owned_pvg_buffer_capability_v1.h"
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char PVGChildPathV1[] = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static const char PVGImagePathV1[] = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/ParavirtualizedGraphics27.dylib";
static const uint8_t PVGChildUUIDV1[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
static const uint8_t PVGImageUUIDV1[16] = {0x9e,0x6a,0x66,0x7a,0xa7,0x75,0x32,0xde,0x8d,0xd5,0x68,0x72,0xef,0x6a,0x53,0xd9};
static unsigned PVGCapabilityLogCountV1;
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

static BOOL PVGCapabilityScopeV1(void *caller, uintptr_t *callerRVA) {
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
    return *callerRVA == UINT64_C(0x2108c) || *callerRVA == UINT64_C(0x31fb0);
}


static BOOL PVGCapabilityLogV1(void) {
    unsigned count = __atomic_load_n(&PVGCapabilityLogCountV1, __ATOMIC_RELAXED);
    while (count < 8) if (__atomic_compare_exchange_n(&PVGCapabilityLogCountV1,
        &count, count+1, NO, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) return YES;
    return NO;
}

__attribute__((visibility("default")))
BOOL VM27OwnedPVGSupportsBufferAddressRangesV1(id device, SEL selector) {
    int incomingErrno = errno;
    uintptr_t callerRVA = 0;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    if (!selector || strcmp(sel_getName(selector), "supportsBufferWithAddressRanges") ||
        !PVGCapabilityScopeV1(caller, &callerRVA)) {
        dprintf(2,"[VM27OwnedPVGCapabilityV1] admission=0 nativeCalled=0 resultNotClaimed=1\n");
        errno = ENOTSUP; __builtin_trap();
    }
    Class receiverClass = object_getClass(device);
    Method method = receiverClass ? class_getInstanceMethod(receiverClass, selector) : NULL;
    BOOL log = PVGCapabilityLogV1();
    if (!method) {
        if (log) dprintf(2,"[VM27OwnedPVGCapabilityV1] callerRVA=0x%lx deviceClass=%s nativeMethodMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",
            (unsigned long)callerRVA, receiverClass ? class_getName(receiverClass) : "(nil)");
        errno = incomingErrno; return NO;
    }
    char returned[16]={0}, self[16]={0}, command[16]={0};
    method_getReturnType(method,returned,sizeof(returned));
    method_getArgumentType(method,0,self,sizeof(self));
    method_getArgumentType(method,1,command,sizeof(command));
    if (method_getNumberOfArguments(method)!=2 || strcmp(returned,@encode(BOOL)) ||
        strcmp(self,"@") || strcmp(command,":")) {
        if (log) dprintf(2,"[VM27OwnedPVGCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=0 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    IMP original = method_getImplementation(method);
    if (!original) {
        if (log) dprintf(2,"[VM27OwnedPVGCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 implementationMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    /* A real native BOOL getter is invoked once with the original self/SEL.
     * No object is fabricated and no address-range buffer is created here. */
    typedef BOOL (*PVGNativeCapabilityV1)(id,SEL);
    errno = incomingErrno;
    BOOL result = ((PVGNativeCapabilityV1)original)(device,selector);
    int nativeErrno = errno;
    if (log) dprintf(2,"[VM27OwnedPVGCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=1 nativeCalledOnce=1 returned=%u\n",(unsigned long)callerRVA,result?1U:0U);
    errno = nativeErrno; return result;
}
