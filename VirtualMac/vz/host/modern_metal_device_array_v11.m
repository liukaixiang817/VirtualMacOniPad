// Preserve the frozen Metal owned-array implementation and its native gate.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
#include "modern_metal_device_array.m"
#pragma clang diagnostic pop
#include "vm27_owned_pvg_unified_storage_v1.h"
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

static BOOL PVGCapabilityScopeV3(void *caller, uintptr_t *callerRVA, unsigned capability) {
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
    if (capability == 7) return *callerRVA == UINT64_C(0xd82c);
    if (capability == 3) return *callerRVA == 0x3248c || *callerRVA == 0x41bec || *callerRVA == 0x41c28 || *callerRVA == 0x41c54;
    if (capability == 6) return *callerRVA == 0x41c6c || *callerRVA == 0x42f70 || *callerRVA == 0x42898;
    return capability == 2 ? (*callerRVA == UINT64_C(0x21110) || *callerRVA == UINT64_C(0x2d0b0) || *callerRVA == UINT64_C(0x31fa4)) :
        capability == 1 ? (*callerRVA == UINT64_C(0x21098) || *callerRVA == UINT64_C(0x2d0bc)) :
        (*callerRVA == UINT64_C(0x2108c) || *callerRVA == UINT64_C(0x31fb0));
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
        !PVGCapabilityScopeV3(caller, &callerRVA, 0)) {
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

__attribute__((visibility("default")))
BOOL VM27OwnedPVGSupportsHeapAddressRangesV1(id device, SEL selector) {
    int incomingErrno = errno;
    uintptr_t callerRVA = 0;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    if (!selector || strcmp(sel_getName(selector), "supportsHeapWithAddressRanges") ||
        !PVGCapabilityScopeV3(caller, &callerRVA, 1)) {
        dprintf(2,"[VM27OwnedPVGHeapCapabilityV1] admission=0 nativeCalled=0 resultNotClaimed=1\n");
        errno = ENOTSUP; __builtin_trap();
    }
    Class receiverClass = object_getClass(device);
    Method method = receiverClass ? class_getInstanceMethod(receiverClass, selector) : NULL;
    BOOL log = PVGCapabilityLogV1();
    if (!method) {
        if (log) dprintf(2,"[VM27OwnedPVGHeapCapabilityV1] callerRVA=0x%lx deviceClass=%s nativeMethodMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",
            (unsigned long)callerRVA, receiverClass ? class_getName(receiverClass) : "(nil)");
        errno = incomingErrno; return NO;
    }
    char returned[16]={0}, self[16]={0}, command[16]={0};
    method_getReturnType(method,returned,sizeof(returned));
    method_getArgumentType(method,0,self,sizeof(self));
    method_getArgumentType(method,1,command,sizeof(command));
    if (method_getNumberOfArguments(method)!=2 || strcmp(returned,@encode(BOOL)) ||
        strcmp(self,"@") || strcmp(command,":")) {
        if (log) dprintf(2,"[VM27OwnedPVGHeapCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=0 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    IMP original = method_getImplementation(method);
    if (!original) {
        if (log) dprintf(2,"[VM27OwnedPVGHeapCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 implementationMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    /* A real native BOOL getter is invoked once with the original self/SEL.
     * No object is fabricated and no address-range buffer is created here. */
    typedef BOOL (*PVGNativeCapabilityV1)(id,SEL);
    errno = incomingErrno;
    BOOL result = ((PVGNativeCapabilityV1)original)(device,selector);
    int nativeErrno = errno;
    if (log) dprintf(2,"[VM27OwnedPVGHeapCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=1 nativeCalledOnce=1 returned=%u\n",(unsigned long)callerRVA,result?1U:0U);
    errno = nativeErrno; return result;
}

__attribute__((visibility("default")))
BOOL VM27OwnedPVGSupportsResourceDetachBackingV1(id device, SEL selector) {
    int incomingErrno = errno;
    uintptr_t callerRVA = 0;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    if (!selector || strcmp(sel_getName(selector), "supportsResourceDetachBacking") ||
        !PVGCapabilityScopeV3(caller, &callerRVA, 2)) {
        dprintf(2,"[VM27OwnedPVGDetachCapabilityV1] admission=0 nativeCalled=0 resultNotClaimed=1\n");
        errno = ENOTSUP; __builtin_trap();
    }
    Class receiverClass = object_getClass(device);
    Method method = receiverClass ? class_getInstanceMethod(receiverClass, selector) : NULL;
    BOOL log = PVGCapabilityLogV1();
    if (!method) {
        if (log) dprintf(2,"[VM27OwnedPVGDetachCapabilityV1] callerRVA=0x%lx deviceClass=%s nativeMethodMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",
            (unsigned long)callerRVA, receiverClass ? class_getName(receiverClass) : "(nil)");
        errno = incomingErrno; return NO;
    }
    char returned[16]={0}, self[16]={0}, command[16]={0};
    method_getReturnType(method,returned,sizeof(returned));
    method_getArgumentType(method,0,self,sizeof(self));
    method_getArgumentType(method,1,command,sizeof(command));
    if (method_getNumberOfArguments(method)!=2 || strcmp(returned,@encode(BOOL)) ||
        strcmp(self,"@") || strcmp(command,":")) {
        if (log) dprintf(2,"[VM27OwnedPVGDetachCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=0 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    IMP original = method_getImplementation(method);
    if (!original) {
        if (log) dprintf(2,"[VM27OwnedPVGDetachCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 implementationMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    /* A real native BOOL getter is invoked once with the original self/SEL.
     * No object is fabricated and no address-range buffer is created here. */
    typedef BOOL (*PVGNativeCapabilityV1)(id,SEL);
    errno = incomingErrno;
    BOOL result = ((PVGNativeCapabilityV1)original)(device,selector);
    int nativeErrno = errno;
    if (log) dprintf(2,"[VM27OwnedPVGDetachCapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=1 nativeCalledOnce=1 returned=%u\n",(unsigned long)callerRVA,result?1U:0U);
    errno = nativeErrno; return result;
}

/* iOS has no Managed storage. Only original PVG resource calls on a real
 * unified-memory device replace the Managed storage nibble with Shared.
 * Native resources, lengths, offsets, cache/hazard bits and +1 ownership remain
 * genuine. No Apple method is added or replaced globally. */
static unsigned PVGStorageLogCountV1;
static void PVGStorageRejectV1(const char *stage) {
    dprintf(2,"[VM27OwnedPVGStorageV1] admission=0 stage=%s nativeResourceNotClaimed=1\n",stage);
    errno=ENOTSUP; __builtin_trap();
}
static IMP PVGStorageMethodV1(id receiver, SEL selector, const char *result,
    unsigned count, const char *const *arguments) {
    Method m=receiver ? class_getInstanceMethod(object_getClass(receiver),selector) : NULL;
    char encoded[128]={0};
    if (!m || method_getNumberOfArguments(m)!=count) PVGStorageRejectV1("method-arguments");
    method_getReturnType(m,encoded,sizeof(encoded));
    if (strcmp(encoded,result)) PVGStorageRejectV1("method-return");
    for (unsigned i=0;i<count;++i) {
        memset(encoded,0,sizeof(encoded)); method_getArgumentType(m,i,encoded,sizeof(encoded));
        if (strcmp(encoded,arguments[i])) PVGStorageRejectV1("method-argument-type");
    }
    IMP imp=method_getImplementation(m);
    if (!imp) PVGStorageRejectV1("method-implementation");
    return imp;
}
static BOOL PVGStorageUnifiedV1(id device) {
    SEL sel=@selector(hasUnifiedMemory);
    const char *args[]={"@",":"};
    IMP imp=PVGStorageMethodV1(device,sel,@encode(BOOL),2,args);
    return ((BOOL(*)(id,SEL))imp)(device,sel);
}
static id PVGStorageDeviceV1(id resource) {
    SEL sel=@selector(device); const char *args[]={"@",":"};
    return ((id(*)(id,SEL))PVGStorageMethodV1(resource,sel,"@",2,args))(resource,sel);
}
static NSUInteger PVGStorageModeV1(id resource) {
    SEL sel=@selector(storageMode); const char *args[]={"@",":"};
    return ((NSUInteger(*)(id,SEL))PVGStorageMethodV1(resource,sel,@encode(NSUInteger),2,args))(resource,sel);
}
static BOOL PVGStorageLogV1(void) {
    unsigned n=__atomic_load_n(&PVGStorageLogCountV1,__ATOMIC_RELAXED);
    while(n<16) if(__atomic_compare_exchange_n(&PVGStorageLogCountV1,&n,n+1,NO,__ATOMIC_RELAXED,__ATOMIC_RELAXED))return YES;
    return NO;
}
static MTLResourceOptions PVGStorageOptionsV1(id device, MTLResourceOptions options, BOOL *converted) {
    /* Numeric Managed=1 is deliberately used: the iOS SDK marks its enum
     * unavailable, and only its actual original 1<<4 storage bits are removed. */
    *converted=(options & MTLResourceStorageModeMask)==(UINT64_C(1)<<MTLResourceStorageModeShift) && PVGStorageUnifiedV1(device);
    return *converted ? (options & ~((MTLResourceOptions)MTLResourceStorageModeMask)) : options;
}
static uintptr_t PVGStorageAdmitV1(void *caller, SEL sel, const char *name, unsigned scope) {
    uintptr_t rva=0;
    if(!sel || strcmp(sel_getName(sel),name) || !PVGCapabilityScopeV3(caller,&rva,scope))PVGStorageRejectV1("caller-selector");
    return rva;
}
__attribute__((visibility("default"),ns_returns_retained))
id VM27OwnedPVGNewBufferWithLengthOptionsV1(id device,SEL sel,NSUInteger length,MTLResourceOptions options) {
    int incoming=errno; void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    uintptr_t rva=PVGStorageAdmitV1(caller,sel,"newBufferWithLength:options:",3);
    const char *args[]={"@",":",@encode(NSUInteger),@encode(MTLResourceOptions)};
    IMP imp=PVGStorageMethodV1(device,sel,"@",4,args); BOOL converted=NO;
    MTLResourceOptions actual=PVGStorageOptionsV1(device,options,&converted);
    errno=incoming; id result=((id(*)(id,SEL,NSUInteger,MTLResourceOptions))imp)(device,sel,length,actual);
    int nativeErrno=errno;
    if(PVGStorageLogV1())dprintf(2,"[VM27OwnedPVGStorageV1] callerRVA=0x%lx operation=buffer requestedOptions=0x%lx actualOptions=0x%lx managedToShared=%u nativeCalledOnce=1 actualResource=%p\n",(unsigned long)rva,(unsigned long)options,(unsigned long)actual,converted?1U:0U,result);
    errno=nativeErrno; return result;
}
__attribute__((visibility("default")))
void VM27OwnedPVGDidModifyManagedRangeV1(id buffer,SEL sel,NSRange range) {
    int incoming=errno; void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    uintptr_t rva=PVGStorageAdmitV1(caller,sel,"didModifyRange:",6);
    if(PVGStorageModeV1(buffer)==MTLStorageModeShared && PVGStorageUnifiedV1(PVGStorageDeviceV1(buffer))) {
        SEL lengthSEL=@selector(length); const char *args[]={"@",":"};
        NSUInteger length=((NSUInteger(*)(id,SEL))PVGStorageMethodV1(buffer,lengthSEL,@encode(NSUInteger),2,args))(buffer,lengthSEL);
        /* Only the original 96-byte color/gamma buffer and exact original
         * range. Shared memory requires no managed CPU-to-GPU copy. The
         * original command-buffer submission/completion stays untouched. */
        if(length!=0x60 || range.location!=0 || range.length!=0x60)PVGStorageRejectV1("shared-range");
        if(PVGStorageLogV1())dprintf(2,"[VM27OwnedPVGStorageV1] callerRVA=0x%lx operation=did-modify sharedUnified=1 managedSynchronizationRequired=0 nativeCalled=0 length=%lu\n",(unsigned long)rva,(unsigned long)length);
        errno=incoming; return;
    }
    const char *args[]={"@",":",@encode(NSRange)};
    IMP imp=PVGStorageMethodV1(buffer,sel,"v",3,args);
    errno=incoming; ((void(*)(id,SEL,NSRange))imp)(buffer,sel,range);
}

__attribute__((visibility("default")))
BOOL VM27OwnedPVGIsDepth24Stencil8PixelFormatSupportedV1(id device, SEL selector) {
    int incomingErrno = errno;
    uintptr_t callerRVA = 0;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    if (!selector || strcmp(sel_getName(selector), "isDepth24Stencil8PixelFormatSupported") ||
        !PVGCapabilityScopeV3(caller, &callerRVA, 7)) {
        dprintf(2,"[VM27OwnedPVGDepth24CapabilityV1] admission=0 nativeCalled=0 resultNotClaimed=1\n");
        errno = ENOTSUP; __builtin_trap();
    }
    Class receiverClass = object_getClass(device);
    Method method = receiverClass ? class_getInstanceMethod(receiverClass, selector) : NULL;
    BOOL log = PVGCapabilityLogV1();
    if (!method) {
        if (log) dprintf(2,"[VM27OwnedPVGDepth24CapabilityV1] callerRVA=0x%lx deviceClass=%s nativeMethodMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",
            (unsigned long)callerRVA, receiverClass ? class_getName(receiverClass) : "(nil)");
        errno = incomingErrno; return NO;
    }
    char returned[16]={0}, self[16]={0}, command[16]={0};
    method_getReturnType(method,returned,sizeof(returned));
    method_getArgumentType(method,0,self,sizeof(self));
    method_getArgumentType(method,1,command,sizeof(command));
    if (method_getNumberOfArguments(method)!=2 || strcmp(returned,@encode(BOOL)) ||
        strcmp(self,"@") || strcmp(command,":")) {
        if (log) dprintf(2,"[VM27OwnedPVGDepth24CapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=0 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    IMP original = method_getImplementation(method);
    if (!original) {
        if (log) dprintf(2,"[VM27OwnedPVGDepth24CapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 implementationMissing=1 capabilityUnsupported=1 nativeCalled=0 returned=0\n",(unsigned long)callerRVA);
        errno = incomingErrno; return NO;
    }
    /* A real native BOOL getter is invoked once with the original self/SEL.
     * No texture, format support or native method is fabricated here. */
    typedef BOOL (*PVGNativeCapabilityV1)(id,SEL);
    errno = incomingErrno;
    BOOL result = ((PVGNativeCapabilityV1)original)(device,selector);
    int nativeErrno = errno;
    if (log) dprintf(2,"[VM27OwnedPVGDepth24CapabilityV1] callerRVA=0x%lx nativeMethodMissing=0 BOOLABICompatible=1 nativeCalledOnce=1 returned=%u\n",(unsigned long)callerRVA,result?1U:0U);
    errno = nativeErrno; return result;
}

