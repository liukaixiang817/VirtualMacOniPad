// CPU-only VZ27 loader/metadata/configuration lifecycle probe. No VM is created.
// The two metadata accessors use the original Swift MetadataResponse SwiftCC ABI.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "modern_vz_required_imports.h"

static const unsigned char VZUUID[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
static unsigned checks, failures;
static BOOL Check(BOOL value, NSString *name) {
    ++checks; if (!value) ++failures;
    NSLog(@"VZ27 check %@: %@", value ? @"PASS" : @"FAIL", name); return value;
}
static BOOL Read(const void *address, void *output, size_t length) {
    if (!address || !output || !length || length > 65536) return NO;
    vm_size_t copied = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)address, length,
        (vm_address_t)output, &copied) == KERN_SUCCESS && copied == length;
}
static BOOL ImageUUID(const void *base, unsigned char result[16]) {
    struct mach_header_64 header;
    if (!Read(base, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.cputype != CPU_TYPE_ARM64 || header.sizeofcmds > 65536 ||
        !header.ncmds || header.ncmds > 1024) return NO;
    uintptr_t at = (uintptr_t)base + sizeof(header), end = at + header.sizeofcmds;
    if (end < at) return NO;
    unsigned found = 0;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        struct load_command command;
        if (at > end || end - at < sizeof(command) ||
            !Read((void *)at, &command, sizeof(command)) || command.cmdsize < 8 ||
            command.cmdsize % 8 || command.cmdsize > end - at) return NO;
        if (command.cmd == LC_UUID) {
            struct uuid_command uuid;
            if (command.cmdsize != sizeof(uuid) || !Read((void *)at, &uuid, sizeof(uuid))) return NO;
            memcpy(result, uuid.uuid, sizeof(uuid.uuid)); ++found;
        }
        at += command.cmdsize;
    }
    return at == end && found == 1;
}
static BOOL Owner(const void *address, const void **base) {
    Dl_info image = {}; unsigned char uuid[16];
    if (!address || !dladdr(address, &image) || !ImageUUID(image.dli_fbase, uuid) ||
        memcmp(uuid, VZUUID, 16)) return NO;
    if (base) *base = image.dli_fbase;
    return YES;
}
struct MetadataResponse { const void *metadata; uintptr_t state; };
using MetadataAccessor = MetadataResponse (__attribute__((swiftcall)) *)(uintptr_t);
struct ValueInfo { uintptr_t size, stride; uint32_t flags, extraInhabitants; };
static const void *Metadata(void *handle, const char *symbol, NSString *name,
                            size_t expectedSize, size_t expectedStride) {
    void *entry = dlsym(handle, symbol);
    const void *entryOwner = nullptr;
    if (!Check(Owner(entry, &entryOwner), [name stringByAppendingString:@" accessor original UUID"])) return nullptr;
    MetadataAccessor accessor = (MetadataAccessor)entry;
    // Request zero is complete, blocking. The response must be complete, state 0.
    MetadataResponse response = accessor(0);
    const void *metadataOwner = nullptr;
    if (!Check(response.state == 0 && Owner(response.metadata, &metadataOwner) &&
               metadataOwner == entryOwner, [name stringByAppendingString:@" genuine complete metadata"])) return nullptr;
    const void *slots[2];
    if (!Check(Read((const unsigned char *)response.metadata - 16, slots, sizeof(slots)),
               [name stringByAppendingString:@" metadata prefix readable"])) return nullptr;
    void *layout = (void *)slots[0], *table = (void *)slots[1];
#if __has_feature(ptrauth_calls)
    layout = ptrauth_auth_data(layout, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)response.metadata - 16, 0x8b65));
    table = ptrauth_auth_data(table, ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)response.metadata - 8, 0x2e3f));
#endif
    ValueInfo info = {}; const void *layoutOwner = nullptr, *tableOwner = nullptr;
    if (!Check(!((uintptr_t)layout & 1) && Owner(layout, &layoutOwner) && Owner(table, &tableOwner) &&
               layoutOwner == entryOwner && tableOwner == entryOwner &&
               Read((const unsigned char *)table + 64, &info, sizeof(info)) &&
               info.size == expectedSize && info.stride == expectedStride,
               [name stringByAppendingString:@" authenticated VZ layout and VWT"])) return nullptr;
    NSLog(@"VZ27 metadata %@=%p layout=%p VWT=%p size=%lu stride=%lu flags=0x%08x extra=%u",
        name, response.metadata, layout, table, (unsigned long)info.size,
        (unsigned long)info.stride, info.flags, info.extraInhabitants);
    return response.metadata;
}
static Class OriginalClass(void *handle, const char *name) {
    NSString *symbol = [@"OBJC_CLASS_$_" stringByAppendingString:[NSString stringWithUTF8String:name]];
    void *entry = dlsym(handle, symbol.UTF8String);
    Class cls = (__bridge Class)entry;
    if (!Check(cls && cls == objc_getClass(name) && Owner(entry, nullptr),
               [NSString stringWithFormat:@"%s original class UUID and lookup identity", name])) return Nil;
    return cls;
}
static BOOL RequiredImports(void *handle) {
    unsigned missing = 0, resolved = 0;
    for (const char *name : VM27VZRequiredNames) {
        // New private provider routing may legitimately differ from old cache
        // ordinals. This is a finite pointer-presence gate, not ABI validation.
        void *value = dlsym(handle,name);
        if (!value) value = dlsym(RTLD_DEFAULT,name);
        if (!value) { ++missing; NSLog(@"VZ27 required import missing: %s",name); }
        else ++resolved;
    }
    NSLog(@"VZ27 original nonweak nlist presence total=%lu resolved=%u missing=%u; original fixups not recovered",
        (unsigned long)(sizeof(VM27VZRequiredNames)/sizeof(VM27VZRequiredNames[0])),resolved,missing);
    return Check(missing == 0,@"required import presence before all VZ function/metadata calls");
}
static BOOL CheckMethod(Class cls, const char *name, const char *returnType, unsigned arguments,
                        const char *valueType = nullptr) {
    Method method = class_getInstanceMethod(cls, sel_registerName(name));
    if (!method) return Check(NO, [NSString stringWithFormat:@"%s method exists", name]);
    char result[32] = {}; method_getReturnType(method, result, sizeof(result));
    char selfType[32] = {}, selectorType[32] = {}, argumentType[32] = {};
    method_getArgumentType(method,0,selfType,sizeof(selfType));
    method_getArgumentType(method,1,selectorType,sizeof(selectorType));
    if (valueType) method_getArgumentType(method,2,argumentType,sizeof(argumentType));
    const void *imp = ptrauth_strip((void *)method_getImplementation(method), ptrauth_key_function_pointer);
    return Check(strcmp(result, returnType) == 0 && method_getNumberOfArguments(method) == arguments &&
                 strcmp(selfType,"@") == 0 && strcmp(selectorType,":") == 0 &&
                 (!valueType || strcmp(argumentType,valueType) == 0) &&
                 Owner(imp, nullptr), [NSString stringWithFormat:@"%s exact return/count and original IMP UUID", name]);
}
static BOOL Configurations(void *handle) {
    Class configClass = OriginalClass(handle, "VZVirtualMachineConfiguration");
    Class bootClass = OriginalClass(handle, "VZEFIBootLoader");
    if (!configClass || !bootClass) return NO;
    if (!CheckMethod(configClass,"init","@",2) || !CheckMethod(bootClass,"init","@",2) ||
        !CheckMethod(configClass,"setCPUCount:","v",3,"Q") || !CheckMethod(configClass,"CPUCount","Q",2) ||
        !CheckMethod(configClass,"setMemorySize:","v",3,"Q") || !CheckMethod(configClass,"memorySize","Q",2) ||
        !CheckMethod(configClass,"setBootLoader:","v",3,"@") || !CheckMethod(configClass,"bootLoader","@",2)) return NO;
    SEL setCPU = sel_registerName("setCPUCount:"), cpu = sel_registerName("CPUCount");
    SEL setMemory = sel_registerName("setMemorySize:"), memory = sel_registerName("memorySize");
    SEL setBoot = sel_registerName("setBootLoader:"), boot = sel_registerName("bootLoader");
    for (unsigned i = 0; i < 16; ++i) {
        __weak id weakConfig, weakBoot;
        @autoreleasepool {
            id config = [configClass new], loader = [bootClass new];
            if (!Check(config != nil && loader != nil, @"real configuration and EFI object creation")) return NO;
            weakConfig = config; weakBoot = loader;
            ((void (*)(id,SEL,NSUInteger))objc_msgSend)(config,setCPU,2);
            ((void (*)(id,SEL,uint64_t))objc_msgSend)(config,setMemory,UINT64_C(512)*1024*1024);
            ((void (*)(id,SEL,id))objc_msgSend)(config,setBoot,loader);
            if (!Check(((NSUInteger (*)(id,SEL))objc_msgSend)(config,cpu) == 2 &&
                ((uint64_t (*)(id,SEL))objc_msgSend)(config,memory) == UINT64_C(512)*1024*1024 &&
                ((id (*)(id,SEL))objc_msgSend)(config,boot) == loader,
                @"CPU/memory/bootloader properties preserve actual values")) return NO;
            loader = nil;
            if (!Check(weakBoot != nil, @"configuration genuinely retains EFI bootloader")) return NO;
            config = nil;
        }
        if (!Check(weakConfig == nil && weakBoot == nil, @"configuration and owned bootloader both deallocated")) return NO;
    }
    return YES;
}
int main(int argc, char **argv) {
    @autoreleasepool {
        BOOL loadOnly = argc == 3 && strcmp(argv[2],"--load-only") == 0;
        if (argc != 2 && !loadOnly) { fprintf(stderr,"usage: %s EXACT_VZ27_PATH [--load-only]\n",argv[0]); return 64; }
        // Duplicate ObjC names would make even a correct candidate unsafe to test.
        if (!Check(objc_getClass("VZVirtualMachineConfiguration") == Nil,
                   @"no previously loaded VZ configuration class")) return 65;
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!handle) { NSLog(@"VZ27 exact dlopen failed: %s", dlerror()); return 66; }
        if (!OriginalClass(handle,"VZVirtualMachineConfiguration")) { dlclose(handle); return 67; }
        BOOL imports = RequiredImports(handle);
        if (loadOnly || !imports) {
            NSLog(@"VZ27 load-only finish: identityChecked=1 requiredImportsPresent=%d metadataCalls=0 configurationObjects=0",
                imports);
            int closed = dlclose(handle);
            return imports && closed == 0 ? 0 : 68;
        }
        BOOL caching = Metadata(handle,
            "$sSo28VZLinuxRosettaDirectoryShareC14VirtualizationE14CachingOptionsOMa",
            @"CachingOptions",17,24) != nullptr;
        BOOL efi = Metadata(handle,"$s14Virtualization14VZEFISignatureOMa",@"VZEFISignature",16,16) != nullptr;
        BOOL configured = caching && efi && Configurations(handle);
        NSLog(@"VZ27 CPU-only summary checks=%u failures=%u config=%d VMCreated=0 VMMStarted=0 GPUWork=0",
            checks,failures,configured);
        // ObjC runtime may retain image state: dlclose releases our handle only.
        int closed = dlclose(handle);
        return configured && !failures && closed == 0 ? 0 : 67;
    }
}
