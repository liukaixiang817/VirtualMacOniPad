// SDK declarations precede the source renames. One inherited backend/registry
// is linked with Factory18/Life22 and the genuine production SVC provider.
#include "vm27_hv_public_vm_bootstrap_v14.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <limits.h>
#include <ptrauth.h>

#if VM27_HV_VM_ENTRY_TESTING
#if TARGET_OS_IPHONE
#error "Root14 entry testing hooks cannot be compiled for iOS"
#endif
extern const struct mach_header *VM27HVVMEntryTestImageV14(void);
extern int VM27HVVMEntryTestPathV14(char *,uint32_t *);
extern uintptr_t VM27HVVMEntryTestReturnV14(void);
extern hv_return_t VM27HVVMEntryTestInstallV14(void);
#define MAIN_IMAGE_V14 VM27HVVMEntryTestImageV14()
#define MAIN_PATH_V14 VM27HVVMEntryTestPathV14
#define INSTALL_PRODUCTION_V14 VM27HVVMEntryTestInstallV14
#else
#include "vm27_actual_executable_image_v1.h"
static const struct mach_header *ActualMainImageV19(void) {
    VM27ActualExecutableImageV1 image = {0};
    return VM27ActualExecutableImageFindSelfV1(&image) == 0
        ? (const struct mach_header *)image.header : NULL;
}
#define MAIN_IMAGE_V14 ActualMainImageV19()
#define MAIN_PATH_V14 _NSGetExecutablePath
#define INSTALL_PRODUCTION_V14 VM27InstallProductionNativeOpsV1
#endif

#define hv_vm_config_create VM27HVVMInheritedConfigCreateV14
#define hv_vm_config_get_max_ipa_size VM27HVVMInheritedMaxIPAV14
#include "vm27_hv_public_vm_bootstrap_v12.m"
#undef hv_vm_config_create
#undef hv_vm_config_get_max_ipa_size

// The actual modern VMM config-create import has one BL caller. Its auth stub
// is a tail BRAA, preserving this LR. UUID and executable name exclude the UI
// parent and the old VMM. These are source admission, not a signing claim.
static bool ChildConfigEntryV14(uintptr_t caller) {
    static const unsigned char uuid[16] = {
        0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
        0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b
    };
    const struct mach_header *mainImage=MAIN_IMAGE_V14;
    struct mach_header_64 header={0};
    if (!VM27CPUSelfReadV1(NULL,mainImage,sizeof(header),&header) ||
        header.magic!=MH_MAGIC_64 || header.cputype!=CPU_TYPE_ARM64 ||
        header.filetype!=MH_EXECUTE || !header.ncmds || header.ncmds>2048 ||
        header.sizeofcmds>16384 || header.sizeofcmds<8 ||
        (uintptr_t)mainImage>UINTPTR_MAX-sizeof(header)-header.sizeofcmds ||
        (uintptr_t)mainImage>UINTPTR_MAX-UINT32_C(0x2e9d50) ||
        caller!=(uintptr_t)mainImage+UINT32_C(0x2e9d50)) return false;
    unsigned char commands[16384];
    if (!VM27CPUSelfReadV1(NULL,(const unsigned char *)mainImage+sizeof(header),
        header.sizeofcmds,commands)) return false;
    size_t cursor=0;unsigned uuidCount=0;
    for (uint32_t index=0;index<header.ncmds;++index) {
        struct load_command command={0};
        if (cursor>header.sizeofcmds || header.sizeofcmds-cursor<sizeof(command)) return false;
        memcpy(&command,commands+cursor,sizeof(command));
        if (command.cmdsize<sizeof(command) || command.cmdsize%8 ||
            command.cmdsize>header.sizeofcmds-cursor) return false;
        if (command.cmd==LC_UUID) {
            if (command.cmdsize!=sizeof(struct uuid_command) || ++uuidCount!=1 ||
                memcmp(commands+cursor+sizeof(command),uuid,sizeof(uuid))) return false;
        }
        cursor+=command.cmdsize;
    }
    uint32_t branch=0;
    if (cursor!=header.sizeofcmds || uuidCount!=1 ||
        !VM27CPUSelfReadV1(NULL,(const unsigned char *)mainImage+UINT32_C(0x2e9d4c),
            sizeof(branch),&branch) || branch!=UINT32_C(0x9404a45a)) return false;
    char executable[PATH_MAX];uint32_t capacity=sizeof(executable);
    if (MAIN_PATH_V14(executable,&capacity) || !capacity || capacity>sizeof(executable) ||
        !memchr(executable,0,sizeof(executable))) return false;
    const char *basename=strrchr(executable,'/');basename=basename?basename+1:executable;
    return !strcmp(basename,"com.apple.Virtualization.VirtualMachine");
}
__attribute__((noinline)) hv_vm_config_t hv_vm_config_create(void) {
#if VM27_HV_VM_ENTRY_TESTING
    uintptr_t caller=VM27HVVMEntryTestReturnV14();
#else
    uintptr_t caller=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
#endif
    if (!ChildConfigEntryV14(caller) || INSTALL_PRODUCTION_V14()!=0) abort();
    return VM27HVVMInheritedConfigCreateV14();
}
hv_return_t hv_vm_config_get_max_ipa_size(uint32_t *out) {
    if (!OutputBeforeLock(out,sizeof(*out))) return Error(3);
    if (!Begin()) return Error(2);
    Lock();bool valid=OutputLocked(out,sizeof(*out));Unlock();
    if (!valid) { End();return Error(3); }
    VM27CPURawIPAPairV2 pair={0};
    VM27CPUConfigAcquireRawIPAPairV2(&pair);
    hv_return_t status=Error(15);
    if (pair.known && !(pair.rawFieldA>>32) && !(pair.rawFieldB>>32)) {
        uint32_t a=(uint32_t)pair.rawFieldA,b=(uint32_t)pair.rawFieldB;
        uint32_t nativeMax=a<b?a:b;
        if (nativeMax>=36) status=0;
    }
    if (!status) {
        Lock();if (!OutputLocked(out,sizeof(*out))) status=Error(3);else *out=36;Unlock();
    }
    End();return status;
}
