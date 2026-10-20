#define _DARWIN_C_SOURCE 1
#include "vm27_owned_child_gestalt_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHILD_MAIN "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"
extern CFTypeRef MGCopyAnswer(CFStringRef key);
extern int32_t MGGetSInt32Answer(CFStringRef key, int32_t defaultValue);
extern int csops(pid_t, unsigned int, void *, size_t);
static bool GestaltImageUUIDV1(const void *image, const uint8_t expected[16]) {
    if (!image) return false;
    const struct mach_header_64 *header = image;
    if (header->magic != MH_MAGIC_64 || !header->ncmds ||
        header->ncmds > 2048 || header->sizeofcmds > 65536) return false;
    const uint8_t *at = (const uint8_t *)(header + 1);
    const uint8_t *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end-at) < sizeof(struct load_command)) return false;
        const struct load_command *command = (const struct load_command *)at;
        if (command->cmdsize < 8 || (command->cmdsize & 7) ||
            command->cmdsize > (size_t)(end-at)) return false;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) || ++matches != 1 ||
                memcmp(((const struct uuid_command *)command)->uuid, expected, 16)) return false;
        }
        at += command->cmdsize;
    }
    return at == end && matches == 1;
}


static bool GestaltExactCallerV1(void *caller) {
    static const uint8_t childUUID[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    static const uint8_t nativeUUID[16]={0x74,0xe2,0xf2,0x23,0x37,0x04,0x3f,0x21,0xae,0xb0,0xf6,0x81,0xc0,0x03,0xe5,0xfb};
    uint32_t status=0;
    if (getuid()!=501 || geteuid()!=501 || getpid()<=1 || csops(getpid(),0,&status,sizeof(status)) ||
        (status & UINT32_C(0x04000001))!=UINT32_C(0x04000001)) return false;
    char path[4096],canonical[4096];uint32_t capacity=sizeof(path);
    if (_NSGetExecutablePath(path,&capacity) || !realpath(path,canonical) || strcmp(canonical,CHILD_MAIN)) return false;
    Dl_info child={0},copy={0},typed={0};
    void *nativeCopy=ptrauth_strip((void *)&MGCopyAnswer,ptrauth_key_function_pointer);
    void *nativeTyped=ptrauth_strip((void *)&MGGetSInt32Answer,ptrauth_key_function_pointer);
    return caller && dladdr(caller,&child) && child.dli_fname && !strcmp(child.dli_fname,CHILD_MAIN) &&
        GestaltImageUUIDV1(child.dli_fbase,childUUID) &&
        ((uintptr_t)caller-(uintptr_t)child.dli_fbase==(uintptr_t)UINT64_C(0x307d14) ||
         (uintptr_t)caller-(uintptr_t)child.dli_fbase==(uintptr_t)UINT64_C(0x320acc) ||
         (uintptr_t)caller-(uintptr_t)child.dli_fbase==(uintptr_t)UINT64_C(0x348524)) &&
        dladdr(nativeCopy,&copy) && copy.dli_fname && !strcmp(copy.dli_fname,"/usr/lib/libMobileGestalt.dylib") &&
        GestaltImageUUIDV1(copy.dli_fbase,nativeUUID) &&
        (uintptr_t)nativeCopy-(uintptr_t)copy.dli_fbase==(uintptr_t)UINT64_C(0x2584) &&
        dladdr(nativeTyped,&typed) && typed.dli_fbase==copy.dli_fbase &&
        (uintptr_t)nativeTyped-(uintptr_t)typed.dli_fbase==(uintptr_t)UINT64_C(0x2ba4);
}

/* Only the genuine VMM optional SoCSKU integer query is adapted. Native iOS
 * typed lookup aborts on an answer-type mismatch before honoring its default.
 * Use the genuine untyped +1 answer, then accept only a real representable
 * CFNumber. Unsupported or missing answers keep the caller's own default;
 * no numeric SKU, CPU capability, or VM-success value is invented. */
__attribute__((visibility("default")))
int32_t VM27OwnedChildMGGetSInt32AnswerV1(CFStringRef key,int32_t defaultValue) {
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    int incomingErrno=errno;
    bool selectedKey=key && CFGetTypeID(key)==CFStringGetTypeID() && CFEqual(key,CFSTR("SoCSKU"));
    if (!selectedKey || defaultValue!=-1 || !GestaltExactCallerV1(caller)) {
        if (selectedKey) {
            Dl_info owner={0};uint32_t status=0;
            (void)dladdr(caller,&owner);(void)csops(getpid(),0,&status,sizeof(status));
            fprintf(stderr,"[VM27OwnedChildGestaltV2] admission=0 key=SoCSKU caller=%p callerRVA=0x%lx pid=%d uid=%u euid=%u status=%08x default=%d path=%s\n",
                caller,(unsigned long)((uintptr_t)caller-(uintptr_t)owner.dli_fbase),(int)getpid(),(unsigned)getuid(),(unsigned)geteuid(),status,defaultValue,owner.dli_fname?owner.dli_fname:"(none)");
        }
        errno=incomingErrno;return MGGetSInt32Answer(key,defaultValue);
    }
    errno=incomingErrno;
    CFTypeRef answer=MGCopyAnswer(key);int nativeErrno=errno;
    CFTypeID type=answer ? CFGetTypeID(answer) : 0;
    int32_t result=defaultValue;
    bool numeric=answer && type==CFNumberGetTypeID();
    bool converted=numeric && CFNumberGetValue((CFNumberRef)answer,kCFNumberSInt32Type,&result);
    if (!converted) result=defaultValue;
    if (answer) CFRelease(answer);
    fprintf(stderr,"[VM27OwnedChildGestaltV2] key=SoCSKU answerPresent=%u answerType=%lu genuineNumber=%u conversionPassed=%u callerDefault=%d returned=%d optionalNumericCapabilityUnknown=%u nativeTypedCall=0\n",
        answer ? 1U:0U,(unsigned long)type,numeric ? 1U:0U,converted ? 1U:0U,defaultValue,result,converted ? 0U:1U);
    errno=nativeErrno;return result;
}
