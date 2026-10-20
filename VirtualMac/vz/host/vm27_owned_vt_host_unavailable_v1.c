/* Only the original owned Child's Create and Deliver imports use this adapter.
 * An unavailable native host endpoint stays unavailable: no session/message is
 * fabricated, and the original VMM writes the returned OSStatus to the guest. */
#define _DARWIN_C_SOURCE 1
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VT_CHILD_V1 "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"
extern int csops(pid_t, unsigned int, void *, size_t);
extern int _NSGetExecutablePath(char *, uint32_t *);

typedef int32_t (*VTCreateV1)(const void *, void **);
/* All six arguments are in integer registers in the original macOS27 caller.
 * The last argument is w5; the other values remain opaque pointer-sized bits. */
typedef int32_t (*VTDeliverV1)(void *, const void *, const void *,
                             const void *, const void *, uint32_t);
static unsigned VTLogCountV1;

static bool VTAdmissionV1(void *caller, uintptr_t expectedRVA) {
    static const uint8_t uuid[16] = {
        0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
        0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    uint32_t status = 0;
    if (getuid()!=501 || geteuid()!=501 || getpid()<=1 ||
        csops(getpid(),0,&status,sizeof(status)) ||
        (status & UINT32_C(0x04000001))!=UINT32_C(0x04000001)) return false;
    char path[4096]={0}, canonical[4096]={0};
    uint32_t capacity=sizeof(path);
    if (_NSGetExecutablePath(path,&capacity) || capacity>sizeof(path) ||
        !memchr(path,0,sizeof(path)) || !realpath(path,canonical) ||
        strcmp(canonical,VT_CHILD_V1)) return false;
    Dl_info owner={0};
    if (!caller || !dladdr(caller,&owner) || !owner.dli_fname ||
        strcmp(owner.dli_fname,VT_CHILD_V1) || !owner.dli_fbase ||
        (uintptr_t)caller<(uintptr_t)owner.dli_fbase ||
        (uintptr_t)caller-(uintptr_t)owner.dli_fbase!=expectedRVA) return false;
    const struct mach_header_64 *h=owner.dli_fbase;
    if (h->magic!=MH_MAGIC_64 || h->filetype!=MH_EXECUTE ||
        !h->ncmds || h->ncmds>2048 || h->sizeofcmds>65536) return false;
    const uint8_t *at=(const uint8_t *)(h+1), *end=at+h->sizeofcmds;
    unsigned matches=0;
    for (uint32_t i=0;i<h->ncmds;++i) {
        if ((size_t)(end-at)<sizeof(struct load_command)) return false;
        const struct load_command *c=(const struct load_command *)at;
        if (c->cmdsize<8 || (c->cmdsize&7) || c->cmdsize>(size_t)(end-at)) return false;
        if (c->cmd==LC_UUID && (c->cmdsize!=sizeof(struct uuid_command) ||
            ++matches!=1 || memcmp(((const struct uuid_command *)c)->uuid,uuid,16))) return false;
        at+=c->cmdsize;
    }
    return at==end && matches==1;
}

/* Resolve only already-loaded genuine native functions. Requiring the entire
 * endpoint prevents a real session being created without its teardown APIs.
 * Lookups are local to this call; there is no mutable shared session state. */
static bool VTNativeEndpointV1(VTCreateV1 *create, VTDeliverV1 *deliver) {
    static const char *const names[5]={
        "VTParavirtualizationHostSessionCompleteInvalidate",
        "VTParavirtualizationHostSessionCreate",
        "VTParavirtualizationHostSessionCreateTerminateAllSessionsMessage",
        "VTParavirtualizationHostSessionDeliverMessageFromGuest",
        "VTParavirtualizationHostSessionInvalidate"};
    void *symbols[5]={0}, *base=NULL;
    for (unsigned i=0;i<5;++i) {
        symbols[i]=dlsym(RTLD_DEFAULT,names[i]);
        Dl_info owner={0};
        void *address=ptrauth_strip(symbols[i],ptrauth_key_function_pointer);
        if (!symbols[i] || !dladdr(address,&owner) || !owner.dli_fbase ||
            !owner.dli_fname ||
            (strcmp(owner.dli_fname,"/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox") &&
             strcmp(owner.dli_fname,"/System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox")) ||
            (base && base!=owner.dli_fbase)) return false;
        base=owner.dli_fbase;
    }
    *create=(VTCreateV1)symbols[1];
    *deliver=(VTDeliverV1)symbols[3];
    return true;
}

static void VTUnavailableLogV1(const char *operation) {
    unsigned count=__atomic_load_n(&VTLogCountV1,__ATOMIC_RELAXED);
    while (count<4) {
        if (__atomic_compare_exchange_n(&VTLogCountV1,&count,count+1,false,
                                       __ATOMIC_RELAXED,__ATOMIC_RELAXED)) {
            dprintf(2,"[VM27OwnedVTHostUnavailableV1] operation=%s nativeEndpointComplete=0 nativeCalled=0 sessionFabricated=0 status=-4\n",operation);
            return;
        }
    }
}

__attribute__((visibility("default")))
int32_t VM27OwnedVTSessionCreateV1(const void *callbacks, void **outSession) {
    int incomingErrno=errno;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    if (!VTAdmissionV1(caller,UINT64_C(0xdf234)) || !outSession) {
        errno=ENOTSUP; __builtin_trap();
    }
    VTCreateV1 create=NULL; VTDeliverV1 deliver=NULL;
    if (!VTNativeEndpointV1(&create,&deliver)) {
        *outSession=NULL;
        VTUnavailableLogV1("create");
        errno=incomingErrno; return -4; /* unimpErr */
    }
    errno=incomingErrno;
    return create(callbacks,outSession);
}

__attribute__((visibility("default")))
int32_t VM27OwnedVTSessionDeliverV1(void *session, const void *message,
    const void *context, const void *objects, const void *lengths, uint32_t count) {
    int incomingErrno=errno;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    if (!VTAdmissionV1(caller,UINT64_C(0xdebac))) {
        errno=ENOTSUP; __builtin_trap();
    }
    VTCreateV1 create=NULL; VTDeliverV1 deliver=NULL;
    if (!VTNativeEndpointV1(&create,&deliver)) {
        /* With this same all-or-none gate, Create cannot have produced a real
         * session. A non-NULL value is not claimed as an owned offline session. */
        if (session) { errno=ENOTSUP; __builtin_trap(); }
        VTUnavailableLogV1("deliver");
        errno=incomingErrno; return -4;
    }
    errno=incomingErrno;
    return deliver(session,message,context,objects,lengths,count);
}
