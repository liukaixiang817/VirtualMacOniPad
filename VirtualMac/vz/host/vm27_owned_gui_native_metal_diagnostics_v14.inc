/* MRC Main14-only diagnostic. No VM creation, port mutation, or GPU submit.
 * The first native factory call can initialize/cache state used by the second;
 * this instrumented comparison cannot establish uninstrumented causality. */
#include <ptrauth.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    Dl_info origin;
    const void *entry;
    uintptr_t rva;
    char uuid[33];
} VM27GUIMetalOriginV14;

static BOOL VM27GUIMetalNativeProfileV14(VM27GUIMetalOriginV14 *actual) {
    static const uint8_t expected[16] = {
        0x8f,0x06,0x21,0x25,0x74,0x88,0x39,0xef,
        0xaf,0xda,0x57,0xdb,0x8c,0xd8,0x00,0x33};
    memset(actual,0,sizeof(*actual));
    actual->entry=ptrauth_strip((void *)&MTLCreateSystemDefaultDevice,ptrauth_key_function_pointer);
    if(!dladdr(actual->entry,&actual->origin) || !actual->origin.dli_fbase ||
       !actual->origin.dli_fname)return NO;
    uintptr_t base=(uintptr_t)actual->origin.dli_fbase,address=(uintptr_t)actual->entry;
    if(address<base)return NO;
    actual->rva=address-base;
    if(strcmp(actual->origin.dli_fname,"/System/Library/Frameworks/Metal.framework/Metal") ||
       actual->rva!=UINTPTR_C(144272))return NO;
    const struct mach_header_64 *header=(const void *)base;
    if(header->magic!=MH_MAGIC_64 || header->cputype!=0x100000c ||
       !header->ncmds || header->ncmds>1024 || header->sizeofcmds<8 ||
       header->sizeofcmds>65536 || header->ncmds>header->sizeofcmds/8 ||
       base>UINTPTR_MAX-sizeof(*header)-header->sizeofcmds)return NO;
    const uint8_t *at=(const uint8_t *)(header+1),*end=at+header->sizeofcmds;
    unsigned uuids=0;BOOL uuidMatches=NO;
    for(uint32_t i=0;i<header->ncmds;i++) {
        if((size_t)(end-at)<sizeof(struct load_command))return NO;
        const struct load_command *command=(const void *)at;
        if(command->cmdsize<8 || command->cmdsize%8 || command->cmdsize>(size_t)(end-at))return NO;
        if(command->cmd==LC_UUID) {
            if(command->cmdsize!=sizeof(struct uuid_command))return NO;
            const uint8_t *uuid=((const struct uuid_command *)command)->uuid;
            for(unsigned j=0;j<16;j++)snprintf(actual->uuid+j*2,3,"%02x",uuid[j]);
            uuidMatches=!memcmp(uuid,expected,16);++uuids;
        }
        at+=command->cmdsize;
    }
    return at==end && uuids==1 && uuidMatches;
}

static void VM27GUIMetalObjectLogV14(const char *phase,const char *kind,id object) {
    Class cls=object?object_getClass(object):Nil;
    fprintf(stderr,"[Independent27MetalGUIV14] phase=%s kind=%s object=%p class=%s image=%s\n",
        phase,kind,(__bridge void *)object,cls?class_getName(cls):"(nil)",
        cls && class_getImageName(cls)?class_getImageName(cls):"(none)");
}

static void VM27OwnedGUINativeMetalDiagnosticV14(NSString *point,UIWindow *window,BOOL after) {
    static pid_t ownerPID;
    static BOOL beforeObserved,afterObserved;
    const char *phase=point.UTF8String?:"(missing)";
    if(!pthread_main_np() || !VZIndependent27SourceRouteSelected() || getuid()!=501 || geteuid()!=501) {
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s refused=owned-main-uid pid=%d uid=%u euid=%u\n",
            phase,(int)getpid(),(unsigned)getuid(),(unsigned)geteuid());return;
    }
    if((!after && beforeObserved) || (after && (!beforeObserved || afterObserved)) ||
       (ownerPID && ownerPID!=getpid())) {
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s refused=once-or-process pid=%d\n",phase,(int)getpid());return;
    }
    ownerPID=getpid();if(after)afterObserved=YES;else beforeObserved=YES;
    int inheritedErrno=errno;
    id<MTLDevice> device=nil;id<MTLCommandQueue> queue=nil;
    BOOL defaultInvoked=NO,queueInvoked=NO;
    VM27GUIMetalOriginV14 native={0};
    @try {
        Class windowClass=window?object_getClass(window):Nil;
        id controller=window.rootViewController;
        Class controllerClass=controller?object_getClass(controller):Nil;
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s pid=%d uid=%u euid=%u mainThread=1 mainQueue=%p appState=%ld window=%p key=%d windowClass=%s rootClass=%s\n",
            phase,(int)getpid(),(unsigned)getuid(),(unsigned)geteuid(),dispatch_get_main_queue(),
            (long)UIApplication.sharedApplication.applicationState,(__bridge void *)window,(int)window.isKeyWindow,
            windowClass?class_getName(windowClass):"(nil)",controllerClass?class_getName(controllerClass):"(nil)");
        BOOL matches=VM27GUIMetalNativeProfileV14(&native);
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s nativeProfileMatched=%d entry=%p image=%s base=%p uuid=%s rva=%llu appleValidationClaim=0\n",
            phase,(int)matches,native.entry,native.origin.dli_fname?:"(none)",native.origin.dli_fbase,
            native.uuid[0]?native.uuid:"(unavailable)",(unsigned long long)native.rva);
        if(!matches)return;
        errno=0;defaultInvoked=YES;device=MTLCreateSystemDefaultDevice();int deviceErrno=errno;
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s defaultCalled=1 returnedNil=%d errno=%d\n",phase,(int)(device==nil),deviceErrno);
        VM27GUIMetalObjectLogV14(phase,"device",device);
        if(device) {
            errno=0;queueInvoked=YES;queue=[device newCommandQueue];int queueErrno=errno;
            fprintf(stderr,"[Independent27MetalGUIV14] phase=%s queueCalled=1 returnedNil=%d errno=%d\n",phase,(int)(queue==nil),queueErrno);
            VM27GUIMetalObjectLogV14(phase,"queue",queue);
        } else {
            fprintf(stderr,"[Independent27MetalGUIV14] phase=%s queueCalled=0 reason=no-native-device\n",phase);
        }
    } @catch(NSException *exception) {
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s exception=%s reason=%s errno=%d defaultCalled=%d queueCalled=%d\n",
            phase,exception.name.UTF8String?:"(unknown)",exception.reason.UTF8String?:"(none)",errno,
            (int)defaultInvoked,(int)queueInvoked);
    } @finally {
        /* Both native factory results have +1 contracts in this MRC TU. */
        @try {if(queue)[queue release];}
        @catch(NSException *exception) {
            fprintf(stderr,"[Independent27MetalGUIV14] phase=%s cleanupException=queue-release name=%s unresolved=1\n",phase,exception.name.UTF8String?:"(unknown)");
        }
        @try {if(device)[device release];}
        @catch(NSException *exception) {
            fprintf(stderr,"[Independent27MetalGUIV14] phase=%s cleanupException=device-release name=%s unresolved=1\n",phase,exception.name.UTF8String?:"(unknown)");
        }
        errno=inheritedErrno;
        fprintf(stderr,"[Independent27MetalGUIV14] phase=%s diagnosticOnly=1 gpuSubmit=0 nativeLazyInitializationMayAffectAfter=1\n",phase);
    }
}
