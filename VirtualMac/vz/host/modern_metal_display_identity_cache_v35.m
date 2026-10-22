/* Include the actual R74 root and all capabilities/VT/error paths byte for byte. */
#include "modern_metal_device_array_v20.m"
#include "vm27_pg_image_identity_cache_v1.h"

static VM27PGImageIdentityCacheV1 PGDisplayImageIdentityV35={.generation=1};
static void PGDisplayImageChangedV35(const struct mach_header *header,intptr_t slide) {
    (void)header;(void)slide;VM27PGImageIdentityInvalidateV1(&PGDisplayImageIdentityV35);
}
__attribute__((constructor)) static void PGDisplayImageCacheInitializeV35(void) {
    _dyld_register_func_for_add_image(PGDisplayImageChangedV35);
    _dyld_register_func_for_remove_image(PGDisplayImageChangedV35);
    __atomic_store_n(&PGDisplayImageIdentityV35.active,1,__ATOMIC_RELEASE);
}

static uint64_t PGDisplayStateOrdinalV1,PGDisplaySwapOrdinalV1;
static uint64_t PGDisplayObservationOrdinalV1(uint64_t *counter) {
    uint64_t value=__atomic_load_n(counter,__ATOMIC_RELAXED);
    while(value!=UINT64_MAX) {
        if(__atomic_compare_exchange_n(counter,&value,value+1,YES,
            __ATOMIC_RELAXED,__ATOMIC_RELAXED))return value+1;
    }
    return UINT64_MAX;
}
static IMP PGDisplayObservationValidateV35(id receiver,SEL selector,void *caller,
    unsigned entry,uintptr_t *callerRVA,BOOL allowCache) {
    const char *expected=entry==0 ? "stateMachineWithCaller:" :
        "presentMappedSurface:gammaTableVirtualOffset:gammaTableMappedLength:gammaTableEntryCount:gammaTableSum:";
    uint32_t status=0;uint8_t uuid[16];char path[4096]={0},canonical[4096]={0};
    uint32_t capacity=sizeof(path);Dl_info owner={0},implementationOwner={0};
    pid_t actualPID=getpid();
    uint64_t generation=VM27PGImageIdentityGenerationV1(&PGDisplayImageIdentityV35);
    uintptr_t cachedBase=0;
    BOOL valid=entry<2 && receiver && selector && !strcmp(sel_getName(selector),expected) &&
        getuid()==501 && geteuid()==501 && actualPID>1 &&
        !csops(actualPID,0,&status,sizeof(status)) &&
        (status&UINT32_C(0x04000001))==UINT32_C(0x04000001) &&
        vm27_metal_device_array_profile_matches();
    BOOL cached=valid && allowCache && VM27PGImageIdentityLookupV1(
        &PGDisplayImageIdentityV35,actualPID,generation,&cachedBase);
    if(cached) {
        owner.dli_fbase=(void *)cachedBase;
        valid=caller && (uintptr_t)caller>=cachedBase;
    } else {
        valid=valid && !_NSGetExecutablePath(path,&capacity) && capacity<=sizeof(path) &&
            memchr(path,0,sizeof(path)) && realpath(path,canonical) &&
            !strcmp(canonical,PVGChildPathV1);
        unsigned mainCount=0;uint32_t images=valid?_dyld_image_count():0;
        if(!images || images>4096)valid=NO;
        for(uint32_t i=0;valid && i<images;++i) {
            const char *name=_dyld_get_image_name(i);
            if(!name || strcmp(name,PVGChildPathV1))continue;
            if(++mainCount!=1 || !PVGReadUUIDV1(_dyld_get_image_header(i),MH_EXECUTE,uuid) ||
                memcmp(uuid,PVGChildUUIDV1,16))valid=NO;
        }
        valid=valid && mainCount==1 && caller && dladdr(caller,&owner) && owner.dli_fname &&
            !strcmp(owner.dli_fname,PVGImagePathV1) &&
            PVGReadUUIDV1(owner.dli_fbase,MH_DYLIB,uuid) && !memcmp(uuid,PVGImageUUIDV1,16) &&
            (uintptr_t)caller>=(uintptr_t)owner.dli_fbase;
    }
    if(valid) {
        *callerRVA=(uintptr_t)caller-(uintptr_t)owner.dli_fbase;
        if(entry==0)valid=*callerRVA==0x27110 || *callerRVA==0x271ac ||
            *callerRVA==0x2720c || *callerRVA==0x272d4 ||
            *callerRVA==0x2c080 || *callerRVA==0x2c318;
        else valid=*callerRVA==0x3b080;
    }
    Class receiverClass=valid?object_getClass(receiver):Nil;
    if(valid)valid=receiverClass &&
        (uintptr_t)ptrauth_strip((void *)receiverClass,ptrauth_key_process_independent_data)==
            (uintptr_t)owner.dli_fbase+UINT64_C(0x84370);
    Method method=valid?class_getInstanceMethod(receiverClass,selector):NULL;
    unsigned arguments=entry==0?3:7;
    if(!method || method_getNumberOfArguments(method)!=arguments)valid=NO;
    static const char *const stateTypes[]={"@",":","r*"};
    static const char *const swapTypes[]={"@",":","Q","Q","Q","I","I"};
    const char *const *types=entry==0?stateTypes:swapTypes;
    char encoded[16]={0};
    if(valid) {
        method_getReturnType(method,encoded,sizeof(encoded));valid=!strcmp(encoded,"v");
        for(unsigned i=0;valid && i<arguments;++i) {
            memset(encoded,0,sizeof(encoded));method_getArgumentType(method,i,encoded,sizeof(encoded));
            valid=!strcmp(encoded,types[i]);
        }
    }
    IMP original=valid?method_getImplementation(method):NULL;
    void *implementation=original?ptrauth_strip((void *)original,ptrauth_key_function_pointer):NULL;
    valid=valid && implementation && dladdr(implementation,&implementationOwner) &&
        implementationOwner.dli_fbase==owner.dli_fbase && implementationOwner.dli_fname &&
        !strcmp(implementationOwner.dli_fname,PVGImagePathV1) &&
        (uintptr_t)implementation-(uintptr_t)owner.dli_fbase==(entry==0?0x273bc:0x27938);
    if(!valid) {
        dprintf(2,"[VM27OwnedPGDisplayHandshakeV1] admission=0 originalNotCalled=1 resultNotClaimed=1\n");
        errno=ENOTSUP;__builtin_trap();
    }
    if(cached && generation!=VM27PGImageIdentityGenerationV1(&PGDisplayImageIdentityV35))
        return PGDisplayObservationValidateV35(receiver,selector,caller,entry,callerRVA,NO);
    if(!cached)VM27PGImageIdentityPublishV1(&PGDisplayImageIdentityV35,
        actualPID,generation,(uintptr_t)owner.dli_fbase);
    return original;
}

static IMP PGDisplayObservationOriginalV1(id receiver,SEL selector,void *caller,
    unsigned entry,uintptr_t *callerRVA) {
    return PGDisplayObservationValidateV35(receiver,selector,caller,entry,callerRVA,YES);
}

typedef struct {
    unsigned known,mappingPresent,sharedPresent,clientPresent,modeListPresent;
    uint32_t phase,sequence,ack;
    uint16_t modeCount;
    uint8_t pending;
} PGDisplayObservationV1;
/* Read only the original self layout and its actual mapping's virtual address.
 * No mapping object, client or mode-list object is followed or messaged. Every
 * fixed shared-page field ends below 0x1000, inside the original 16KiB mapping.
 * A failed observation never changes whether the real method is invoked. */
static void PGDisplayObservationReadV1(id receiver,PGDisplayObservationV1 *result) {
    /* All four private call sites pass their fully zero-initialized snapshot. */
    uintptr_t object=(uintptr_t)receiver;
    uintptr_t mapping=0,shared=0,client=0,modeList=0;
    if(!object || object>UINTPTR_MAX-0x200)return;
    if(PVGSelfReadV1((void *)(object+0x20),sizeof(mapping),&mapping)) {
        result->known|=1;result->mappingPresent=mapping!=0;
    }
    if(PVGSelfReadV1((void *)(object+0x28),sizeof(shared),&shared)) {
        result->known|=2;result->sharedPresent=shared!=0;
    }
    if(PVGSelfReadV1((void *)(object+0x30),sizeof(modeList),&modeList)) {
        result->known|=4;result->modeListPresent=modeList!=0;
    }
    if(PVGSelfReadV1((void *)(object+0x1b0),sizeof(client),&client)) {
        result->known|=8;result->clientPresent=client!=0;
    }
    if((result->known&3)!=3 || !mapping || !shared || shared>UINTPTR_MAX-0x4000)return;
    if(PVGSelfReadV1((void *)(shared+0x200),sizeof(result->sequence),&result->sequence))result->known|=16;
    if(PVGSelfReadV1((void *)(shared+0x208),sizeof(result->modeCount),&result->modeCount))result->known|=32;
    if(PVGSelfReadV1((void *)(shared+0xfa9),sizeof(result->pending),&result->pending))result->known|=64;
    if(PVGSelfReadV1((void *)(shared+0xfbc),sizeof(result->ack),&result->ack))result->known|=128;
    if(PVGSelfReadV1((void *)(shared+0xfc0),sizeof(result->phase),&result->phase))result->known|=256;
    return;
}
static void PGDisplayObservationLogV1(const char *entry,uint64_t ordinal,
    uintptr_t callerRVA,id receiver,const PGDisplayObservationV1 *before,
    const PGDisplayObservationV1 *after) {
    dprintf(2,"[VM27OwnedPGDisplayHandshakeV1] entry=%s ordinal=%llu callerRVA=0x%lx self=%p beforeKnown=0x%x beforeMapping=%u beforeShared=%u beforeClient=%u beforeModeList=%u beforePhase=%u beforeModeCount=%u beforeSeq=%u beforeAck=%u beforePending=%u afterKnown=0x%x afterMapping=%u afterShared=%u afterClient=%u afterModeList=%u afterPhase=%u afterModeCount=%u afterSeq=%u afterAck=%u afterPending=%u actualOriginalIMPInvokedOnce=1 nativeReturned=1 observationOnly=1\n",
        entry,(unsigned long long)ordinal,(unsigned long)callerRVA,(void *)receiver,
        before->known,before->mappingPresent,before->sharedPresent,before->clientPresent,
        before->modeListPresent,before->phase,(unsigned)before->modeCount,before->sequence,
        before->ack,(unsigned)before->pending,after->known,after->mappingPresent,
        after->sharedPresent,after->clientPresent,after->modeListPresent,after->phase,
        (unsigned)after->modeCount,after->sequence,after->ack,(unsigned)after->pending);
}
__attribute__((visibility("default")))
void VM27OwnedPGDisplayStateMachineObserveV1(id receiver,SEL selector,const char *originalCaller) {
    int incoming=errno;uintptr_t callerRVA=0;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    IMP original=PGDisplayObservationOriginalV1(receiver,selector,caller,0,&callerRVA);
    uint64_t ordinal=PGDisplayObservationOrdinalV1(&PGDisplayStateOrdinalV1);
    BOOL observe=ordinal<=16;PGDisplayObservationV1 before={0};
    if(observe)PGDisplayObservationReadV1(receiver,&before);
    errno=incoming;
    ((void(*)(id,SEL,const char *))original)(receiver,selector,originalCaller);
    int nativeErrno=errno;
    if(observe) {
        PGDisplayObservationV1 after={0};PGDisplayObservationReadV1(receiver,&after);
        PGDisplayObservationLogV1("state",ordinal,callerRVA,receiver,&before,&after);
    }
    errno=nativeErrno;
}
__attribute__((visibility("default")))
void VM27OwnedPGDisplaySwapObserveV1(id receiver,SEL selector,uint64_t mappingID,
    uint64_t gammaOffset,uint64_t gammaLength,uint32_t gammaEntries,uint32_t gammaSum) {
    int incoming=errno;uintptr_t callerRVA=0;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    IMP original=PGDisplayObservationOriginalV1(receiver,selector,caller,1,&callerRVA);
    uint64_t ordinal=PGDisplayObservationOrdinalV1(&PGDisplaySwapOrdinalV1);
    BOOL observe=ordinal<=4;PGDisplayObservationV1 before={0};
    if(observe)PGDisplayObservationReadV1(receiver,&before);
    errno=incoming;
    ((void(*)(id,SEL,uint64_t,uint64_t,uint64_t,uint32_t,uint32_t))original)
        (receiver,selector,mappingID,gammaOffset,gammaLength,gammaEntries,gammaSum);
    int nativeErrno=errno;
    if(observe) {
        PGDisplayObservationV1 after={0};PGDisplayObservationReadV1(receiver,&after);
        PGDisplayObservationLogV1("swap",ordinal,callerRVA,receiver,&before,&after);
    }
    errno=nativeErrno;
}
