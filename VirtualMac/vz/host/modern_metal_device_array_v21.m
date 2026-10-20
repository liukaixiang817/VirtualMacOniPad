/* Preserve all frozen V8 capabilities, Shared paths and earlier reason routes. */
#include "modern_metal_device_array_v22.m"
#include "vm27_owned_child_vm_result_diagnostic_v1.h"

static const uint8_t VM27ChildInitializePrefixV1[32]={
    0x7f,0x23,0x03,0xd5,0xfc,0x6f,0xba,0xa9,
    0xfa,0x67,0x01,0xa9,0xf8,0x5f,0x02,0xa9,
    0xf6,0x57,0x03,0xa9,0xf4,0x4f,0x04,0xa9,
    0xfd,0x7b,0x05,0xa9,0xfd,0x43,0x01,0x91
};
static unsigned VM27ChildInitializeLogCountV1;
static void *VM27ChildInitializeOriginalV1(void *caller) {
    int saved=errno;uint32_t status=0;uint8_t uuid[16],prefix[32];
    char path[4096]={0},canonical[4096]={0};uint32_t capacity=sizeof(path);Dl_info owner={0};
    BOOL valid=getuid()==501 && geteuid()==501 && getpid()>1 &&
        !csops(getpid(),0,&status,sizeof(status)) && (status&UINT32_C(0x04000001))==UINT32_C(0x04000001) &&
        !_NSGetExecutablePath(path,&capacity) && capacity<=sizeof(path) && memchr(path,0,sizeof(path)) &&
        realpath(path,canonical) && !strcmp(canonical,PVGChildPathV1) &&
        caller && dladdr(caller,&owner) && owner.dli_fname && !strcmp(owner.dli_fname,PVGChildPathV1) &&
        PVGReadUUIDV1(owner.dli_fbase,MH_EXECUTE,uuid) && !memcmp(uuid,PVGChildUUIDV1,16) &&
        (uintptr_t)caller>=(uintptr_t)owner.dli_fbase &&
        (uintptr_t)caller-(uintptr_t)owner.dli_fbase==0x24a78;
    void *original=valid ? (uint8_t*)owner.dli_fbase+0x2e9b24 : NULL;
    if(!valid || !PVGSelfReadV1(original,sizeof(prefix),prefix) || memcmp(prefix,VM27ChildInitializePrefixV1,sizeof(prefix))) {
        dprintf(2,"[VM27OwnedChildVMResultV1] admission=0 originalNotCalled=1 resultNotClaimed=1\n");
        errno=ENOTSUP;__builtin_trap();
    }
    errno=saved;return ptrauth_sign_unauthenticated(original,ptrauth_key_function_pointer,0);
}
static BOOL VM27ChildInitializeLogV1(void) {
    unsigned n=__atomic_load_n(&VM27ChildInitializeLogCountV1,__ATOMIC_RELAXED);
    while(n<8)if(__atomic_compare_exchange_n(&VM27ChildInitializeLogCountV1,&n,n+1,NO,__ATOMIC_RELAXED,__ATOMIC_RELAXED))return YES;
    return NO;
}
static void VM27ChildInitializeObserveV1(const void *result) {
    uint8_t actual[49]={0};BOOL read=PVGSelfReadV1(result,sizeof(actual),actual);
    if(!read) {
        dprintf(2,"[VM27OwnedChildVMResultV1] stage=return resultUnavailable=1 nativeCalledOnce=1 resultUnmodified=1\n");return;
    }
    unsigned valid=actual[48];
    if(valid!=0) {
        dprintf(2,"[VM27OwnedChildVMResultV1] stage=return actualValidByte=%u failureFieldsNotRead=1 nativeCalledOnce=1 resultUnmodified=1 guestRunningNotClaimed=1\n",valid);return;
    }
    int32_t variant=0;memcpy(&variant,actual+40,sizeof(variant));
    char payload[17]={0};static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<8;++i){payload[i*2]=hex[actual[32+i]>>4];payload[i*2+1]=hex[actual[32+i]&15];}
    VM27ChildReasonSnapshotV1 reason={0};VM27ChildReasonCaptureV1((const uint8_t*)result+8,&reason);
    dprintf(2,"[VM27OwnedChildVMResultV1] stage=return actualValidByte=0 actualVariantIndex=%d opaqueVariantBytes=%s nativeCalledOnce=1 resultUnmodified=1\n",variant,payload);
    /* This is the native returned Error, observed before its original caller
     * copies/moves/frees it. Read failures remain diagnostic-only. */
    VM27ChildReasonObserveV1(result,0x24a78,&reason);
}
__attribute__((visibility("default")))
void VM27OwnedChildInitializeVMResultDiagnosticV1(void *result,void *actualVM,void *actualConfig) {
    int incoming=errno;void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    typedef void(*NativeInitializeV1)(void*,void*,void*);
    NativeInitializeV1 original=(NativeInitializeV1)VM27ChildInitializeOriginalV1(caller);
    BOOL log=VM27ChildInitializeLogV1();
    if(log)dprintf(2,"[VM27OwnedChildVMResultV1] stage=enter callerRVA=0x24a78 originalRVA=0x2e9b24 originalCallNext=1 resultNotClaimed=1\n");
    /* No catch: every native exception, all moves and variants propagate. */
    errno=incoming;original(result,actualVM,actualConfig);int nativeErrno=errno;
    if(log)VM27ChildInitializeObserveV1(result);
    errno=nativeErrno;
}
