/* Frozen V6 Metal capabilities and Shared resource paths are included whole. */
#include "modern_metal_device_array_v6.m"
#include "vm27_owned_child_error_reason_diagnostic_v1.h"

static unsigned VM27ChildReasonLogCountV1;
static const uintptr_t VM27ChildReasonCallersV1[] = {
    0x2ea2f0,0x2eb430,0x2eb4ec,0x2eb958,0x2ec310,0x2ec440,
    0x2ec5f0,0x2ec7a4,0x2ec7f0,0x2ecc68,0x2eccbc
};
static const uint8_t VM27ChildReasonOriginalPrefixV1[32] = {
    0x7f,0x23,0x03,0xd5,0xff,0x03,0x02,0xd1,
    0xf8,0x5f,0x04,0xa9,0xf6,0x57,0x05,0xa9,
    0xf4,0x4f,0x06,0xa9,0xfd,0x7b,0x07,0xa9,
    0xfd,0xc3,0x01,0x91,0xf3,0x03,0x00,0xaa
};
static void *VM27ChildReasonOriginalV1(void *caller, uintptr_t *rva) {
    int saved=errno; uint32_t status=0; uint8_t uuid[16],prefix[32];
    Dl_info owner={0}; char path[4096]={0},canonical[4096]={0}; uint32_t capacity=sizeof(path);
    BOOL valid=getuid()==501 && geteuid()==501 && getpid()>1 &&
        !csops(getpid(),0,&status,sizeof(status)) && (status&UINT32_C(0x04000001))==UINT32_C(0x04000001) &&
        !_NSGetExecutablePath(path,&capacity) && capacity<=sizeof(path) && memchr(path,0,sizeof(path)) &&
        realpath(path,canonical) && !strcmp(canonical,PVGChildPathV1) &&
        caller && dladdr(caller,&owner) && owner.dli_fname && !strcmp(owner.dli_fname,PVGChildPathV1) &&
        PVGReadUUIDV1(owner.dli_fbase,MH_EXECUTE,uuid) && !memcmp(uuid,PVGChildUUIDV1,16) &&
        (uintptr_t)caller>=(uintptr_t)owner.dli_fbase;
    if(valid) {
        *rva=(uintptr_t)caller-(uintptr_t)owner.dli_fbase; valid=NO;
        for(unsigned i=0;i<sizeof(VM27ChildReasonCallersV1)/sizeof(VM27ChildReasonCallersV1[0]);++i)
            if(*rva==VM27ChildReasonCallersV1[i]){valid=YES;break;}
    }
    void *original=valid ? (uint8_t*)owner.dli_fbase+0x3e4fb0 : NULL;
    if(!valid || !PVGSelfReadV1(original,sizeof(prefix),prefix) ||
        memcmp(prefix,VM27ChildReasonOriginalPrefixV1,sizeof(prefix))) {
        dprintf(2,"[VM27OwnedChildErrorV1] admission=0 originalNotCalled=1 resultNotClaimed=1\n");
        errno=ENOTSUP; __builtin_trap();
    }
    errno=saved;
    return ptrauth_sign_unauthenticated(original,ptrauth_key_function_pointer,0);
}
static BOOL VM27ChildReasonLogV1(void) {
    unsigned n=__atomic_load_n(&VM27ChildReasonLogCountV1,__ATOMIC_RELAXED);
    while(n<8)if(__atomic_compare_exchange_n(&VM27ChildReasonLogCountV1,&n,n+1,NO,__ATOMIC_RELAXED,__ATOMIC_RELAXED))return YES;
    return NO;
}
typedef struct { BOOL available; uint64_t length; size_t count; uint8_t bytes[256]; } VM27ChildReasonSnapshotV1;
static void VM27ChildReasonCaptureV1(const void *source,VM27ChildReasonSnapshotV1 *out) {
    uint8_t string[24]={0}; BOOL read=PVGSelfReadV1(source,sizeof(string),string);
    const void *characters=NULL;
    if(read) {
        /* Snapshot native alternate libc++ string BEFORE the original move.
         * No guest/input memory is ever written or retained by this observer. */
        if(string[23]&0x80) {
            uintptr_t address=0;memcpy(&address,string,sizeof(address));
            memcpy(&out->length,string+8,sizeof(out->length));characters=(const void*)address;
        } else {
            out->length=string[23];characters=source;
            if(out->length>22)read=NO;
        }
    }
    out->count=out->length>sizeof(out->bytes)?sizeof(out->bytes):(size_t)out->length;
    out->available=read && (!out->count || PVGSelfReadV1(characters,out->count,out->bytes));
}
static void VM27ChildReasonObserveV1(const void *destination,uintptr_t callerRVA,const VM27ChildReasonSnapshotV1 *snapshot) {
    uint32_t code=0; BOOL codeRead=PVGSelfReadV1(destination,sizeof(code),&code);
    char escaped[1025]={0};size_t out=0;static const char hex[]="0123456789abcdef";
    if(snapshot->available)for(size_t i=0;i<snapshot->count;++i) {
        unsigned c=snapshot->bytes[i];
        if(c>=32 && c<=126 && c!='"' && c!='\\')escaped[out++]=(char)c;
        else {escaped[out++]='\\';escaped[out++]='x';escaped[out++]=hex[c>>4];escaped[out++]=hex[c&15];}
    }
    escaped[out]=0;
    dprintf(2,"[VM27OwnedChildErrorV1] callerRVA=0x%lx codeRead=%u code=%u reasonRead=%u reasonUnavailable=%u reasonLength=%llu capturedBytes=%lu truncated=%u reason=\"%s\" nativeCalledOnce=1 errorSemanticsUnchanged=1\n",
        (unsigned long)callerRVA,codeRead?1U:0U,code,snapshot->available?1U:0U,snapshot->available?0U:1U,
        (unsigned long long)snapshot->length,(unsigned long)(snapshot->available?snapshot->count:0),snapshot->length>sizeof(snapshot->bytes)?1U:0U,escaped);
}
__attribute__((visibility("default")))
void VM27OwnedChildBuildErrorReasonDiagnosticV1(void *destination,void *movedString) {
    int incoming=errno;uintptr_t callerRVA=0;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    typedef void(*NativeErrorConstructorV1)(void*,void*);
    NativeErrorConstructorV1 original=(NativeErrorConstructorV1)VM27ChildReasonOriginalV1(caller,&callerRVA);
    BOOL log=VM27ChildReasonLogV1();VM27ChildReasonSnapshotV1 snapshot={0};
    if(log)VM27ChildReasonCaptureV1(movedString,&snapshot);
    /* Any observer read/decoding failure is diagnostic only. The original still
     * performs all native moves, allocations and variants exactly once. */
    errno=incoming;original(destination,movedString);int nativeErrno=errno;
    if(log)VM27ChildReasonObserveV1(destination,callerRVA,&snapshot);
    errno=nativeErrno;
}
