#include "modern_vz_hypervisor_ipa_acquisition_v1.h"
#include "modern_vz_hypervisor_framework_limits.h"
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define VZ_IPA_ERROR ((int32_t)UINT32_C(0xfae94001))
_Static_assert(sizeof(uint32_t)==4 && CHAR_BIT==8,"Exact original output ABI");
_Static_assert(sizeof(VZFrameworkIPANativeReceiptV1)==72 &&
    offsetof(VZFrameworkIPANativeReceiptV1,queryOwnerThread)==8 &&
    offsetof(VZFrameworkIPANativeReceiptV1,actualNativeReturn)==16 &&
    offsetof(VZFrameworkIPANativeReceiptV1,leftPackedU64)==56 &&
    offsetof(VZFrameworkIPANativeReceiptV1,rightPackedU64)==64,
    "Explicit LP64 receipt1 layout");

static bool Canary(const unsigned char *p,size_t n) {
    for(size_t i=0;i<n;++i) if(p[i]!=0xa5) return false;
    return true;
}
static uint64_t LE64(const unsigned char *p) {
    uint64_t v=0;for(unsigned i=0;i<8;++i) v|=(uint64_t)p[i]<<(8*i);return v;
}
int32_t VZFrameworkQueryMaxIPANativeV1(const VZFrameworkIPAAcquisitionOpsV1 *ops,
    uint32_t *out,VZFrameworkIPANativeReceiptV1 *r) {
    if(!ops || !out || !r || ops->schemaVersion!=1 || !ops->validateOwnProfileAndFrame ||
        !ops->invokeOwnedBufferOp0) return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    memset(r,0,sizeof(*r));r->schemaVersion=1;r->status=VZ_IPA_ERROR;
    if(!ops->validateOwnProfileAndFrame(ops->context,&r->queryOwnerThread) || !r->queryOwnerThread)
        return r->status;
    r->profileAndFrameValidated=1;
    if(sysconf(_SC_PAGESIZE)!=16384) return r->status;
    const size_t page=16384,total=3*page,capacity=352,canary=32;
    unsigned char *allocation=mmap(NULL,total,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(allocation==MAP_FAILED) return r->status;
    unsigned char *middle=allocation+page,*buffer=middle+page-capacity-canary;
    uint32_t actual=0;int32_t status=VZ_IPA_ERROR;
    if(mprotect(middle,page,PROT_READ|PROT_WRITE)==0) {
        memset(middle,0xa5,page);memset(buffer,0,capacity);
        r->alignment32=((uintptr_t)buffer%32)==0;r->originalZeroInput=1;
        bool pre=Canary(middle,(size_t)(buffer-middle)) && Canary(buffer+capacity,canary);
        if(pre && r->alignment32) {
            r->queryCalls=1;
            r->actualNativeReturn=ops->invokeOwnedBufferOp0(ops->context,buffer);
            r->exteriorIntact=Canary(middle,(size_t)(buffer-middle)) &&
                Canary(buffer+capacity,page-(size_t)(buffer+capacity-middle));
            if(r->actualNativeReturn) status=r->actualNativeReturn;
            else if(r->exteriorIntact) {
                r->leftPackedU64=LE64(buffer+VZ_IPA_NATIVE_FIELD_A_OFFSET);
                r->rightPackedU64=LE64(buffer+VZ_IPA_NATIVE_FIELD_B_OFFSET);
                r->packedFieldsKnown=1;
                VZFrameworkNativeIPAInputV1 input={1,VZ_IPA_KERNEL_PROFILE_IPADOS_16_1_1,1,0,0,buffer,capacity};
                status=VZFrameworkComputeMaxIPAFromNativeV1(&input,&actual);
            }
        }
    }
    r->mappingReleased=munmap(allocation,total)==0;
    if(!r->mappingReleased) status=VZ_IPA_ERROR;
    r->status=status;
    if(!status) {r->resultKnown=1;r->minIPA=actual;*out=actual;}
    return status;
}
