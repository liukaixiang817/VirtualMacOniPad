#include "modern_cpu_native_capability_seed.h"
#include <string.h>
static uint64_t LoadLE(const unsigned char *p) {
    uint64_t v=0;for(unsigned i=0;i<8;++i)v|=(uint64_t)p[i]<<(8*i);return v;
}
static void StoreLE(unsigned char *p,uint64_t value) {
    for(unsigned i=0;i<8;++i)p[i]=(unsigned char)(value>>(8*i));
}
VZKernelStatus VZKernelComputeNativeCapabilitySeed(const VZKernelCapabilitySeedInput *q,
    VZKernelCapabilitySeed *out,VZKernelCapabilitySeedReceipt *r) {
    if(r){memset(r,0,sizeof(*r));r->pureTransform=true;}
    if(!q||!out||!r||!q->capabilityPrefix){if(r)r->status=VZ_KERNEL_BAD_ARGUMENT;return VZ_KERNEL_BAD_ARGUMENT;}
    if(q->schemaVersion!=1 || q->validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->prefixBytes!=VZ_KERNEL_CAPABILITY_CONSUMED_PREFIX_BYTES ||
        q->sdkPredicateResults[0]>1 || q->sdkPredicateResults[1]>1 || q->sdkPredicateResults[2]>1)
        return r->status=VZ_KERNEL_UNSUPPORTED;
    const unsigned char *p=q->capabilityPrefix;
    VZKernelCapabilitySeed seed={0};
    seed.featureWords[0]=(LoadLE(p+0x100)&UINT64_C(0xf0f0f000))|6;
    seed.featureWords[1]=0; // Exact original store; not an assumed host value.
    seed.featureWords[2]=LoadLE(p+0x110)&UINT64_C(0xfffffffff0fffff0);
    seed.featureWords[3]=LoadLE(p+0x118)&UINT64_C(0x00000fffffffffff);
    uint64_t mmfrMask=UINT64_C(0x0f00f000fff000f0);
    if(q->sdkPredicateResults[0])mmfrMask|=15;
    seed.featureWords[4]=LoadLE(p+0x120)&mmfrMask;
    if(!q->sdkPredicateResults[1])seed.featureWords[4]|=1;
    seed.featureWords[5]=LoadLE(p+0x128)&UINT64_C(0xfffff0f0);
    seed.featureWords[6]=LoadLE(p+0x130)&UINT64_C(0xf0ff00ff000ff0ff);
    seed.featureWords[7]=LoadLE(p+0x138)&UINT64_C(0xff0f0000f0ff00ff);
    if(!q->sdkPredicateResults[2])seed.featureWords[7]|=0x1100;
    seed.featureWords[8]=LoadLE(p+0x140)&0xf0;
    seed.featureWords[9]=LoadLE(p+0x68);
    seed.featureWords[10]=LoadLE(p+0x70);
    seed.featureWords[11]=LoadLE(p+0x78);
    for(unsigned i=0;i<8;++i){seed.instructionCCSIDR[i]=LoadLE(p+0x80+8*i);
        seed.dataUnifiedCCSIDR[i]=LoadLE(p+0xc0+8*i);}
    *out=seed;r->prefixBytesConsumed=q->prefixBytes;r->seedBytesProduced=VZ_KERNEL_FEATURE_SEED_BYTES;
    r->sdkResultsConsumed=3;return r->status=VZ_KERNEL_OK;
}
VZKernelStatus VZKernelCapabilitySeedGetFeature(const VZKernelCapabilitySeed *seed,uint32_t selector,uint64_t *out){
    if(!seed||!out)return VZ_KERNEL_BAD_ARGUMENT;
    if(selector>=12)return VZ_KERNEL_UNSUPPORTED;
    *out=seed->featureWords[selector==10?11:selector==11?10:selector];return VZ_KERNEL_OK;
}
VZKernelStatus VZKernelCapabilitySeedGetSYSFeature(const VZKernelCapabilitySeed *seed,uint32_t selector,uint64_t *out){
    if(!seed||!out)return VZ_KERNEL_BAD_ARGUMENT;
    static const uint32_t ids[]={0xc020,0xc021,0xc028,0xc029,0xc030,0xc031,0xc038,0xc039,0xc03a};
    static const unsigned indices[]={7,8,0,1,2,3,4,5,6};
    for(unsigned i=0;i<9;++i)if(selector==ids[i]){*out=seed->featureWords[indices[i]];return VZ_KERNEL_OK;}
    return VZ_KERNEL_UNSUPPORTED;
}
VZKernelStatus VZKernelCapabilitySeedGetCCSIDR(const VZKernelCapabilitySeed *seed,uint32_t selector,uint64_t out[8]){
    if(!seed||!out)return VZ_KERNEL_BAD_ARGUMENT;
    if(selector>1)return VZ_KERNEL_UNSUPPORTED;
    memcpy(out,selector?seed->instructionCCSIDR:seed->dataUnifiedCCSIDR,8*sizeof(uint64_t));return VZ_KERNEL_OK;
}
VZKernelStatus VZKernelCapabilitySeedEncodeLE(const VZKernelCapabilitySeed *seed,unsigned char out[VZ_KERNEL_FEATURE_SEED_BYTES]){
    if(!seed||!out)return VZ_KERNEL_BAD_ARGUMENT;
    for(unsigned i=0;i<12;++i)StoreLE(out+8*i,seed->featureWords[i]);
    for(unsigned i=0;i<8;++i){StoreLE(out+0x60+8*i,seed->instructionCCSIDR[i]);
        StoreLE(out+0xa0+8*i,seed->dataUnifiedCCSIDR[i]);}return VZ_KERNEL_OK;
}
