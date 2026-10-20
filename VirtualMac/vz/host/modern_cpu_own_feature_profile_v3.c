#include "modern_cpu_own_feature_profile_v1.h"

#define PFR0_WITHHELD_V1 (UINT64_C(0xff00) | (UINT64_C(15)<<32))
#define PFR1_WITHHELD_V1 (~UINT64_C(0xf0))
#define MMFR1_VH_V1 (UINT64_C(15)<<8)
#define MMFR2_NV_V1 (UINT64_C(15)<<24)

VZKernelStatus VM27CPUOwnProfileGetFeatureV1(const VZKernelCapabilitySeed *seed,
    uint32_t selector,uint64_t *out) {
    if(!seed || !out)return VZ_KERNEL_BAD_ARGUMENT;
    if(selector>=18)return VZ_KERNEL_UNSUPPORTED;
    uint64_t value=0;
    if(selector<12) {
        VZKernelStatus status=VZKernelCapabilitySeedGetFeature(seed,selector,&value);
        if(status!=VZ_KERNEL_OK)return status;
        if(selector==7) {
            value&=~PFR0_WITHHELD_V1;
            unsigned csv2=(unsigned)((value>>56)&15);
            if(csv2>3)return VZ_KERNEL_UNSUPPORTED;
            // Own virtual-CPU profile withholds FEAT_CSV2_2 because the
            // native backend has no SCXTNUM state/guest implementation.
            if(csv2>=2)value=(value&~(UINT64_C(15)<<56))|(UINT64_C(1)<<56);
        }
        else if(selector==8)value&=~PFR1_WITHHELD_V1;
        else if(selector==5)value&=~MMFR1_VH_V1;
        else if(selector==6)value&=~MMFR2_NV_V1;
    }
    /* 12 SMFR0 and 13 ZFR0 have no implemented SME/SVE feature in this
     * profile. 14 ISAR2, 15 PFR2 and 16 MMFR3 add no architecture extension.
     * 17 MMFR4 adds none either: E2H0 is RES0 when AA64EL2 is absent, while
     * NV_frac has no additional NV capability when MMFR2.NV is zero.
     * These are own architectural policy values, not native response reads. */
    *out=value;
    return VZ_KERNEL_OK;
}

VZKernelStatus VM27CPUOwnProfileValidateSYSWriteV1(uint32_t selector,uint64_t value) {
    uint64_t withheld=0;
    switch(selector) {
    case 0xc028:
        // This backend already advertises DFR0.PMUVer=0 at its real seed.
        // A later SYS write cannot silently enable an unimplemented PMU.
        if(value&UINT64_C(0xf00))return VZ_KERNEL_UNSUPPORTED;
        return VZ_KERNEL_OK;
    case 0xc020:
        if(((value>>56)&15)>1)return VZ_KERNEL_UNSUPPORTED;
        withheld=PFR0_WITHHELD_V1;break;
    case 0xc021:withheld=PFR1_WITHHELD_V1;break;
    case 0xc039:withheld=MMFR1_VH_V1;break;
    case 0xc03a:withheld=MMFR2_NV_V1;break;
    default:return VZ_KERNEL_OK;
    }
    return (value&withheld)?VZ_KERNEL_UNSUPPORTED:VZ_KERNEL_OK;
}
