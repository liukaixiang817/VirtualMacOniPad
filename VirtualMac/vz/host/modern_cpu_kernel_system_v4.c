#include "modern_cpu_own_feature_profile_v1.h"
#define VZKernelSysApplyVerifiedRouteV3 VM27CPUInheritedSYSRouteV3
#include "modern_cpu_kernel_system_v3.c"
#undef VZKernelSysApplyVerifiedRouteV3

/* Life22 validates owner, generation, actual returned slot, context version
 * and its operation lease before calling this producer. Both public SYS and
 * private scalar/frame ports reach it; a direct caller cannot bypass the ID
 * policy by using a borrowed CPU adapter. Frozen Life22/System3 are unchanged. */
VZKernelStatus VZKernelSysApplyVerifiedRouteV3(const VZKernelSysRequest *q,
    const VZKernelInitAccess *a,VZKernelSysFeatureCache *cache,uint64_t *out,
    VZKernelSysReceipt *r,VZKernelSysPrepareV3 prepare) {
    if(!q || !a || !a->readAt || !a->writeAt || !cache || !r)
        return VZ_KERNEL_BAD_ARGUMENT;
    if(q->action==VZ_KERNEL_SYS_WRITE) {
        VZKernelStatus status=VM27CPUOwnProfileValidateSYSWriteV1(q->identifier,q->value);
        if(status!=VZ_KERNEL_OK)return r->status=status;
    }
    return VM27CPUInheritedSYSRouteV3(q,a,cache,out,r,prepare);
}
