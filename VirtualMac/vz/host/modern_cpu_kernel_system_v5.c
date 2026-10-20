#include "modern_cpu_own_feature_profile_v1.h"
#define VZKernelSysApplyVerifiedRouteV3 VM27CPUInheritedSYSRouteV5
#include "modern_cpu_kernel_profile_v2.h"
#include "modern_cpu_kernel_system_v3_private.h"

static const VZKernelSysDescriptor Physical[] = {
#include "modern_cpu_kernel_system_fields_v2.inc"
};
static const uint32_t FeatureIDs[] = {0xc020,0xc021,0xc028,0xc029,0xc030,0xc031,0xc038,0xc039,0xc03a};

VZKernelStatus VZKernelSysLookup(uint32_t identifier, VZKernelSysDescriptor *out) {
    if (!out) return VZ_KERNEL_BAD_ARGUMENT;
    for (uint32_t i = 0; i < 9; ++i) if (identifier == FeatureIDs[i]) {
        *out = (VZKernelSysDescriptor){identifier,VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE,0,8,0,i};
        return VZ_KERNEL_OK;
    }
    if (identifier == 0xc000 || identifier == 0xc005) {
        *out = (VZKernelSysDescriptor){identifier,VZ_KERNEL_SYS_CONTROL,
            identifier == 0xc000 ? 0x698 : 0x690,8,0,identifier == 0xc000 ? 5 : 3};
        return VZ_KERNEL_OK;
    }
    size_t low = 0, high = sizeof(Physical)/sizeof(Physical[0]);
    while (low < high) {
        size_t middle = low + (high - low)/2;
        if (identifier < Physical[middle].identifier) high = middle;
        else if (identifier > Physical[middle].identifier) low = middle + 1;
        else { *out = Physical[middle]; return VZ_KERNEL_OK; }
    }
    return VZ_KERNEL_UNSUPPORTED;
}

bool VZKernelSysNativeFieldAllowed(uint32_t offset, size_t bytes) {
    if (bytes != 8) return false;
    for (size_t i = 0; i < sizeof(Physical)/sizeof(Physical[0]); ++i)
        if (offset == Physical[i].nativeOffset) return true;
    return offset == 0x698 || offset == 0x690;
}

static bool Read(const VZKernelInitAccess *a, VZKernelSysReceipt *r,
    uint32_t offset, uint64_t *out) {
    ++r->attemptedNativeReads;
    if (a->readAt(a->context, offset, 8, out)) return true;
    r->status = VZ_KERNEL_CONTEXT_UNREADABLE;
    return false;
}
static bool Write(const VZKernelInitAccess *a, VZKernelSysReceipt *r,
    uint32_t offset, uint64_t value) {
    if (!(VZKernelSysNativeFieldAllowed(offset, 8) || offset == 0x678 || offset == 0x670 || offset == 0x748)) {
        r->status = VZ_KERNEL_UNSUPPORTED;
        return false;
    }
    ++r->attemptedNativeWrites;
    if (a->writeAt(a->context, offset, 8, &value)) {
        ++r->completedNativeWrites;
        return true;
    }
    r->status = VZ_KERNEL_CONTEXT_UNREADABLE;
    return false;
}
static bool Modify(const VZKernelInitAccess *a, VZKernelSysReceipt *r,
    uint32_t offset, uint64_t set) {
    uint64_t value;
    return Read(a,r,offset,&value) && Write(a,r,offset,value | set);
}

static VZKernelStatus ApplyRoute(const VZKernelSysRequest *q,
    const VZKernelInitAccess *a, VZKernelSysFeatureCache *cache,
    uint64_t *readOutput, VZKernelSysReceipt *r, VZKernelSysPrepareV3 prepare) {
    if (!q || !a || !a->readAt || !a->writeAt || !cache || !r)
        return VZ_KERNEL_BAD_ARGUMENT;
    r->status = VZ_KERNEL_OK;
    if (q->schemaVersion != 1 || q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA) ||
        (q->action != VZ_KERNEL_SYS_READ && q->action != VZ_KERNEL_SYS_WRITE))
        return r->status = VZ_KERNEL_UNSUPPORTED;
    if (q->action == VZ_KERNEL_SYS_READ && !readOutput) return r->status = VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = VZKernelSysLookup(q->identifier, &r->descriptor);
    if (status != VZ_KERNEL_OK) return r->status = status;
    const VZKernelSysDescriptor *d = &r->descriptor;
    uint64_t actual;
    if (d->domain == VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE) {
        // Values enter only through the explicit typed SYS setter on this own
        // CPU. Unwritten fresh entries have no invented capability value.
        uint16_t bit = (uint16_t)(1u << d->auxiliaryIndex);
        if (q->action == VZ_KERNEL_SYS_WRITE) {
            cache->values[d->auxiliaryIndex] = q->value;
            cache->valid |= bit;
            r->privateFeatureWrites = 1;
        } else {
            if (!(cache->valid & bit)) return r->status = VZ_KERNEL_UNSUPPORTED;
            *readOutput = cache->values[d->auxiliaryIndex];
            r->privateFeatureRead = true;
        }
    } else if (d->domain == VZ_KERNEL_SYS_CONTROL) {
        if (q->action == VZ_KERNEL_SYS_READ) {
            if (!Read(a,r,d->nativeOffset,&actual)) return r->status;
            *readOutput = actual;
        } else {
            // c000/c005 public setters tail into genuine control setter5/3.
            if (!Write(a,r,d->nativeOffset,q->value) ||
                !Modify(a,r,0x678,UINT64_C(1)<<56) ||
                !Modify(a,r,0x670,UINT64_C(1)<<18) ||
                !Modify(a,r,0x748,4)) return r->status;
        }
    } else {
        uint64_t mask = d->nativeReadyDirtyMask;
        uint64_t available = 0;
        // Original getter5d30 reads dirty748 even for a mask0 field, and only
        // then reads ready4100 when the descriptor mask is nonzero.
        if (q->action == VZ_KERNEL_SYS_READ && !Read(a,r,0x748,&available)) return r->status;
        if (mask) {
            uint64_t ready;
            if (!Read(a,r,0x4100,&ready)) return r->status;
            available = q->action == VZ_KERNEL_SYS_READ ? available | ready : ready;
            if (!(available & mask)) {
                r->nativeOp8Required = true;
                if (!prepare) return r->status = VZ_KERNEL_UNSUPPORTED;
                VZKernelStatus preparation=prepare(a->context,&r->nativeOp8Invoked);
                if (preparation!=VZ_KERNEL_OK) return r->status=preparation;
                // Original getter5dcc/setter6cd8 reload the same CPU's context
                // and proceed after successful native8. There is no second
                // readiness test or synthetic write to ready4100.

            }
        }
        if (q->action == VZ_KERNEL_SYS_READ) {
            if (!Read(a,r,d->nativeOffset,&actual)) return r->status;
            *readOutput = actual;
        } else {
            if (!Write(a,r,d->nativeOffset,q->value)) return r->status;
            if (mask && !Modify(a,r,0x748,mask)) return r->status;
        }
    }
    if (!prepare) r->nativeOp8Invoked = false; // Preserve legacy private V2 success receipt.
    r->completeModernSYSContract = false;
    r->runAllowed = false;
    return r->status;
}

VZKernelStatus VZKernelSysApplyVerifiedRoute(const VZKernelSysRequest *q,
    const VZKernelInitAccess *a,VZKernelSysFeatureCache *cache,uint64_t *out,VZKernelSysReceipt *r) {
    return ApplyRoute(q,a,cache,out,r,NULL);
}
VZKernelStatus VZKernelSysApplyVerifiedRouteV3(const VZKernelSysRequest *q,
    const VZKernelInitAccess *a,VZKernelSysFeatureCache *cache,uint64_t *out,VZKernelSysReceipt *r,
    VZKernelSysPrepareV3 prepare) {
    return ApplyRoute(q,a,cache,out,r,prepare);
}

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
    return VM27CPUInheritedSYSRouteV5(q,a,cache,out,r,prepare);
}
