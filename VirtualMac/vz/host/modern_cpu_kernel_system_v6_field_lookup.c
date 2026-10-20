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
    // Exact union of the unchanged Physical descriptors and control fields.
    // Constant lookup removes a linear scan from every native state access.
    switch (offset) {
        case 0x350:
        case 0x358:
        case 0x360:
        case 0x368:
        case 0x370:
        case 0x378:
        case 0x380:
        case 0x388:
        case 0x398:
        case 0x3a0:
        case 0x3a8:
        case 0x3b0:
        case 0x3b8:
        case 0x3c0:
        case 0x3c8:
        case 0x3d0:
        case 0x3d8:
        case 0x3e0:
        case 0x3e8:
        case 0x400:
        case 0x408:
        case 0x410:
        case 0x418:
        case 0x420:
        case 0x428:
        case 0x430:
        case 0x440:
        case 0x450:
        case 0x458:
        case 0x460:
        case 0x468:
        case 0x470:
        case 0x478:
        case 0x480:
        case 0x488:
        case 0x490:
        case 0x498:
        case 0x4a0:
        case 0x4a8:
        case 0x4b0:
        case 0x4b8:
        case 0x4c0:
        case 0x4c8:
        case 0x4d0:
        case 0x4d8:
        case 0x4e0:
        case 0x4e8:
        case 0x4f0:
        case 0x4f8:
        case 0x500:
        case 0x508:
        case 0x510:
        case 0x518:
        case 0x520:
        case 0x528:
        case 0x530:
        case 0x538:
        case 0x540:
        case 0x548:
        case 0x550:
        case 0x558:
        case 0x560:
        case 0x568:
        case 0x570:
        case 0x578:
        case 0x580:
        case 0x588:
        case 0x590:
        case 0x598:
        case 0x5a0:
        case 0x5a8:
        case 0x5b0:
        case 0x5b8:
        case 0x5c0:
        case 0x5c8:
        case 0x5d0:
        case 0x5d8:
        case 0x5e0:
        case 0x5e8:
        case 0x5f0:
        case 0x5f8:
        case 0x600:
        case 0x608:
        case 0x610:
        case 0x618:
        case 0x620:
        case 0x628:
        case 0x630:
        case 0x638:
        case 0x640:
        case 0x648:
        case 0x650:
        case 0x690:
        case 0x698:
        case 0x758:
        case 0x760:
        case 0x768:
        case 0x770:
        case 0x778:
        case 0x780:
        case 0x788:
        case 0x790:
        case 0x798:
        case 0x7a0:
        case 0x7b0:
        case 0x7b8:
        case 0x7c0:
        case 0x7c8:
        case 0x7d0:
        case 0x7d8:
        case 0x7e0:
        case 0x7e8:
        case 0x7f0:
        case 0x7f8:
        case 0x800:
        case 0x808:
        case 0x810:
        case 0x818:
        case 0x820:
        case 0x828:
        case 0x830:
        case 0x838:
        case 0x840:
        case 0x848:
        case 0x850:
        case 0x858:
        case 0x860:
        case 0x868:
        case 0x878:
        case 0x880:
        case 0x888:
        case 0x890:
        case 0x898:
        case 0x8a0:
        case 0x8a8:
        case 0x8b0:
        case 0x8b8:
        case 0x8c0:
        case 0x8c8:
        case 0x8d0:
        case 0x8d8:
        case 0x8e0:
        case 0x8e8:
        case 0x8f0:
        case 0x8f8:
        case 0x900:
        case 0x908:
        case 0x910:
        case 0x918:
        case 0x920:
        case 0x928:
        case 0x930:
        case 0x938:
        case 0x940:
        case 0x948:
        case 0x950:
            return true;
        default: return false;
    }
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
