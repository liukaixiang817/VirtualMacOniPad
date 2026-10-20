#include "modern_cpu_kernel_profile_v2.h"
#include "modern_cpu_kernel_initialization_v3_private.h"
#include <string.h>

static const uint32_t ControlOffsets[17] = {
    0x670, 0x680, 0x688, 0x690, 0x6a0, 0x698, 0x678, 0x6e0, 0x6e8,
    0x6f0, 0x740, 0x6a8, 0x6b0, 0x6b8, 0x6c0, 0x6c8, 0x6d0
};

static bool ScalarField(uint32_t identifier, uint32_t *offset, size_t *bytes) {
    if (identifier > 34) return false;
    *bytes = identifier > 31 ? 4 : 8;
    if (identifier < 31) *offset = 8 + identifier * 8;
    else {
        static const uint32_t offsets[] = {0x108, 0x344, 0x340, 0x110};
        *offset = offsets[identifier - 31];
    }
    return true;
}

bool VZKernelInitOffsetWritable(uint32_t offset, size_t bytes) {
    for (uint32_t id = 0; id <= 34; ++id) {
        uint32_t scalarOffset; size_t scalarBytes;
        if (ScalarField(id, &scalarOffset, &scalarBytes) &&
            offset == scalarOffset && bytes == scalarBytes) return true;
    }
    if (bytes == 16 && offset >= 0x140 && offset <= 0x330 && !(offset & 15)) return true;
    if (bytes != 8) return false;
    for (uint32_t i = 0; i < 17; ++i) if (offset == ControlOffsets[i]) return true;
    return offset == 0x748;
}

static bool Read(const VZKernelInitAccess *a, VZKernelInitReceipt *r,
    uint32_t offset, size_t bytes, void *out) {
    ++r->attemptedReads;
    if (a->readAt(a->context, offset, bytes, out)) return true;
    r->failedNativeOffset = offset;
    r->status = VZ_KERNEL_CONTEXT_UNREADABLE;
    return false;
}

static bool Write(const VZKernelInitAccess *a, VZKernelInitReceipt *r,
    uint32_t offset, size_t bytes, const void *value) {
    // Both the offset-only engine and lifecycle boundary enforce this closure.
    if (!VZKernelInitOffsetWritable(offset, bytes)) {
        r->status = VZ_KERNEL_UNSUPPORTED;
        return false;
    }
    ++r->attemptedWrites;
    if (a->writeAt(a->context, offset, bytes, value)) {
        ++r->completedWrites;
        return true;
    }
    r->failedWriteOrdinal = r->attemptedWrites;
    r->failedNativeOffset = offset;
    r->status = VZ_KERNEL_CONTEXT_UNREADABLE;
    return false;
}

static bool Modify(const VZKernelInitAccess *a, VZKernelInitReceipt *r,
    uint32_t offset, uint64_t clear, uint64_t set) {
    uint64_t value;
    if (!Read(a, r, offset, 8, &value)) return false;
    value = (value & ~clear) | set;
    return Write(a, r, offset, 8, &value);
}

VZKernelStatus VZKernelInitApplyVerifiedSlice(const VZKernelInitRequest *q,
    const VZKernelInitAccess *a, VZKernelInitReceipt *r) {
    if (!q || !a || !a->readAt || !a->writeAt || !r) return VZ_KERNEL_BAD_ARGUMENT;
    r->status = VZ_KERNEL_OK;
    if (q->schemaVersion != 1 ||
        q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA))
        return r->status = VZ_KERNEL_UNSUPPORTED;
    if (q->operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY) {
        // Explicit private DEFAULT config semantics. Genuine modern vmkey
        // getters/nondefault keys and the old userspace feature cache are NOT
        // implemented here; no Apple config object is copied or forged.
        uint64_t zero = 0;
        if (q->identifier || q->low || q->high) return r->status = VZ_KERNEL_UNSUPPORTED;
        if (!Write(a, r, 0x6e8, 8, &zero) || !Write(a, r, 0x6e0, 8, &zero) ||
            !Modify(a, r, 0x678, 0, UINT64_C(1) << 56) ||
            !Modify(a, r, 0x670, 0, UINT64_C(1) << 18)) return r->status;
        uint8_t policy;
        if (!Read(a, r, 0x4030, 1, &policy)) return r->status;
        r->kernelPolicyBit4Read = true;
        r->kernelPolicyBit4 = (policy & 0x10) != 0;
        if (r->kernelPolicyBit4 && !Modify(a, r, 0x670, UINT64_C(1) << 20, 0)) return r->status;
        if (!Modify(a, r, 0x670, 0, UINT64_C(1) << 19) ||
            !Modify(a, r, 0x748, 0, UINT64_C(1) << 2)) return r->status;
        r->creationPolicySliceComplete = true;
    } else if (q->operation == VZ_KERNEL_INIT_SCALAR) {
        uint32_t offset; size_t bytes;
        if (!ScalarField(q->identifier, &offset, &bytes) || q->high)
            return r->status = VZ_KERNEL_UNSUPPORTED;
        if (bytes == 4) {
            // Original public setter consumes w2: truncate to the real32-bit
            // field, without copying stale high bytes or changing dirty bits.
            uint32_t value = (uint32_t)q->low;
            if (!Write(a, r, offset, bytes, &value)) return r->status;
        } else if (!Write(a, r, offset, bytes, &q->low)) return r->status;
    } else if (q->operation == VZ_KERNEL_INIT_SIMD) {
        if (q->identifier >= 32) return r->status = VZ_KERNEL_UNSUPPORTED;
        uint64_t words[2] = {q->low, q->high};
        if (!Write(a, r, 0x140 + 16 * q->identifier, 16, words)) return r->status;
    } else if (q->operation == VZ_KERNEL_INIT_CONTROL) {
        if (q->identifier >= 17 || q->high) return r->status = VZ_KERNEL_UNSUPPORTED;
        // Original57d8 writes requested native field FIRST, then reads current
        // synchronization words. Identifier0/6 may alias these words; preserve
        // that actual alias/order rather than snapshotting all inputs first.
        if (!Write(a, r, ControlOffsets[q->identifier], 8, &q->low) ||
            !Modify(a, r, 0x678, 0, UINT64_C(1) << 56) ||
            !Modify(a, r, 0x670, 0, UINT64_C(1) << 18) ||
            !Modify(a, r, 0x748, 0, UINT64_C(1) << 2)) return r->status;
    } else return r->status = VZ_KERNEL_UNSUPPORTED;
    // This module has no RUN primitive. Do not let a caller claim completion
    // with flags, successful scalar writes or a copied production dirty mask.
    r->architecturalResetComplete = false;
    r->runAllowed = false;
    return r->status;
}

VZKernelStatus VZKernelInitApplyCreationConfigV3(const VZKernelInitRequest *q,
    const VZKernelInitAccess *a, VZKernelInitReceipt *r) {
    if (!q || !a || !a->readAt || !a->writeAt || !r) return VZ_KERNEL_BAD_ARGUMENT;
    if (q->schemaVersion != 1 || q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA) ||
        q->operation != VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY || q->identifier)
        return r->status = VZ_KERNEL_UNSUPPORTED;
    r->status = VZ_KERNEL_OK;
    // Actual original0e create5544..55b8: key16 first, key24 second, then the
    // native read/modify/write policy sequence. No zero-before-set workaround.
    if (!Write(a,r,0x6e8,8,&q->low) || !Write(a,r,0x6e0,8,&q->high) ||
        !Modify(a,r,0x678,0,UINT64_C(1)<<56) ||
        !Modify(a,r,0x670,0,UINT64_C(1)<<18)) return r->status;
    uint8_t policy;
    if (!Read(a,r,0x4030,1,&policy)) return r->status;
    r->kernelPolicyBit4Read = true; r->kernelPolicyBit4 = (policy & 0x10) != 0;
    if (r->kernelPolicyBit4 && !Modify(a,r,0x670,UINT64_C(1)<<20,0)) return r->status;
    if (!Modify(a,r,0x670,0,UINT64_C(1)<<19) ||
        !Modify(a,r,0x748,0,UINT64_C(1)<<2)) return r->status;
    r->creationPolicySliceComplete = true;
    r->architecturalResetComplete = false; r->runAllowed = false;
    return r->status;
}
