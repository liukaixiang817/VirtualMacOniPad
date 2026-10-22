/* Retains Life29 native lifecycle and AMX query; adds owned WFx wait with
 * genuine physical and virtual timer deadlines. */
#include "wfx_wait_v77/modern_cpu_kernel_lifecycle_v27.c"
#include "modern_cpu_kernel_lifecycle_v28_private.h"

static VZKernelStatus AMXIdentityV28(VZKernelCPU *cpu,
    const VZKernelAMXAvailabilityIdentityV28 *q) {
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        return VZ_KERNEL_WRONG_THREAD;
    VZKernelStatus status = CPUOwnedV5(cpu);
    if (status != VZ_KERNEL_OK) return status;
    Lock(&cpu->vm->mutex);
    VZKernelCPURegistryEntryV5 *entry = cpu->registryEntry;
    bool same = q->identity && q->vmEpoch && q->cpuGeneration && !q->reserved &&
        q->identity == entry->publicIdentity && entry->identityIssued &&
        entry->published && !entry->draining && entry->creationComplete &&
        q->vmEpoch == cpu->vm->generation && q->cpuGeneration == cpu->generation &&
        q->ownerThread == cpu->owner && q->returnedSlotWord == cpu->returnedSlot &&
        q->nativeHVISA == cpu->vm->nativeHVISA;
    bool ready = cpu->creationPolicySliceComplete && cpu->creationConfigComplete &&
        !cpu->mutationPoisoned;
    Unlock(&cpu->vm->mutex);
    if (!same) return VZ_KERNEL_BAD_ARGUMENT;
    if (!ready) return VZ_KERNEL_BUSY;
    return cpu->vm->ops.validatedKernelProfile == VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
        VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA) ?
        VZ_KERNEL_OK : VZ_KERNEL_UNSUPPORTED;
}

static VZKernelStatus AMXReadWordV28(VZKernelCPU *cpu, uint32_t offset,
    const VZKernelAMXAvailabilityIdentityV28 *q, uint64_t *out) {
    VZKernelStatus status = AMXIdentityV28(cpu, q);
    VZKernelLifecycleResult version = {0};
    if (status == VZ_KERNEL_OK) status = Version(cpu, &version);
    if (status != VZ_KERNEL_OK) return status;
    if ((offset != 0x4108 && offset != 0x4110) ||
        cpu->nativeContext > UINTPTR_MAX - offset - sizeof(*out) ||
        !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext + offset),
            sizeof(*out), false, NULL)) return VZ_KERNEL_CONTEXT_UNREADABLE;
    if (!cpu->vm->ops.readMemory(cpu->vm->ops.context,
        (const void *)(cpu->nativeContext + offset), sizeof(*out), out))
        return VZ_KERNEL_CONTEXT_UNREADABLE;
    status = AMXIdentityV28(cpu, q);
    return status == VZ_KERNEL_OK ? Version(cpu, &version) : status;
}

VZKernelStatus VZKernelCPUGetAMXAvailabilityV28(VZKernelCPU *cpu,
    const VZKernelAMXAvailabilityIdentityV28 *input, const void *publicationTarget, uint32_t *out) {
    if (!cpu || !input || !publicationTarget || !out) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status == VZ_KERNEL_BUSY) return status;
    if (status != VZ_KERNEL_OK) {
        EndOperation(&cpu->operationInProgress); return status;
    }
    Lock(&RegistryMutex); Lock(&cpu->vm->mutex);
    bool disjoint = OutputAllPrivateDisjointLockedV5(cpu->vm, input, sizeof(*input)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm, out, sizeof(*out)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm, publicationTarget, sizeof(*out)) &&
        PendingOutputDisjointV3(input, sizeof(*input), out, sizeof(*out));
    /* Native6 maps two real 16 KiB pages for each CPU. The older common
     * output guard ends at4108; protect every registered CPU's whole actual
     * mapping, including the new synchronization words and the second page.
     * Compare addresses only; never read another CPU's state. */
    for (VZKernelCPURegistryEntryV5 *entry = cpu->vm->cpuRegistry;
        disjoint && entry; entry = entry->next) {
        if (entry->cpu && entry->cpu->nativeContext)
            disjoint = PendingOutputDisjointV3(publicationTarget, sizeof(*out),
                (const void *)entry->cpu->nativeContext, 0x8000);
    }
    Unlock(&cpu->vm->mutex); Unlock(&RegistryMutex);
    VZKernelAMXAvailabilityIdentityV28 q = *input;
    if (!disjoint) status = VZ_KERNEL_BAD_ARGUMENT;
    if (status == VZ_KERNEL_OK) status = AMXIdentityV28(cpu, &q);
    uint64_t before[2] = {0}, after[2] = {0};
    if (status == VZ_KERNEL_OK) status = AMXReadWordV28(cpu, 0x4108, &q, &before[0]);
    if (status == VZ_KERNEL_OK) status = AMXReadWordV28(cpu, 0x4110, &q, &before[1]);
    if (status == VZ_KERNEL_OK) status = AMXReadWordV28(cpu, 0x4108, &q, &after[0]);
    if (status == VZ_KERNEL_OK) status = AMXReadWordV28(cpu, 0x4110, &q, &after[1]);
    if (status == VZ_KERNEL_OK && memcmp(before, after, sizeof(before))) status = VZ_KERNEL_BUSY;
    uint32_t staged = VM27_AMX_ABSENT_V1;
    if (status == VZ_KERNEL_OK) {
        /* Actual native1 stores this immutable mask in the successfully
         * created VM. native9 rejects any dirty intersection before entry.
         * Both validated native profiles forbid AMX bit57. In contrast,
         * inactive4108 is a synchronization word: native9 can rewrite it to
         * ~active4110. It must never promote an unsupported guest feature. */
        const uint64_t forbidden = q.nativeHVISA == 1 ?
            UINT64_C(0xdf00000000000000) : UINT64_C(0xcf00000000000000);
        const uint64_t bank = UINT64_C(1) << 57;
        if (before[1] & forbidden) status = VZ_KERNEL_UNSUPPORTED;
        else if (forbidden & bank) staged = VM27_AMX_ABSENT_V1;
        else if ((before[0] | before[1]) & bank) staged = VM27_AMX_PRESENT_V1;
        else status = VZ_KERNEL_UNSUPPORTED;
    }
    if (status == VZ_KERNEL_OK) status = AMXIdentityV28(cpu, &q);
    if (status == VZ_KERNEL_OK) *out = staged;
    EndOperation(&cpu->operationInProgress);
    return status;
}
