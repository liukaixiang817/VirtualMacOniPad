/* Keep the full Factory24 ownership path and all existing failure records. */
#include "modern_cpu_native_public_factory_startup_failure_v1.c"
#include "modern_cpu_kernel_lifecycle_v28_private.h"
#include "modern_vmm_amx_availability_v1.h"

static VZKernelStatus AMXBorrowReadV2(VM27CPUFactoryBorrowV2 *borrow,
    const void *publicationTarget, uint32_t *out) {
    VZKernelStatus status = BeginBorrow(borrow);
    if (status != VZ_KERNEL_OK) return status;
    if (!pthread_equal(pthread_self(), borrow->borrower)) {
        End(&borrow->operation); return VZ_KERNEL_WRONG_THREAD;
    }
    Lock();
    bool valid = ContainsBorrow(borrow);
    Entry *entry = valid ? borrow->entry : NULL;
    bool begun = entry && Begin(&entry->operation);
    Unlock();
    if (!valid) { End(&borrow->operation); return VZ_KERNEL_BAD_ARGUMENT; }
    if (!begun) { End(&borrow->operation); return VZ_KERNEL_BUSY; }
    VZKernelCPU *cpu = NULL;
    status = entry->draining || !entry->configComplete || !entry->complete ||
        !entry->live || !entry->published ? VZ_KERNEL_NOT_LIVE :
        VZKernelCPUBorrowHandleV5(borrow->kernel, &cpu);
    if (status == VZ_KERNEL_OK && (cpu != entry->cpu || Owned != entry ||
        !pthread_equal(pthread_self(), entry->owner))) status = VZ_KERNEL_NOT_LIVE;
    if (status == VZ_KERNEL_OK) {
        const VZKernelAMXAvailabilityIdentityV28 q = {
            entry->identity, borrow->epoch, borrow->generation,
            entry->nativeOwnerThread, entry->returnedSlotWord, entry->vm->nativeISA, 0};
        status = VZKernelCPUGetAMXAvailabilityV28(cpu, &q, publicationTarget, out);
    }
    End(&entry->operation); End(&borrow->operation);
    return status;
}

VM27CPUFactoryMachStatusV2 VM27VMMGetAMXAvailabilityV1(hv_vcpu_t identity, uint32_t *out) {
    if (!PublicBeginV6()) return Mach(VZ_KERNEL_BUSY);
    if (!GICFactoryOutputV15(out, sizeof(*out), true)) {
        PublicEndV6(); return Mach(VZ_KERNEL_BAD_ARGUMENT);
    }
    VM27CPUFactoryBorrowV2 *borrow = NULL;
    VM27CPUFactoryViewV2 before = {0}, after = {0};
    uint32_t staged = UINT32_MAX;
    VM27CPUFactoryMachStatusV2 result = VM27CPUFactoryBorrowAcquireV2(identity, &borrow);
    if (!result) result = VM27CPUFactoryBorrowViewV2(borrow, &before);
    if (!result && (before.identity != identity || !before.identity ||
        !before.vmEpoch || !before.cpuGeneration)) result = Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!result) result = Mach(AMXBorrowReadV2(borrow, out, &staged));
    if (!result) result = VM27CPUFactoryBorrowViewV2(borrow, &after);
    if (!result && (before.identity != after.identity || before.vmEpoch != after.vmEpoch ||
        before.cpuGeneration != after.cpuGeneration || staged > VM27_AMX_PRESENT_V1))
        result = Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (borrow) {
        VM27CPUFactoryMachStatusV2 released = VM27CPUFactoryBorrowReleaseV2(borrow);
        if (released) {
            /* The existing public drain retains this exact real lease. */
            PublicDeferredBorrowV6 = borrow;
            result = released;
        }
    }
    /* A failed lookup, owner/version check, read or release never publishes. */
    if (!result) {
        if (!GICFactoryOutputV15(out, sizeof(*out), true)) result = Mach(VZ_KERNEL_BAD_ARGUMENT);
        else if (!VM27CPUSelfWriteV1(NULL, out, sizeof(*out), &staged)) result = Mach(VZ_KERNEL_NATIVE_ERROR);
    }
    PublicEndV6();
    return result;
}
