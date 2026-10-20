#include "modern_cpu_public_register_setters_v1.h"
#include <string.h>

_Static_assert(sizeof(VM27CPURegisterSIMDV1) == 16, "SDK vector value size");
_Static_assert(_Alignof(VM27CPURegisterSIMDV1) == 16, "SDK vector value alignment");
static _Thread_local bool Active;
static _Thread_local VM27CPUFactoryBorrowV2 *PendingRelease;

static VM27CPUFactoryMachStatusV2 Bits(uint32_t bits) {
    VM27CPUFactoryMachStatusV2 status;
    memcpy(&status, &bits, sizeof(status));
    return status;
}

static VM27CPUFactoryMachStatusV2 Apply(VM27CPUFactoryIDV2 identity,
    VZKernelInitOperation operation, uint32_t identifier, uint64_t low,
    uint64_t high, const VZKernelInitWriter *writer, VZKernelInitReceipt *receipt,
    VM27CPUFactoryDiagnosticV2 *diagnostic) {
    // Refuse callback reentry and stranded cleanup before dereferencing any
    // caller input. This TLS is independent of the factory's actual guards.
    if (Active || PendingRelease) return Bits(UINT32_C(0xfae94002));
    if (!identity || !writer || !receipt) return Bits(UINT32_C(0xfae94003));
    Active = true;
    VM27CPUFactoryBorrowV2 *borrow = NULL;
    VM27CPUFactoryMachStatusV2 status = VM27CPUFactoryBorrowAcquireV2(identity, &borrow);
    if (status == 0) {
        status = VM27CPUFactoryBorrowApplyV2(borrow, operation, identifier, low,
            high, writer, receipt, diagnostic);
        VM27CPUFactoryMachStatusV2 release = VM27CPUFactoryBorrowReleaseV2(borrow);
        if (release != 0) {
            PendingRelease = borrow;
            // Preserve a real apply failure; a successful apply must still
            // report failed cleanup rather than claiming the call completed.
            if (status == 0) status = release;
        }
    }
    Active = false;
    return status;
}

VM27CPUFactoryMachStatusV2 VM27CPUSetScalarRegisterV1(VM27CPUFactoryIDV2 identity,
    uint32_t identifier, uint64_t value, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *receipt, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    if (identifier > 34) return Bits(UINT32_C(0xfae9400f));
    return Apply(identity, VZ_KERNEL_INIT_SCALAR, identifier, value, 0, writer,
        receipt, diagnostic);
}

VM27CPUFactoryMachStatusV2 VM27CPUSetSIMDRegisterV1(VM27CPUFactoryIDV2 identity,
    uint32_t identifier, VM27CPURegisterSIMDV1 value, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *receipt, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    if (identifier > 31) return Bits(UINT32_C(0xfae9400f));
    uint64_t words[2];
    memcpy(words, &value, sizeof(words));
    return Apply(identity, VZ_KERNEL_INIT_SIMD, identifier, words[0], words[1],
        writer, receipt, diagnostic);
}

VM27CPUFactoryMachStatusV2 VM27CPUSetControlRegisterV1(VM27CPUFactoryIDV2 identity,
    uint32_t identifier, uint64_t value, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *receipt, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    if (identifier > 16) return Bits(UINT32_C(0xfae9400f));
    return Apply(identity, VZ_KERNEL_INIT_CONTROL, identifier, value, 0, writer,
        receipt, diagnostic);
}

bool VM27CPURegisterSettersHasPendingReleaseV1(void) {
    return PendingRelease != NULL;
}

VM27CPUFactoryMachStatusV2 VM27CPURegisterSettersDrainV1(void) {
    if (Active) return Bits(UINT32_C(0xfae94002));
    if (!PendingRelease) return 0;
    Active = true;
    VM27CPUFactoryMachStatusV2 status = VM27CPUFactoryBorrowReleaseV2(PendingRelease);
    if (status == 0) PendingRelease = NULL;
    Active = false;
    return status;
}
