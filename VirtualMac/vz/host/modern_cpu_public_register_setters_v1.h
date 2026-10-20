#ifndef VM27_CPU_PUBLIC_REGISTER_SETTERS_V1_H
#define VM27_CPU_PUBLIC_REGISTER_SETTERS_V1_H
#include "modern_cpu_native_public_factory_v2.h"

// Same LP64 ID, 32-bit register identifier and 16-byte vector value ABI as the
// genuine SDK. These are own entry points with extra writer/receipt/diagnostic
// arguments, not hv_* interposers or a complete public Hypervisor provider.
typedef unsigned char VM27CPURegisterSIMDV1 __attribute__((ext_vector_type(16)));
#ifdef __cplusplus
extern "C" {
#endif

// The factory holds actual entry/borrow/CPU guards, constructs the owner,
// generation and slot itself, and admits only the writer bound to this VM.
// Scalar IDs 0..34 are the genuine scalar namespace; FPCR/FPSR/CPSR use the
// engine's actual 32-bit writes. SIMD IDs 0..31 copy the by-value 16-byte vector.
// Outputs are owned readable/writable C storage; the factory rejects aliases
// to retained private allocations. Early refusals leave them unchanged.
VM27CPUFactoryMachStatusV2 VM27CPUSetScalarRegisterV1(VM27CPUFactoryIDV2,
    uint32_t identifier, uint64_t value, const VZKernelInitWriter *,
    VZKernelInitReceipt *, VM27CPUFactoryDiagnosticV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUSetSIMDRegisterV1(VM27CPUFactoryIDV2,
    uint32_t identifier, VM27CPURegisterSIMDV1 value, const VZKernelInitWriter *,
    VZKernelInitReceipt *, VM27CPUFactoryDiagnosticV2 *);
// This is the independently audited native control namespace 0..16, never a
// guessed hv_sys_reg_t mapping. The engine preserves original write/RMW order.
VM27CPUFactoryMachStatusV2 VM27CPUSetControlRegisterV1(VM27CPUFactoryIDV2,
    uint32_t identifier, uint64_t value, const VZKernelInitWriter *,
    VZKernelInitReceipt *, VM27CPUFactoryDiagnosticV2 *);

// Normal factory release is callback-free and releases the actual local
// borrow. If it unexpectedly fails, retain that borrow in this actual thread's
// private TLS. Further setters refuse BUSY until this cleanup succeeds; a
// failed release never silently loses the live reference. No CPU pointer or
// context is exposed. A caller must drain before terminating its owner thread.
bool VM27CPURegisterSettersHasPendingReleaseV1(void);
VM27CPUFactoryMachStatusV2 VM27CPURegisterSettersDrainV1(void);
#ifdef __cplusplus
}
#endif
#endif
