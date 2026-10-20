#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V6_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V6_H
#include "modern_cpu_native_public_factory_v5.h"
#include "modern_cpu_kernel_lifecycle_v10.h"
#include "modern_cpu_hv_public_abi_v1.h"
// Link alternative Factory6 + Lifecycle10. Nine actual public hv_* symbols
// refer to the existing own factory VM created with immutable nativeOps/writer.
// They do NOT load HV, accept foreign configs, provide modern VIEW, perform
// nativeRun, or implement the remaining25CPU/75Hypervisor imports.
// An unexpected borrow-release failure retains its real reference in TLS.
// Caller can drain on the same borrower before owner cleanup; no false success.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryPublicDrainBorrowV6(void);
#endif
