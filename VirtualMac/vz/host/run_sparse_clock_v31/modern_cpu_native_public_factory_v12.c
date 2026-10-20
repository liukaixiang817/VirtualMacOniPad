// The original public single-run admission/release/publication path is kept.
// Only its private lower producer call is routed through the new real C0
// protocol, so every existing real retained borrow spans all added writes.
#include "modern_cpu_native_public_factory_v12.h"
#include "modern_cpu_native_self_memory_v1.h"
static VZKernelStatus FactoryPendingRunBridgeV12(VZKernelCPU *,VZKernelRunStepReceiptV7 *);
static VM27CPUFactoryMachStatusV2 FactoryInheritedRunDiagnosticV12(
 VM27CPUFactoryBorrowV2 *,VM27CPUFactoryRunDiagnosticV3 *);
#define VZKernelCPURunOwnedStepV7 FactoryPendingRunBridgeV12
#define VM27CPUFactoryRunOwnedStepV3 FactoryInheritedRunDiagnosticV12
#include "modern_cpu_native_public_factory_v11.c"
#undef VM27CPUFactoryRunOwnedStepV3
#undef VZKernelCPURunOwnedStepV7
#include "modern_cpu_native_public_factory_pending_v12.inc"
