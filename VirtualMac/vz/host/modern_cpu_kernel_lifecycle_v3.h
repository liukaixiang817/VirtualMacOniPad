#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V3_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V3_H

// An alternative implementation unit of all legacy lifecycle APIs plus only
// the two own pending-value APIs below. Link V3 OR V2, never both units.
// Existing V2 headers, sources, frozen products and build scripts are intact.
#ifdef __cplusplus
extern "C" {
#endif
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_pending_interrupt_values_v1.h"

// Owner-thread only: requires this module's actual CPU TLS, live VM/CPU and
// current CPU generation. Guard acquisition precedes currentThread. IRQ/FIQ
// begin false because this application's own CPU allocation uses calloc;
// no native/kernel creation-default claim is made. No native callback runs.
// pending must be exactly 0/1. An unsupported type or any refusal preserves
// actual state. Pending is not applied to native control words or Run.
VZKernelStatus VZKernelCPUSetPendingInterruptV3(VZKernelCPU *,
    VZCPUPendingInterruptTypeV1 type, uint32_t pending);

// Returns the two validated application booleans and their value schema.
// The output must be disjoint from the actual CPU and VM private allocations.
// Refusals, wrong-thread calls, dead handles and callback reentry preserve
// output bytes. Destroy clears own state only after genuine successful
// owner-thread native destroy; a failed destroy preserves its cleanup handle
// and pending values. Calls through an already freed pointer are invalid C.
VZKernelStatus VZKernelCPUReadPendingInterruptsV3(VZKernelCPU *,
    VZCPUPendingInterruptValuesV1 *out);

// No API here executes Run, adds a native context read/write, constructs
// USER/VIEW, creates a post-return lease or changes any runAllowed gate.
#ifdef __cplusplus
}
#endif
#endif
