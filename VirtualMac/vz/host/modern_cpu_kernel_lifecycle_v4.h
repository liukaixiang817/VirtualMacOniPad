#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V4_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V4_H
// Alternative implementation unit: link V4 OR V3 OR V2, never together.
// The legacy function signatures and V3 pending-value APIs are retained.
// In V4 a VM has a stable allocation epoch; every CPU has a separate monotonic
// generation and a private registry entry bound to that VM epoch. A worker
// owns at most one live CPU through this unit's actual private TLS.
// Multiple workers/CPU handles are supported by the application lifecycle.
// Actual native multi-CPU allocation with fixed op6 input {0,0} is NOT proved.
// Original13 instead scans and sends its selected userspace slot. This unit
// does not enlarge that input, fabricate public hv_vcpu_t IDs or enter Run.
// CPU results expose their own generation; VM results expose its stable epoch.
// Every retained handle, including a successfully destroyed CPU not yet freed,
// blocks VMDestroy. Owner-thread destroy failure preserves its live cleanup
// handle. CPUFree requires its original actual pthread and removes the entry.
// Pending reads reject overlap with ANY retained CPU, registry entry or VM.
// Freed pointers are invalid C; identities are not public IDs or lifetime
// leases. Native callbacks run outside the VM mutex under existing guards.
#include "modern_cpu_kernel_lifecycle_v3.h"
#endif
