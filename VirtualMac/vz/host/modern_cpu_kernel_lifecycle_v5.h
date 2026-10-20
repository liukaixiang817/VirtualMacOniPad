#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V5_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V5_H
// Alternative implementation: link V5 OR V4 OR V3 OR V2, never together.
// The existing signatures and own pending APIs remain available.
#include "modern_cpu_kernel_lifecycle_v4.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VZKernelCPUBorrowV5 VZKernelCPUBorrowV5;

// Only an actual successful, completed CPUCreate may publish an independent
// process-monotonic own identity. This is NOT an Apple hv_vcpu_t or proof of a
// public exit object/Run implementation. It is unrelated to native returnedSlot
// and CPU generation. A failed read/version cleanup handle never publishes.
// Actual CPU owner/TLS/thread and its live VM/epoch/generation are checked.
// Output stays unchanged on all refusals and must not overlap private objects.
VZKernelStatus VZKernelCPUPublishIdentityV5(VZKernelCPU *, uint64_t *outIdentity);

// Lookup begins under the process registry mutex before dereferencing a VM or
// CPU allocation. Success retains the actual entry until ReleaseBorrow. No
// native/currentThread/read/write callback is invoked. Borrow acquisition may
// occur on any actual pthread. Unknown/stale IDs fail with output unchanged.
// The returned opaque borrow belongs to that actual borrowing pthread; freed
// borrow pointers are invalid C. No numeric claim can fabricate a borrow.
VZKernelStatus VZKernelCPUBorrowIdentityV5(uint64_t identity,
    VZKernelCPUBorrowV5 **outBorrow);

// Requires the actual borrower pthread AND the CPU's actual owner/TLS. It
// acquires borrow and CPU guards before currentThread, verifies retained entry
// membership/VM epoch/CPU generation, and refuses draining/dead CPUs. The CPU
// pointer remains allocated only while this genuine borrow remains retained.
// Neither this reference nor its handle permits native Run or register calls.
VZKernelStatus VZKernelCPUBorrowHandleV5(VZKernelCPUBorrowV5 *,
    VZKernelCPU **outCPU);

// No callback; only the actual acquiring pthread may remove its retained
// entry reference. Synchronous reentry through BorrowHandle returns BUSY.
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *);

// Permanently stops lookup of this issued identity and starts drain. Current
// borrows still retain the allocation and may be released. Existing own owner
// cleanup APIs remain available. CPUDestroy also unpublishes before checking
// borrowCount, returns BUSY without a native call while any borrow remains,
// and retains cleanup state after native destroy failure. CPUFree cannot free
// a published/borrowed entry. VMDestroy refuses every retained CPU handle.
VZKernelStatus VZKernelCPUUnpublishIdentityV5(VZKernelCPU *);

// Fixed native op6 {0,0}, op7 NULL, no native Run, no public Mach status mapping,
// no USER/VIEW, no initialization defaults, no post-return/Run lease. A public
// Apple factory still needs its own reviewed persistent 32-byte exit storage.
#ifdef __cplusplus
}
#endif
#endif
