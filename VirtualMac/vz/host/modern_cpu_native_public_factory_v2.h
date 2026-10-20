#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V2_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V2_H
#include "modern_cpu_kernel_lifecycle_v6.h"
#ifdef __cplusplus
extern "C" {
#endif

// Application-owned factory/storage integration, never an Apple USER/VIEW.
// Link the alternative V6 implementation and initialization_v3 once.
// Immutable V5 and factoryV1 remain unchanged.
// No hv_* symbols, framework dependency, native Run or exit-write API exists.
typedef struct VM27CPUFactoryVMV2 VM27CPUFactoryVMV2;
typedef struct VM27CPUFactoryBorrowV2 VM27CPUFactoryBorrowV2;
typedef uint64_t VM27CPUFactoryIDV2;
typedef int32_t VM27CPUFactoryMachStatusV2;
// Genuine caller-shaped opaque pointer. Only registered own OSv3 objects are
// accepted; Apple/foreign OS_OBJECTs are rejected before pointer dereference.
typedef const void *VM27CPUFactoryForeignConfigV2;
typedef struct {
    uint32_t reason;
    uint32_t reservedPadding;
    uint64_t syndrome, virtualAddress, physicalAddress;
} VM27CPUFactoryExitV2;

typedef struct {
    VZKernelStatus ownStatus;
    bool nativeInvoked;
    int32_t nativeReturn;
    bool cleanupPending;
    bool nativeCPUCreationComplete;
    bool exitRecordValid; // Always false: no native Run/exit producer.
    bool creationConfigComplete, nativeKeyPolicyApplied;
    bool nativeFeatureProfileApplied, TLBIExecutionHandlerImplemented;
    VZKernelInitReceipt creationReceipt;
    bool callerDestroyFailureIsFatal; // Genuine VMM contract, not a crash here.
    uint64_t vmEpoch, cpuGeneration;
} VM27CPUFactoryDiagnosticV2;
typedef struct {
    VM27CPUFactoryIDV2 identity;
    uint64_t vmEpoch, cpuGeneration;
    const VM27CPUFactoryExitV2 *exitStorage;
    bool exitRecordValid;
} VM27CPUFactoryViewV2;

// Output pointers remain unchanged on refusal. Diagnostic is optional and
// populated after validation; invalid/aliased pointers remain unchanged too.
// Ops are the project's audited native launcher OR local mocks, never old HV.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMCreateV2(
    const VZKernelLifecycleOps *, const VZKernelVMOptions *, const VZKernelInitWriter *,
    VM27CPUFactoryVMV2 **, VM27CPUFactoryDiagnosticV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMDestroyV2(
    VM27CPUFactoryVMV2 *, VM27CPUFactoryDiagnosticV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMFreeV2(VM27CPUFactoryVMV2 *);

// Allocate persistent aligned 32B storage BEFORE native V5 create. Publish own
// ID and pointer together only after create+full64 version+configuration slice+V6 publication.
// ID is V5's process-monotonic application identity, NOT returned native slot
// or original VMM public ID. No valid reason is produced by calloc. Outputs can
// be staged into an owned caller's ID/exit fields; raw original C++ objects are
// never cast/written. Original VMM's true fields are +d8/+e0 in 296B objects.
// Successful native create with failed validation keeps the actual owner TLS
// cleanup entry but publishes neither output. OwnerCleanup explicitly tears
// it down, even after a later read would succeed; it cannot become published.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryCreateV2(VM27CPUFactoryVMV2 *,
    VM27CPUFactoryIDV2 *, VM27CPUFactoryExitV2 **,
    VM27CPUFactoryForeignConfigV2, VM27CPUFactoryDiagnosticV2 *);

// Destroy stops new lookup before drain. Busy borrows/native errors preserve
// storage and the actual owner cleanup entry; a drained ID is never revived.
// The genuine original VMM crashes on nonzero hv_vcpu_destroy; this own API
// returns explicit errors and retains a cleanup path instead of false success.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryDestroyV2(
    VM27CPUFactoryIDV2, VM27CPUFactoryDiagnosticV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryOwnerCleanupV2(
    VM27CPUFactoryVMV2 *, VM27CPUFactoryDiagnosticV2 *);

// Real V5 entry borrows retain both CPU and storage. Acquire is cross-thread;
// View requires actual borrower AND CPU owner/TLS. Release requires borrower.
// No raw CPU handle escapes; foreign/stale/draining view output stays unchanged.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAcquireV2(
    VM27CPUFactoryIDV2, VM27CPUFactoryBorrowV2 **);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowViewV2(
    VM27CPUFactoryBorrowV2 *, VM27CPUFactoryViewV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowReleaseV2(
    VM27CPUFactoryBorrowV2 *);
// The factory constructs owner/gen/returnedSlot/profile/ISA from its live entry.
// Writer is fixed at VMCreate; this extra own argument must match that binding.
// Scalar/SIMD/control only; no guessed getter, native Run or raw context escapes.
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowApplyV2(VM27CPUFactoryBorrowV2 *,
    VZKernelInitOperation, uint32_t identifier, uint64_t low, uint64_t high,
    const VZKernelInitWriter *, VZKernelInitReceipt *, VM27CPUFactoryDiagnosticV2 *);
#ifdef __cplusplus
}
#endif
#endif
