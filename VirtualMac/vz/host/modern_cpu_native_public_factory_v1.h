#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V1_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V1_H
#include "modern_cpu_kernel_lifecycle_v5.h"
#ifdef __cplusplus
extern "C" {
#endif

// Application-owned factory/storage integration, never an Apple USER/VIEW.
// Link the immutable V5 implementation and its existing dependencies once.
// No hv_* symbols, framework dependency, native Run or exit-write API exists.
typedef struct VM27CPUFactoryVMV1 VM27CPUFactoryVMV1;
typedef struct VM27CPUFactoryBorrowV1 VM27CPUFactoryBorrowV1;
typedef uint64_t VM27CPUFactoryIDV1;
typedef int32_t VM27CPUFactoryMachStatusV1;
// Actual C SDK configuration type. Non-NULL foreign OS_OBJECTs are refused
// without dereferencing/releasing them: their allocation/feature ABI is open.
typedef struct hv_vcpu_config_s *VM27CPUFactoryForeignConfigV1;
typedef struct {
    uint32_t reason;
    uint32_t reservedPadding;
    uint64_t syndrome, virtualAddress, physicalAddress;
} VM27CPUFactoryExitV1;

typedef struct {
    VZKernelStatus ownStatus;
    bool nativeInvoked;
    int32_t nativeReturn;
    bool cleanupPending;
    bool nativeCPUCreationComplete;
    bool exitRecordValid; // Always false in V1: storage does not produce exits.
    bool callerDestroyFailureIsFatal; // Genuine VMM contract, not a crash here.
    uint64_t vmEpoch, cpuGeneration;
} VM27CPUFactoryDiagnosticV1;
typedef struct {
    VM27CPUFactoryIDV1 identity;
    uint64_t vmEpoch, cpuGeneration;
    const VM27CPUFactoryExitV1 *exitStorage;
    bool exitRecordValid;
} VM27CPUFactoryViewV1;

// Output pointers remain unchanged on refusal. Diagnostic is optional and
// populated after validation; invalid/aliased pointers remain unchanged too.
// Ops are the project's audited native launcher OR local mocks, never old HV.
VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMCreateV1(
    const VZKernelLifecycleOps *, const VZKernelVMOptions *,
    VM27CPUFactoryVMV1 **, VM27CPUFactoryDiagnosticV1 *);
VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMDestroyV1(
    VM27CPUFactoryVMV1 *, VM27CPUFactoryDiagnosticV1 *);
VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMFreeV1(VM27CPUFactoryVMV1 *);

// Allocate persistent aligned 32B storage BEFORE native V5 create. Publish own
// ID and pointer together only after create+full64 version+V5 publication.
// ID is V5's process-monotonic application identity, NOT returned native slot
// or original VMM public ID. No valid reason is produced by calloc. Outputs can
// be staged into an owned caller's ID/exit fields; raw original C++ objects are
// never cast/written. Original VMM's true fields are +d8/+e0 in 296B objects.
// Successful native create with failed validation keeps the actual owner TLS
// cleanup entry but publishes neither output. OwnerCleanup explicitly tears
// it down, even after a later read would succeed; it cannot become published.
VM27CPUFactoryMachStatusV1 VM27CPUFactoryCreateV1(VM27CPUFactoryVMV1 *,
    VM27CPUFactoryIDV1 *, VM27CPUFactoryExitV1 **,
    VM27CPUFactoryForeignConfigV1, VM27CPUFactoryDiagnosticV1 *);

// Destroy stops new lookup before drain. Busy borrows/native errors preserve
// storage and the actual owner cleanup entry; a drained ID is never revived.
// The genuine original VMM crashes on nonzero hv_vcpu_destroy; this own API
// returns explicit errors and retains a cleanup path instead of false success.
VM27CPUFactoryMachStatusV1 VM27CPUFactoryDestroyV1(
    VM27CPUFactoryIDV1, VM27CPUFactoryDiagnosticV1 *);
VM27CPUFactoryMachStatusV1 VM27CPUFactoryOwnerCleanupV1(
    VM27CPUFactoryVMV1 *, VM27CPUFactoryDiagnosticV1 *);

// Real V5 entry borrows retain both CPU and storage. Acquire is cross-thread;
// View requires actual borrower AND CPU owner/TLS. Release requires borrower.
// No raw V5 handle escapes; foreign/stale/draining view output stays unchanged.
VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowAcquireV1(
    VM27CPUFactoryIDV1, VM27CPUFactoryBorrowV1 **);
VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowViewV1(
    VM27CPUFactoryBorrowV1 *, VM27CPUFactoryViewV1 *);
VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowReleaseV1(
    VM27CPUFactoryBorrowV1 *);
#ifdef __cplusplus
}
#endif
#endif
