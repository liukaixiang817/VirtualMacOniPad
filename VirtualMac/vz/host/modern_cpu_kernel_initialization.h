// Partial application-private native initialization. Not an Apple USER/VIEW.
#ifndef VZ_MODERN_CPU_KERNEL_INITIALIZATION_H
#define VZ_MODERN_CPU_KERNEL_INITIALIZATION_H
#include "modern_cpu_kernel_lifecycle.h"

typedef enum {
    VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY = 1,
    VZ_KERNEL_INIT_SCALAR = 2,
    VZ_KERNEL_INIT_SIMD = 3,
    VZ_KERNEL_INIT_CONTROL = 4,
    VZ_KERNEL_INIT_SYSTEM_REGISTER = 5,
    VZ_KERNEL_INIT_COMPLETE_RESET = 6,
    VZ_KERNEL_INIT_RUN = 7
} VZKernelInitOperation;

typedef struct {
    uint32_t schemaVersion;
    uint32_t validatedKernelProfile;
    uint64_t expectedOwnerThread;
    uint64_t expectedCPUGeneration;
    uint64_t expectedReturnedSlotWord;
    uint32_t nativeHVISA;
    VZKernelInitOperation operation;
    uint32_t identifier;
    uint64_t low;
    uint64_t high;
} VZKernelInitRequest;

// A trusted application-private bounded self-task writer, provided by the
// exact launcher. The lifecycle computes its address from its OWN op6 handle;
// no caller-supplied context/base/pointer is accepted by initialization APIs.
// Keep separate from schema1 lifecycle ops so deployed read-only ABI is intact.
typedef struct {
    void *context;
    bool (*writeMemory)(void *, void *, size_t, const void *);
} VZKernelInitWriter;

typedef struct {
    VZKernelStatus status;
    uint32_t attemptedReads;
    uint32_t attemptedWrites;
    uint32_t completedWrites;
    uint32_t failedWriteOrdinal;
    uint32_t failedNativeOffset;
    bool kernelPolicyBit4Read;
    bool kernelPolicyBit4;
    bool creationPolicySliceComplete;
    bool architecturalResetComplete;
    bool runAllowed;
    bool mutationPoisoned;
    bool cpuCleanupRequired;
} VZKernelInitReceipt;

// Default-policy slice exactly follows original5544..55b8 for a private default
// CPU config with vmkey fields0. Scalar/SIMD/control writes require that slice.
// Complete-reset, system-register and run requests are expressly UNSUPPORTED:
// modern feature objects, original USER/VIEW, readiness/exit ABI are not closed.
// A failed read/write after mutation poisons further initialization, retaining
// the same-thread CPU destroy recovery handle. It does not invent rollback.
VZKernelStatus VZKernelCPUApplyInitialization(VZKernelCPU *,
    const VZKernelInitRequest *, const VZKernelInitWriter *, VZKernelInitReceipt *,
    VZKernelLifecycleResult *);

#endif
