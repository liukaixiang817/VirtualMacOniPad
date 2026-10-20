// Typed old-kernel SYS routes. No Apple context/cache object is forged.
#ifndef VZ_MODERN_CPU_KERNEL_SYSTEM_H
#define VZ_MODERN_CPU_KERNEL_SYSTEM_H
#include "modern_cpu_kernel_initialization.h"

typedef enum {
    VZ_KERNEL_SYS_PHYSICAL = 1,
    VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE = 2,
    VZ_KERNEL_SYS_CONTROL = 3
} VZKernelSysDomain;
typedef enum { VZ_KERNEL_SYS_READ = 1, VZ_KERNEL_SYS_WRITE = 2 } VZKernelSysAction;

typedef struct {
    uint32_t identifier;
    VZKernelSysDomain domain;
    uint32_t nativeOffset;
    uint32_t bytes;
    uint64_t nativeReadyDirtyMask;
    uint32_t auxiliaryIndex;
} VZKernelSysDescriptor;

typedef struct {
    uint32_t schemaVersion;
    uint32_t validatedKernelProfile;
    uint64_t expectedOwnerThread;
    uint64_t expectedCPUGeneration;
    uint64_t expectedReturnedSlotWord;
    uint32_t nativeHVISA;
    VZKernelSysAction action;
    uint32_t identifier;
    uint64_t value;
} VZKernelSysRequest;

typedef struct {
    VZKernelStatus status;
    VZKernelSysDescriptor descriptor;
    uint32_t attemptedNativeReads;
    uint32_t attemptedNativeWrites;
    uint32_t completedNativeWrites;
    uint32_t privateFeatureWrites;
    bool privateFeatureRead;
    bool nativeOp8Required;
    bool nativeOp8Invoked;
    bool mutationPoisoned;
    bool cpuCleanupRequired;
    bool completeModernSYSContract;
    bool runAllowed;
} VZKernelSysReceipt;

// Closed154 physical +9 feature-cache +2 control routes, generated from pinned
// original bytes. Unknown32-bit IDs leave out unchanged and are unsupported.
VZKernelStatus VZKernelSysLookup(uint32_t identifier, VZKernelSysDescriptor *out);

// Uses this lifecycle driver's real CPU handle and actual owner/slot/generation.
// Requires its default creation-policy slice. READ output remains unchanged on
// any failure. Physical routes requiring op8 fail UNSUPPORTED before writes.
// Each feature-cache value is invalid until this CPU's explicit typed setter
// stores it; no capabilities or complete old118B table are seeded with zeros.
VZKernelStatus VZKernelCPUAccessSystemRegister(VZKernelCPU *,
    const VZKernelSysRequest *, const VZKernelInitWriter *, uint64_t *readOutput,
    VZKernelSysReceipt *, VZKernelLifecycleResult *);

#endif
