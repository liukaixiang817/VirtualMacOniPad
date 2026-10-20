// Application-private iPadOS 16.1.1 kernel lifecycle bridge for modern VMM.
// This is not an Apple USER/VIEW object or a complete Hypervisor implementation.
#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int32_t VZKernelHVReturn;
#define VZ_KERNEL_NATIVE_CONTEXT_VERSION UINT64_C(0x206879700000000e)
#define VZ_KERNEL_PROFILE_IPADOS_16_1_1 UINT32_C(0x16110001)

typedef enum {
    VZ_KERNEL_OK = 0,
    VZ_KERNEL_BAD_ARGUMENT,
    VZ_KERNEL_UNSUPPORTED,
    VZ_KERNEL_OUT_OF_MEMORY,
    VZ_KERNEL_BUSY,
    VZ_KERNEL_WRONG_THREAD,
    VZ_KERNEL_NATIVE_ERROR,
    VZ_KERNEL_CONTEXT_UNREADABLE,
    VZ_KERNEL_CONTEXT_VERSION_MISMATCH,
    VZ_KERNEL_NOT_LIVE
} VZKernelStatus;

// Exact old-host native operation-1 input, not an OS configuration object.
// Field locations are from original 13 hv_vm_create 4af4..4b50. The
// compatibility entry must translate genuine modern options into these fields.
typedef struct {
    uint64_t reserved;
    uint64_t ipaLimit;
    uint32_t ipaGranule;
    uint32_t reserved20;
    uint32_t nativeHVISA;
    uint32_t reserved28;
} VZKernelNativeVMConfig;

// These numeric namespaces are distinct. Their architectural names have not
// been established; do not infer an ARM instruction set from the number.
// The serialized scope is this audited VMM's own 0/1/2 configuration values.
typedef enum {
    VZ_KERNEL_SERIALIZED_GUEST_ISA_0 = 0,
    VZ_KERNEL_SERIALIZED_GUEST_ISA_1 = 1,
    VZ_KERNEL_SERIALIZED_GUEST_ISA_2 = 2
} VZKernelSerializedGuestISA;
typedef enum {
    VZ_KERNEL_NATIVE_HV_ISA_1 = 1,
    VZ_KERNEL_NATIVE_HV_ISA_2 = 2,
    VZ_KERNEL_NATIVE_HV_ISA_3 = 3
} VZKernelNativeHVISA;

typedef struct {
    uint32_t ipaBits;
    uint32_t ipaGranule;
    uint32_t nativeHVISA;
    bool el2Enabled;
    bool vheEnabled;
} VZKernelVMOptions;

// No function-pointer fallback to old Hypervisor is present. The injected
// nativeTrap implementation is either this project's exact SVC trampoline or
// a local mock. Profile validation is performed by the native launcher before
// constructing this table. readMemory must be a bounded self-task read.
typedef struct {
    uint32_t schemaVersion;
    uint32_t validatedKernelProfile;
    void *context;
    VZKernelHVReturn (*nativeTrap)(void *, uint64_t, void *);
    uint64_t (*currentThread)(void *);
    bool (*readMemory)(void *, const void *, size_t, void *);
} VZKernelLifecycleOps;

typedef struct VZKernelVM VZKernelVM;
typedef struct VZKernelCPU VZKernelCPU;

typedef struct {
    VZKernelStatus status;
    bool nativeInvoked;
    VZKernelHVReturn nativeReturn;
    bool vmLive;
    bool cpuLive;
    bool cleanupPending;
    uint64_t ownerThread;
    uint64_t generation;
    uint64_t requestedSlot;
    uint64_t returnedSlotWord;
    bool nativeContextVersionRead;
    uint64_t nativeContextVersion;
} VZKernelLifecycleResult;

// Convert only an explicitly supported application-format value. Unknown
// values leave out unchanged, although the original VMM uses a catch-all2.
VZKernelStatus VZKernelConvertSerializedGuestISA(VZKernelSerializedGuestISA, VZKernelNativeHVISA *);
bool VZKernelNativeHVISAIsKnown(uint32_t);
VZKernelStatus VZKernelTranslateVMOptions(const VZKernelVMOptions *, VZKernelNativeVMConfig *);
VZKernelStatus VZKernelVMCreate(const VZKernelLifecycleOps *, const VZKernelVMOptions *, VZKernelVM **, VZKernelLifecycleResult *);
VZKernelStatus VZKernelVMDestroy(VZKernelVM *, VZKernelLifecycleResult *);
// Free only a successfully destroyed VM. A failed destroy preserves recovery
// ownership and returns BUSY. CPU pointers must be freed before this call.
VZKernelStatus VZKernelVMFree(VZKernelVM *);

// One diagnostic CPU, slot 0, on a genuine caller-owned pthread. Successful
// native creation followed by a read/version failure STILL returns a live
// cleanup handle through outCPU. The caller must destroy it on that thread.
// No public exit record, register reset, context projection or run is supplied.
VZKernelStatus VZKernelCPUCreate(VZKernelVM *, VZKernelCPU **, VZKernelLifecycleResult *);
VZKernelStatus VZKernelCPUContextVersion(VZKernelCPU *, VZKernelLifecycleResult *);
VZKernelStatus VZKernelCPUDestroy(VZKernelCPU *, VZKernelLifecycleResult *);
VZKernelStatus VZKernelCPUFree(VZKernelCPU *);

#endif
