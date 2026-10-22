#include "modern_cpu_kernel_lifecycle_v27.h"
#include "modern_cpu_kernel_profile_v2.h"
// Real native op1/op2/op6/op7 lifecycle, with explicit owner-thread cleanup.
// No Hypervisor framework is linked or loaded. Optional initialization uses
// explicit typed slices; create/read/destroy alone never writes native state.
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_kernel_lifecycle_v6.h"
#include "modern_cpu_kernel_lifecycle_v7.h"
#include "modern_cpu_kernel_lifecycle_v9_private.h"
#include "modern_cpu_kernel_lifecycle_v11.h"
#include <sys/mman.h>
#include "modern_cpu_kernel_system_v3_private.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_kernel_initialization_v3_private.h"
#include "modern_cpu_native_fields.h"
#include "modern_cpu_kernel_initialization_private.h"
#include "modern_cpu_kernel_system_private.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdatomic.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "../modern_cpu_ram_task_scope_v53.h"
#include "../modern_cpu_ram_range_v54.h"
#include "modern_cpu_kernel_lifecycle_v18.h"
#include "modern_cpu_ram_host_input_v52.h"

_Static_assert(sizeof(void *) == 8, "Audited LP64 kernel ABI only");
_Static_assert(sizeof(VZKernelNativeVMConfig) == 32, "Native VM input width");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaLimit) == 8, "Native IPA field");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaGranule) == 16, "Native granule field");
_Static_assert(offsetof(VZKernelNativeVMConfig, nativeHVISA) == 24, "Native ISA field");
typedef struct { uint64_t requestedSlot; uintptr_t nativeContext; } NativeCPUCreate;
_Static_assert(sizeof(NativeCPUCreate) == 16, "Native CPU-create argument width");
_Static_assert(offsetof(NativeCPUCreate, nativeContext) == 8, "Kernel output field");

typedef struct VZKernelCPURegistryEntryV5 {
    struct VZKernelCPURegistryEntryV5 *next;
    struct VZKernelCPU *cpu;
    uint64_t vmEpoch, cpuGeneration;
    pthread_t ownerPthread;
    uint64_t publicIdentity;
    bool identityIssued, published, draining, creationComplete;
    unsigned borrowCount;
    struct VZKernelCPUBorrowV5 *borrows;
} VZKernelCPURegistryEntryV5;

typedef struct VZKernelRAMSegmentV54 {
 struct VZKernelRAMSegmentV54 *next;
 uint64_t guestAddress,bytes,hostOffset,flags;
 bool mapped,uncertain,target;
} VZKernelRAMSegmentV54;
typedef struct VZKernelRAMRangePlanV54 {
 struct VZKernelRAMRangePlanV54 *next;
 VZKernelRAMV9 *root;
 VZKernelRAMSegmentV54 *segments;
} VZKernelRAMRangePlanV54;
struct VZKernelVM {
    VZKernelLifecycleOps ops;
    pthread_mutex_t mutex;
    pthread_cond_t ramPublication;
    uint64_t owner, generation; // Stable VM allocation epoch.
    pthread_t ownerPthread;
    uint32_t nativeHVISA;
    pid_t taskPID; // Real process identity; a copied fork registry is not this VM.
    bool live;
    _Atomic bool operationInProgress;
    unsigned cpuHandles;
    unsigned liveCPUs;
    VZKernelCPURegistryEntryV5 *cpuRegistry;
    VZKernelRAMV9 *ramRegistry;
    VZKernelRAMRangePlanV54 *ramRangePlan;
    uint64_t ramMapVersion;
    unsigned ramCodeReaders;
};
struct VZKernelCPU {
    struct VZKernelVM *vm;
    VZKernelCPURegistryEntryV5 *registryEntry;
    uint64_t owner, generation, requestedSlot, returnedSlot;
    bool nativeSlotReserved;
    uintptr_t nativeContext;
    bool live;
    _Atomic bool operationInProgress;
    bool creationPolicySliceComplete;
    bool mutationPoisoned;
    VZKernelSysFeatureCache requestedFeatures;
    // Explicit requested values for own-profile absent extensions, never
    // seeded from a fabricated native feature-register response.
    uint64_t requestedModernFeatures[6];
    uint8_t requestedModernFeaturesValid;
    // Own calloc-backed IRQ/FIQ values, never native creation defaults.
    VZCPUPendingInterruptValuesV1 pendingInterrupts;
    VZKernelCreationConfigV6 creationConfig;
    bool creationConfigComplete;
    // Own software debug transfer bank; architectural reset policy is zero.
    uint64_t dtrRXV23, dtrTXV23;
    uint64_t runToken;
    bool runPostReturnActive;
};

struct VZKernelRAMV9 {
 VZKernelRAMV9 *next;
 VZKernelVM *vm;
 uint64_t epoch, bytes, guestAddress, flags;
 void *allocation, *host;
 size_t allocationBytes;
 bool mapped, uncertain, borrowedHost;
 bool mapInFlight;
 VZKernelRAMSegmentV54 *segments;
};

static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static VZKernelVM *RegisteredVM;
static uint64_t NextGeneration;
static uint64_t NextCPUGenerationV5;
static _Atomic bool VMCreateInProgress;
static uint64_t NextPublicIdentityV5;
struct VZKernelCPUBorrowV5 {
    struct VZKernelCPUBorrowV5 *next;
    VZKernelVM *vm;
    VZKernelCPURegistryEntryV5 *entry;
    uint64_t vmEpoch, cpuGeneration;
    pthread_t borrowerPthread;
    _Atomic bool operationInProgress;
};
// This is private compatibility-module TLS. Apple's VMM TLV is untouched.
static _Thread_local VZKernelCPU *OwnedCPU;

// Enter before any caller-supplied callback, including currentThread. The
// callbacks may synchronously reenter a public function on the same handle.
// No callback runs under the VM mutex; atomics also avoid racing a rejected
// call from another thread with the owning operation's exclusion flag.
static bool BeginOperation(_Atomic bool *flag) {
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(flag, &expected, true,
        memory_order_acquire, memory_order_relaxed);
}
static void EndOperation(_Atomic bool *flag) {
    atomic_store_explicit(flag, false, memory_order_release);
}
static VZKernelStatus BeginCPUOperation(VZKernelCPU *cpu) {
    if (!BeginOperation(&cpu->operationInProgress)) return VZ_KERNEL_BUSY;
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner) {
        // The acquired guard remains held while the caller records truthful
        // resource/poison state. Only BUSY means no exclusion was acquired.
        return VZ_KERNEL_WRONG_THREAD;
    }
    return VZ_KERNEL_OK;
}

static void Lock(pthread_mutex_t *mutex) {
    if (pthread_mutex_lock(mutex)) abort();
}
static void Unlock(pthread_mutex_t *mutex) {
    if (pthread_mutex_unlock(mutex)) abort();
}
static VZKernelStatus Finish(VZKernelLifecycleResult *r, VZKernelStatus status) {
    if (r) r->status = status;
    return status;
}
static void Start(VZKernelLifecycleResult *r) {
    if (r) memset(r, 0, sizeof(*r));
}
static void VMResult(VZKernelVM *vm, VZKernelLifecycleResult *r) {
    if (!r) return;
    r->vmLive = vm->live;
    r->cpuLive = vm->liveCPUs != 0;
    r->cleanupPending = r->vmLive || vm->cpuHandles != 0;
    r->ownerThread = vm->owner;
    r->generation = vm->generation;
}
/* Native CPU handles pin VM lifetime: VMDestroy rejects cpuHandles or
 * cpuRegistry. CPUFree removes only this owner's entry after native7 cleared
 * OwnedCPU. These identity/generation fields are immutable for that handle.
 * Other workers can change list links, publication and borrow counts; none
 * are read here. Destruction/error/foreign-thread paths keep the mutex path. */
static bool StableOwnerMetadataV67(VZKernelCPU *cpu) {
    if (OwnedCPU!=cpu || !atomic_load_explicit(&cpu->operationInProgress,memory_order_relaxed))return false;
    const VZKernelCPURegistryEntryV5 *entry=cpu->registryEntry;
    return entry && pthread_equal(pthread_self(),entry->ownerPthread) && cpu->live &&
        cpu->vm->live && entry->cpu==cpu && entry->cpuGeneration &&
        entry->cpuGeneration==cpu->generation && entry->vmEpoch==cpu->vm->generation;
}
static void CPUResult(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    if (StableOwnerMetadataV67(cpu)) {
        r->vmLive=cpu->vm->live;r->cpuLive=cpu->live;
        r->cleanupPending=r->vmLive || r->cpuLive;
        r->ownerThread=cpu->owner;r->generation=cpu->generation;
        r->requestedSlot=cpu->requestedSlot;r->returnedSlotWord=cpu->returnedSlot;
        return;
    }
    if (!r) return;
    Lock(&cpu->vm->mutex);
    r->vmLive = cpu->vm->live;
    r->cpuLive = cpu->live;
    r->cleanupPending = r->vmLive || r->cpuLive;
    r->ownerThread = cpu->owner;
    r->generation = cpu->generation;
    r->requestedSlot = cpu->requestedSlot;
    r->returnedSlotWord = cpu->returnedSlot;
    Unlock(&cpu->vm->mutex);
}

// Caller holds the VM mutex and CPU operation guard. Registry identity is
// separate from returned native packet words and original public CPU IDs.
static bool CPURegisteredLockedV5(VZKernelCPU *cpu) {
    VZKernelVM *vm = cpu->vm;
    for (VZKernelCPURegistryEntryV5 *entry = vm->cpuRegistry; entry; entry = entry->next) {
        if (entry == cpu->registryEntry && entry->cpu == cpu)
            return entry->vmEpoch == vm->generation && entry->cpuGeneration != 0 &&
                entry->cpuGeneration == cpu->generation;
    }
    return false;
}
static VZKernelStatus CPUOwnedV5(VZKernelCPU *cpu) {
    if (StableOwnerMetadataV67(cpu))return VZ_KERNEL_OK;
    Lock(&cpu->vm->mutex);
    bool valid = cpu->vm->live && cpu->live && OwnedCPU == cpu && CPURegisteredLockedV5(cpu) &&
        pthread_equal(pthread_self(), cpu->registryEntry->ownerPthread);
    Unlock(&cpu->vm->mutex);
    return valid ? VZ_KERNEL_OK : VZ_KERNEL_NOT_LIVE;
}
static bool RemoveCPUEntryLockedV5(VZKernelCPU *cpu) {
    VZKernelCPURegistryEntryV5 **link = &cpu->vm->cpuRegistry;
    while (*link && *link != cpu->registryEntry) link = &(*link)->next;
    if (!*link || (*link)->cpu != cpu || !cpu->vm->cpuHandles) return false;
    *link = (*link)->next;
    --cpu->vm->cpuHandles;
    return true;
}

bool VZKernelNativeHVISAIsKnown(uint32_t value) {
    return value >= VZ_KERNEL_NATIVE_HV_ISA_1 && value <= VZ_KERNEL_NATIVE_HV_ISA_3;
}

VZKernelStatus VZKernelConvertSerializedGuestISA(VZKernelSerializedGuestISA serialized,
    VZKernelNativeHVISA *out) {
    if (!out) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelNativeHVISA native;
    // Exact original VMM d9ff8..da034 selection, with a deliberately closed
    // application-format scope rather than the original catch-all branch.
    switch (serialized) {
        case VZ_KERNEL_SERIALIZED_GUEST_ISA_0: native = VZ_KERNEL_NATIVE_HV_ISA_2; break;
        case VZ_KERNEL_SERIALIZED_GUEST_ISA_1: native = VZ_KERNEL_NATIVE_HV_ISA_3; break;
        case VZ_KERNEL_SERIALIZED_GUEST_ISA_2: native = VZ_KERNEL_NATIVE_HV_ISA_1; break;
        default: return VZ_KERNEL_UNSUPPORTED;
    }
    *out = native;
    return VZ_KERNEL_OK;
}

VZKernelStatus VZKernelTranslateVMOptions(const VZKernelVMOptions *options, VZKernelNativeVMConfig *out) {
    if (!options || !out) return VZ_KERNEL_BAD_ARGUMENT;
    // Exact 36-bit, granule-zero lifecycle profiles for native ISA1/ISA2.
    // These validated context slices do not advertise guest execution.
    // +24 is the genuine Hypervisor config's native selector; it is NOT a
    // serialized guest ISA value. The conversion helper is a separate step.
    if (options->ipaBits != 36 || options->ipaGranule != 0 ||
        !VZKernelNativeISAHasValidatedContextV2(options->nativeHVISA) || options->el2Enabled || options->vheEnabled)
        return VZ_KERNEL_UNSUPPORTED;
    VZKernelNativeVMConfig exact = {0};
    exact.ipaLimit = UINT64_C(1) << options->ipaBits;
    exact.ipaGranule = options->ipaGranule;
    exact.nativeHVISA = options->nativeHVISA;
    *out = exact;
    return VZ_KERNEL_OK;
}

VZKernelStatus VZKernelVMCreate(const VZKernelLifecycleOps *ops, const VZKernelVMOptions *options,
    VZKernelVM **outVM, VZKernelLifecycleResult *r) {
    Start(r);
    if (!outVM) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    *outVM = NULL;
    if (!ops || !r || ops->schemaVersion != 1 ||
        ops->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        !ops->nativeTrap || !ops->currentThread || !ops->readMemory)
        return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    VZKernelNativeVMConfig config;
    VZKernelStatus status = VZKernelTranslateVMOptions(options, &config);
    if (status != VZ_KERNEL_OK) return Finish(r, status);
    if (!BeginOperation(&VMCreateInProgress)) return Finish(r, VZ_KERNEL_BUSY);
    // Admission precedes any injected callback. An existing live/drained VM
    // cannot be destroyed by a callback from a rejected replacement create.
    Lock(&RegistryMutex);
    bool unavailable = RegisteredVM || NextGeneration == UINT64_MAX;
    Unlock(&RegistryMutex);
    if (unavailable) { EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_BUSY); }
    uint64_t thread = ops->currentThread(ops->context);
    if (!thread) { EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_WRONG_THREAD); }
    VZKernelVM *vm = calloc(1, sizeof(*vm));
    if (!vm) { EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    vm->ops = *ops; vm->owner = thread; vm->nativeHVISA = config.nativeHVISA;
    vm->ownerPthread = pthread_self(); vm->taskPID = getpid();
    atomic_init(&vm->operationInProgress, true);
    if (pthread_mutex_init(&vm->mutex, NULL)) { free(vm); EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    if (pthread_cond_init(&vm->ramPublication, NULL)) { pthread_mutex_destroy(&vm->mutex); free(vm); EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    Lock(&RegistryMutex);
    if (RegisteredVM || NextGeneration == UINT64_MAX) {
        Unlock(&RegistryMutex); pthread_cond_destroy(&vm->ramPublication); pthread_mutex_destroy(&vm->mutex); free(vm);
        EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_BUSY);
    }
    vm->generation = ++NextGeneration;
    RegisteredVM = vm; // Reserve before the real call; reentrant create is blocked.
    Unlock(&RegistryMutex);
    r->nativeInvoked = true;
    r->nativeReturn = ops->nativeTrap(ops->context, 1, &config);
    if (r->nativeReturn) {
        Lock(&RegistryMutex); RegisteredVM = NULL; Unlock(&RegistryMutex);
        pthread_cond_destroy(&vm->ramPublication); pthread_mutex_destroy(&vm->mutex); free(vm);
        EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_NATIVE_ERROR);
    }
    vm->live = true; *outVM = vm; VMResult(vm, r);
    EndOperation(&vm->operationInProgress);
    EndOperation(&VMCreateInProgress);
    return Finish(r, VZ_KERNEL_OK);
}

VZKernelStatus VZKernelVMDestroy(VZKernelVM *vm, VZKernelLifecycleResult *r) {
    Start(r);
    if (!vm || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    if (!BeginOperation(&vm->operationInProgress)) return Finish(r, VZ_KERNEL_BUSY);
    if (vm->ops.currentThread(vm->ops.context) != vm->owner ||
        !pthread_equal(pthread_self(), vm->ownerPthread)) {
        EndOperation(&vm->operationInProgress);
        return Finish(r, VZ_KERNEL_WRONG_THREAD);
    }
    Lock(&vm->mutex);
    VMResult(vm, r);
    if (!vm->live || vm->cpuHandles || vm->cpuRegistry || vm->ramRegistry) {
        VZKernelStatus status = vm->live ? VZ_KERNEL_BUSY : VZ_KERNEL_NOT_LIVE;
        Unlock(&vm->mutex); EndOperation(&vm->operationInProgress);
        return Finish(r, status);
    }
    Unlock(&vm->mutex);
    // Shared VM exclusion prevents creation/free during this callback. Holding
    // the mutex here would deadlock a synchronous callback's VMFree attempt.
    r->nativeInvoked = true;
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 2, NULL);
    Lock(&vm->mutex);
    if (!r->nativeReturn) vm->live = false;
    VMResult(vm, r); Unlock(&vm->mutex);
    EndOperation(&vm->operationInProgress);
    return Finish(r, r->nativeReturn ? VZ_KERNEL_NATIVE_ERROR : VZ_KERNEL_OK);
}

VZKernelStatus VZKernelVMFree(VZKernelVM *vm) {
    if (!vm) return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&vm->operationInProgress)) return VZ_KERNEL_BUSY;
    if (vm->ops.currentThread(vm->ops.context) != vm->owner ||
        !pthread_equal(pthread_self(), vm->ownerPthread)) {
        EndOperation(&vm->operationInProgress); return VZ_KERNEL_WRONG_THREAD;
    }
    Lock(&vm->mutex);
    bool busy = vm->live || vm->cpuRegistry || vm->cpuHandles || vm->ramRegistry;
    Unlock(&vm->mutex);
    if (busy) { EndOperation(&vm->operationInProgress); return VZ_KERNEL_BUSY; }
    Lock(&RegistryMutex);
    if (RegisteredVM != vm) {
        Unlock(&RegistryMutex); EndOperation(&vm->operationInProgress);
        return VZ_KERNEL_BAD_ARGUMENT;
    }
    RegisteredVM = NULL; Unlock(&RegistryMutex);
    if (pthread_cond_destroy(&vm->ramPublication)) abort();
    if (pthread_mutex_destroy(&vm->mutex)) abort();
    free(vm);
    return VZ_KERNEL_OK;
}

static VZKernelStatus Version(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    CPUResult(cpu, r);
    r->nativeContextVersionRead = false;
    r->nativeContextVersion = 0;
    if (!cpu->nativeContext || cpu->nativeContext > UINTPTR_MAX - 0x4000)
        return Finish(r, VZ_KERNEL_CONTEXT_UNREADABLE);
    uint64_t version = 0;
    if (!cpu->vm->ops.readMemory(cpu->vm->ops.context,
        (const void *)(cpu->nativeContext + 0x4000), sizeof(version), &version))
        return Finish(r, VZ_KERNEL_CONTEXT_UNREADABLE);
    r->nativeContextVersionRead = true;
    r->nativeContextVersion = version;
    return Finish(r, version == VZ_KERNEL_NATIVE_CONTEXT_VERSION ?
        VZ_KERNEL_OK : VZ_KERNEL_CONTEXT_VERSION_MISMATCH);
}

VZKernelStatus VZKernelCPUCreate(VZKernelVM *vm, VZKernelCPU **outCPU, VZKernelLifecycleResult *r) {
    Start(r);
    if (!outCPU) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    *outCPU = NULL;
    if (!vm || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    if (!BeginOperation(&vm->operationInProgress)) return Finish(r, VZ_KERNEL_BUSY);
    uint64_t thread = vm->ops.currentThread(vm->ops.context);
    if (!thread || OwnedCPU) {
        EndOperation(&vm->operationInProgress);
        return Finish(r, thread ? VZ_KERNEL_BUSY : VZ_KERNEL_WRONG_THREAD);
    }
    VZKernelCPU *cpu = calloc(1, sizeof(*cpu));
    if (!cpu) {
        EndOperation(&vm->operationInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY);
    }
    VZKernelCPURegistryEntryV5 *entry = calloc(1, sizeof(*entry));
    if (!entry) { free(cpu); EndOperation(&vm->operationInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    cpu->vm = vm; cpu->owner = thread; cpu->registryEntry = entry;
    entry->cpu = cpu; entry->ownerPthread = pthread_self();
    cpu->pendingInterrupts.schemaVersion = VZ_CPU_PENDING_VALUES_SCHEMA_V1;
    atomic_init(&cpu->operationInProgress, true);
    // All combined registry/VM acquisition uses this order. Identity lookup
    // holds RegistryMutex before touching the current VM allocation.
    Lock(&RegistryMutex);
    Lock(&vm->mutex);
    if (!vm->live || NextCPUGenerationV5 == UINT64_MAX || vm->cpuHandles == UINT_MAX) {
        bool live = vm->live; Unlock(&vm->mutex); Unlock(&RegistryMutex); free(entry); free(cpu);
        EndOperation(&vm->operationInProgress);
        return Finish(r, live ? VZ_KERNEL_BUSY : VZ_KERNEL_NOT_LIVE);
    }
    // Native op6 takes a requested slot, not an automatically assigned ID.
    // Reserve the lowest free slot before exposing the in-progress entry.
    // Failed native destroy and incomplete creation retain this reservation.
    uint64_t usedSlots = 0;
    for (VZKernelCPURegistryEntryV5 *used = vm->cpuRegistry; used; used = used->next) {
        if (used->cpu->nativeSlotReserved) {
            if (used->cpu->requestedSlot >= 64) abort();
            usedSlots |= UINT64_C(1) << used->cpu->requestedSlot;
        }
    }
    if (usedSlots == UINT64_MAX) {
        Unlock(&vm->mutex); Unlock(&RegistryMutex); free(entry); free(cpu);
        EndOperation(&vm->operationInProgress);
        return Finish(r, VZ_KERNEL_BUSY);
    }
    uint64_t requestedSlot = 0;
    while (usedSlots & (UINT64_C(1) << requestedSlot)) ++requestedSlot;
    cpu->requestedSlot = requestedSlot;
    cpu->nativeSlotReserved = true;
    // Existing typed requests carry CPU generation without VM epoch. Never
    // recycle that generation across VM lifetimes (including create failures).
    cpu->generation = ++NextCPUGenerationV5;
    entry->cpuGeneration = cpu->generation; entry->vmEpoch = vm->generation;
    entry->next = vm->cpuRegistry; vm->cpuRegistry = entry; ++vm->cpuHandles;
    Unlock(&vm->mutex); Unlock(&RegistryMutex);
    OwnedCPU = cpu; // The real kernel and the private handle use this worker.
    NativeCPUCreate args = {cpu->requestedSlot, 0};
    r->requestedSlot = cpu->requestedSlot;
    r->nativeInvoked = true;
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 6, &args);
    if (r->nativeReturn) {
        OwnedCPU = NULL; Lock(&vm->mutex);
        if (!RemoveCPUEntryLockedV5(cpu)) abort();
        Unlock(&vm->mutex); free(entry); free(cpu); EndOperation(&vm->operationInProgress);
        return Finish(r, VZ_KERNEL_NATIVE_ERROR);
    }
    cpu->returnedSlot = args.requestedSlot;
    cpu->nativeContext = args.nativeContext;
    // Record real ownership BEFORE checking a read or version, preserving
    // a valid cleanup handle even if the returned context cannot be consumed.
    Lock(&vm->mutex); cpu->live = true; ++vm->liveCPUs; Unlock(&vm->mutex);
    VZKernelStatus status = Version(cpu, r);
    Lock(&vm->mutex); entry->creationComplete = status == VZ_KERNEL_OK; Unlock(&vm->mutex);
    // Publish only after the version callback has returned under exclusion.
    // A real successful creation still supplies its live cleanup handle on a
    // version/read error; no version validity is required for owner teardown.
    CPUResult(cpu, r); // Actual metadata belongs to the retained created handle.
    *outCPU = cpu;
    EndOperation(&cpu->operationInProgress);
    EndOperation(&vm->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUContextVersion(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return Finish(r, status);
    }
    CPUResult(cpu, r);
    status = CPUOwnedV5(cpu);
    status = status == VZ_KERNEL_OK ? Version(cpu, r) : Finish(r, status);
    EndOperation(&cpu->operationInProgress);
    return status;
}

static bool NativeFieldRead(VZKernelCPU *cpu, uint32_t offset, uint32_t bytes,
    void *out, VZKernelNativeReadDiagnostics *d) {
    ++d->attemptedReads;
    if (!bytes || bytes > 16 || cpu->nativeContext > UINTPTR_MAX - offset - bytes)
        return false;
    return cpu->vm->ops.readMemory(cpu->vm->ops.context,
        (const void *)(cpu->nativeContext + offset), bytes, out);
}

static VZKernelStatus ReadNativeFields(VZKernelCPU *cpu, VZKernelNativeSnapshot *out,
    VZKernelNativeReadDiagnostics *d, VZKernelLifecycleResult *r) {
    VZKernelStatus status = Version(cpu, r); ++d->attemptedReads;
    d->versionReadBefore = r->nativeContextVersionRead;
    if (status != VZ_KERNEL_OK) return status;
    VZKernelNativeSnapshot staged = {0};
    staged.ownerThread = cpu->owner; staged.generation = cpu->generation;
    staged.nativeVersionBefore = r->nativeContextVersion;
    uint64_t before[4] = {0}, after[4] = {0};
    for (uint32_t i = 0; i < 4; ++i) {
        VZKernelNativeField f;
        if (VZKernelNativeFieldAt(VZ_KERNEL_NATIVE_MARKER_FIRST + i, &f) != VZ_KERNEL_OK)
            abort();
        if (!NativeFieldRead(cpu, f.nativeOffset, f.bytes, &before[i], d)) {
            d->failedFieldIndex = f.index;
            return Finish(r, VZ_KERNEL_CONTEXT_UNREADABLE);
        }
    }
    d->markersReadBefore = true;
    for (uint32_t i = 0; i < VZ_KERNEL_NATIVE_FIELD_COUNT; ++i) {
        VZKernelNativeObservation *o = &staged.observations[i];
        if (VZKernelNativeFieldAt(i, &o->field) != VZ_KERNEL_OK) abort();
        uint64_t value[2] = {0};
        if (i >= VZ_KERNEL_NATIVE_MARKER_FIRST) value[0] = before[i - VZ_KERNEL_NATIVE_MARKER_FIRST];
        else if (!NativeFieldRead(cpu, o->field.nativeOffset, o->field.bytes, value, d)) {
            d->failedFieldIndex = i;
            return Finish(r, VZ_KERNEL_CONTEXT_UNREADABLE);
        }
        o->low = value[0]; o->high = value[1];
        o->nativeLogicalValueReady = o->field.domain != VZ_NATIVE_SYNCHRONIZATION &&
            (!o->field.nativeReadinessMask ||
            ((before[2] | before[3]) & o->field.nativeReadinessMask) != 0);
        o->modernValueCorrespondenceEstablished = o->nativeLogicalValueReady &&
            o->field.modernValueKind != VZ_NATIVE_MODERN_REQUIRES_VIEW &&
            o->field.modernValueKind != VZ_NATIVE_MODERN_METADATA_ONLY;
        ++d->completedFields;
    }
    for (uint32_t i = 0; i < 4; ++i) {
        VZKernelNativeField f;
        if (VZKernelNativeFieldAt(VZ_KERNEL_NATIVE_MARKER_FIRST + i, &f) != VZ_KERNEL_OK)
            abort();
        if (!NativeFieldRead(cpu, f.nativeOffset, f.bytes, &after[i], d)) {
            d->failedFieldIndex = f.index;
            return Finish(r, VZ_KERNEL_CONTEXT_UNREADABLE);
        }
    }
    d->markersReadAfter = true;
    status = Version(cpu, r); ++d->attemptedReads;
    d->versionReadAfter = r->nativeContextVersionRead;
    if (status != VZ_KERNEL_OK) return status;
    staged.nativeVersionAfter = r->nativeContextVersion;
    d->markersStable = !memcmp(before, after, sizeof(before));
    if (!d->markersStable) return Finish(r, VZ_KERNEL_BUSY);
    staged.count = VZ_KERNEL_NATIVE_FIELD_COUNT;
    staged.versionStable = staged.nativeVersionBefore == staged.nativeVersionAfter;
    staged.synchronizationMarkersStable = d->markersStable;
    *out = staged;
    return Finish(r, VZ_KERNEL_OK);
}

VZKernelStatus VZKernelCPUReadNativeFields(VZKernelCPU *cpu, VZKernelNativeSnapshot *out,
    VZKernelNativeReadDiagnostics *d, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !out || !d || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    memset(d, 0, sizeof(*d)); d->failedFieldIndex = UINT32_MAX;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return Finish(r, status);
    }
    CPUResult(cpu, r);
    status = CPUOwnedV5(cpu);
    status = status == VZ_KERNEL_OK ? ReadNativeFields(cpu, out, d, r) : Finish(r, status);
    EndOperation(&cpu->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUDestroy(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return Finish(r, status);
    }
    VZKernelVM *vm = cpu->vm;
    CPUResult(cpu, r);
    if (CPUOwnedV5(cpu) != VZ_KERNEL_OK) {
        EndOperation(&cpu->operationInProgress); return Finish(r, VZ_KERNEL_NOT_LIVE);
    }
    Lock(&vm->mutex);
    // Stop new lookups before testing existing borrows. A failed drain or
    // native destroy preserves the owner cleanup handle, never republishes.
    cpu->registryEntry->published = false;
    cpu->registryEntry->draining = true;
    bool borrowed = cpu->registryEntry->borrowCount || cpu->registryEntry->borrows;
    Unlock(&vm->mutex);
    if (borrowed) { EndOperation(&cpu->operationInProgress); return Finish(r, VZ_KERNEL_BUSY); }
    r->nativeInvoked = true;
    // Original old native destroy is op7 with NULL, CURRENT owner; the ID
    // selects a userspace table slot only. Never send a fabricated ID struct.
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 7, NULL);
    if (!r->nativeReturn) {
        Lock(&vm->mutex); cpu->live = false; cpu->nativeContext = 0;
        cpu->nativeSlotReserved = false;
        memset(cpu->requestedModernFeatures,0,sizeof(cpu->requestedModernFeatures));
        cpu->requestedModernFeaturesValid=0;
        cpu->dtrRXV23=cpu->dtrTXV23=0;
        memset(&cpu->pendingInterrupts, 0, sizeof(cpu->pendingInterrupts));
        memset(&cpu->creationConfig, 0, sizeof(cpu->creationConfig));
        cpu->creationConfigComplete = false;
        if (!vm->liveCPUs) abort();
        --vm->liveCPUs; Unlock(&vm->mutex);
        OwnedCPU = NULL;
    }
    CPUResult(cpu, r);
    EndOperation(&cpu->operationInProgress);
    return Finish(r, r->nativeReturn ? VZ_KERNEL_NATIVE_ERROR : VZ_KERNEL_OK);
}

VZKernelStatus VZKernelCPUFree(VZKernelCPU *cpu) {
    if (!cpu) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return status;
    }
    VZKernelVM *vm = cpu->vm;
    Lock(&vm->mutex);
    if (!CPURegisteredLockedV5(cpu)) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_BAD_ARGUMENT;
    }
    if (!pthread_equal(pthread_self(), cpu->registryEntry->ownerPthread)) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_WRONG_THREAD;
    }
    if (cpu->live || OwnedCPU == cpu || cpu->registryEntry->published ||
        cpu->registryEntry->borrowCount || cpu->registryEntry->borrows) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_BUSY;
    }
    if (!RemoveCPUEntryLockedV5(cpu)) abort();
    VZKernelCPURegistryEntryV5 *entry = cpu->registryEntry;
    Unlock(&vm->mutex);
    memset(&cpu->pendingInterrupts, 0, sizeof(cpu->pendingInterrupts));
    memset(entry, 0, sizeof(*entry)); free(entry); free(cpu);
    return VZ_KERNEL_OK;
}

typedef struct {
    VZKernelCPU *cpu;
    const VZKernelInitWriter *writer;
    VZKernelLifecycleResult *lifecycle;
    VZKernelStatus boundaryStatus;
} InitializationAccess;

static bool InitializationOwned(InitializationAccess *a) {
    VZKernelCPU *cpu = a->cpu;
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner) {
        a->boundaryStatus = VZ_KERNEL_WRONG_THREAD;
        return false;
    }
    if (!atomic_load_explicit(&cpu->operationInProgress, memory_order_relaxed) ||
        CPUOwnedV5(cpu) != VZ_KERNEL_OK) {
        a->boundaryStatus = VZ_KERNEL_NOT_LIVE;
        return false;
    }
    a->boundaryStatus = Version(cpu, a->lifecycle);
    return a->boundaryStatus == VZ_KERNEL_OK;
}

static bool InitializationRead(void *opaque, uint32_t offset, size_t bytes, void *out) {
    InitializationAccess *a = opaque;
    if (!out || !(VZKernelInitOffsetWritable(offset, bytes) ||
        VZKernelSysNativeFieldAllowed(offset, bytes) ||
        (offset == 0x4030 && bytes == 1) || (offset == 0x4100 && bytes == 8))) return false;
    if (!InitializationOwned(a)) return false;
    VZKernelCPU *cpu = a->cpu;
    if (cpu->nativeContext > UINTPTR_MAX - offset - bytes) return false;
    return cpu->vm->ops.readMemory(cpu->vm->ops.context,
        (const void *)(cpu->nativeContext + offset), bytes, out);
}

static bool InitializationWrite(void *opaque, uint32_t offset, size_t bytes,
    const void *value) {
    InitializationAccess *a = opaque;
    if (!value || !(VZKernelInitOffsetWritable(offset, bytes) ||
        VZKernelSysNativeFieldAllowed(offset, bytes)) || !a->writer || !a->writer->writeMemory) return false;
    if (!InitializationOwned(a)) return false;
    VZKernelCPU *cpu = a->cpu;
    if (cpu->nativeContext > UINTPTR_MAX - offset - bytes) return false;
    return a->writer->writeMemory(a->writer->context,
        (void *)(cpu->nativeContext + offset), bytes, value);
}

VZKernelStatus VZKernelCPUApplyInitialization(VZKernelCPU *cpu,
    const VZKernelInitRequest *q, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *receipt, VZKernelLifecycleResult *r) {
    Start(r);
    if (receipt) {
        memset(receipt, 0, sizeof(*receipt));
        receipt->failedNativeOffset = UINT32_MAX;
        receipt->failedWriteOrdinal = UINT32_MAX;
    }
    if (!cpu || !q || !writer || !writer->writeMemory || !receipt || !r) {
        if (receipt) receipt->status = VZ_KERNEL_BAD_ARGUMENT;
        return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    }
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status == VZ_KERNEL_BUSY) {
        receipt->status = status; return Finish(r, status);
    }
    if (status != VZ_KERNEL_OK) goto finish;
    if (CPUOwnedV5(cpu) != VZ_KERNEL_OK)
        status = VZ_KERNEL_NOT_LIVE;
    else if (q->expectedOwnerThread != cpu->owner ||
        q->expectedCPUGeneration != cpu->generation ||
        q->expectedReturnedSlotWord != cpu->returnedSlot)
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (q->schemaVersion != 1 ||
        q->validatedKernelProfile != cpu->vm->ops.validatedKernelProfile ||
        q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->nativeHVISA != cpu->vm->nativeHVISA ||
        !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA))
        status = VZ_KERNEL_UNSUPPORTED;
    else if (q->operation < VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY ||
        q->operation > VZ_KERNEL_INIT_CONTROL)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (cpu->mutationPoisoned)
        status = VZ_KERNEL_BUSY;
    else if (q->operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY ?
        cpu->creationPolicySliceComplete : !cpu->creationPolicySliceComplete)
        status = VZ_KERNEL_BUSY;
    if (status != VZ_KERNEL_OK) goto finish;
    status = Version(cpu, r);
    if (status != VZ_KERNEL_OK) goto finish;
    InitializationAccess opaque = {cpu, writer, r, VZ_KERNEL_OK};
    VZKernelInitAccess access = {&opaque, InitializationRead, InitializationWrite};
    status = VZKernelInitApplyVerifiedSlice(q, &access, receipt);
    // A successful final writer may change the owner or real context version.
    // Recheck its returned state before completing the policy or any slice.
    if (status == VZ_KERNEL_OK && !InitializationOwned(&opaque)) status = opaque.boundaryStatus;
    if (opaque.boundaryStatus != VZ_KERNEL_OK) status = opaque.boundaryStatus;
    if (status == VZ_KERNEL_OK && q->operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY)
        cpu->creationPolicySliceComplete = true;
    // A false writer may already have partially written. Never claim that
    // failedWriteOrdinal/completedWrites prove exact restoration or no change.
    if (status != VZ_KERNEL_OK && receipt->attemptedWrites) cpu->mutationPoisoned = true;
finish:
    CPUResult(cpu, r);
    receipt->status = status;
    receipt->creationPolicySliceComplete = cpu->creationPolicySliceComplete;
    receipt->mutationPoisoned = cpu->mutationPoisoned;
    receipt->cpuCleanupRequired = cpu->live;
    receipt->architecturalResetComplete = false;
    receipt->runAllowed = false;
    EndOperation(&cpu->operationInProgress);
    return Finish(r, status);
}

// These two V3 APIs hold the existing CPU exclusion throughout the one
// currentThread callback, validation, and own-state publication. No native
// context read, writer callback, trap, Run, USER/VIEW or return lease occurs.
static VZKernelStatus PendingOwnedV3(VZKernelCPU *cpu) {
    return CPUOwnedV5(cpu);
}

static VZKernelStatus PendingValueStatusV3(VZCPUPendingValueStatusV1 status) {
    if (status == VZ_CPU_PENDING_VALUES_OK_V1) return VZ_KERNEL_OK;
    if (status == VZ_CPU_PENDING_VALUES_UNSUPPORTED_V1) return VZ_KERNEL_UNSUPPORTED;
    return VZ_KERNEL_BAD_ARGUMENT;
}

static bool PendingOutputDisjointV3(const void *out, size_t bytes,
    const void *object, size_t objectBytes) {
    uintptr_t a = (uintptr_t)out, b = (uintptr_t)object;
    if (a > UINTPTR_MAX - bytes || b > UINTPTR_MAX - objectBytes) return false;
    return a + bytes <= b || b + objectBytes <= a;
}

// Both published and staged interval records are private provider metadata.
static bool RAMMetadataDisjointV54(VZKernelVM *vm,const void *p,size_t n) {
 for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next)
  for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next)
   if(!PendingOutputDisjointV3(p,n,g,sizeof(*g)))return false;
 for(VZKernelRAMRangePlanV54 *x=vm->ramRangePlan;x;x=x->next) {
  if(!PendingOutputDisjointV3(p,n,x,sizeof(*x)))return false;
  for(VZKernelRAMSegmentV54 *g=x->segments;g;g=g->next)
   if(!PendingOutputDisjointV3(p,n,g,sizeof(*g)))return false;
 }
 return true;
}
// Caller holds VM mutex. Retained borrows are private allocations too.
static bool OutputAllPrivateDisjointLockedV5(VZKernelVM *vm, const void *out, size_t bytes) {
    bool disjoint = PendingOutputDisjointV3(out, bytes, vm, sizeof(*vm)) && RAMMetadataDisjointV54(vm,out,bytes);
    for (VZKernelRAMV9 *ram=vm->ramRegistry; disjoint && ram; ram=ram->next)
        disjoint=PendingOutputDisjointV3(out,bytes,ram,sizeof(*ram)) &&
            PendingOutputDisjointV3(out,bytes,ram->allocation,ram->allocationBytes);
    for (VZKernelCPURegistryEntryV5 *entry = vm->cpuRegistry; disjoint && entry; entry = entry->next)
    {
        disjoint = PendingOutputDisjointV3(out, bytes, entry, sizeof(*entry)) &&
            PendingOutputDisjointV3(out, bytes, entry->cpu, sizeof(*entry->cpu));
        for (VZKernelCPUBorrowV5 *borrow = entry->borrows; disjoint && borrow; borrow = borrow->next)
            disjoint = PendingOutputDisjointV3(out, bytes, borrow, sizeof(*borrow));
    }
    return disjoint;
}
static bool PendingOutputAllPrivateDisjointV5(VZKernelCPU *cpu, const void *out, size_t bytes) {
    VZKernelVM *vm = cpu->vm;
    Lock(&vm->mutex);
    bool disjoint = OutputAllPrivateDisjointLockedV5(vm, out, bytes);
    Unlock(&vm->mutex);
    return disjoint;
}

// A borrow is a real retained list entry, not a caller-supplied numeric lease.
// Caller holds VM mutex; its actual borrow already prevents entry/VM free.
static bool BorrowRegisteredLockedV5(VZKernelCPUBorrowV5 *borrow) {
    VZKernelVM *vm = borrow->vm;
    VZKernelCPURegistryEntryV5 *entry = borrow->entry;
    bool registered = false;
    for (VZKernelCPURegistryEntryV5 *q = vm->cpuRegistry; q; q = q->next)
        if (q == entry) { registered = true; break; }
    if (!registered || !entry->cpu || !entry->borrowCount ||
        entry->cpu->vm != vm || entry->cpu->registryEntry != entry ||
        borrow->vmEpoch != vm->generation || borrow->vmEpoch != entry->vmEpoch ||
        borrow->cpuGeneration != entry->cpuGeneration ||
        borrow->cpuGeneration != entry->cpu->generation)
        return false;
    for (VZKernelCPUBorrowV5 *q = entry->borrows; q; q = q->next)
        if (q == borrow) return true;
    return false;
}

VZKernelStatus VZKernelCPUPublishIdentityV5(VZKernelCPU *cpu, uint64_t *outIdentity) {
    if (!cpu || !outIdentity) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return status;
    }
    status = CPUOwnedV5(cpu);
    if (status == VZ_KERNEL_OK) {
        VZKernelLifecycleResult validation = {0};
        status = Version(cpu, &validation);
        if (status == VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
            status = VZ_KERNEL_WRONG_THREAD;
        if (status == VZ_KERNEL_OK) status = CPUOwnedV5(cpu);
    }
    if (status == VZ_KERNEL_OK) {
        VZKernelVM *vm = cpu->vm;
        Lock(&RegistryMutex); Lock(&vm->mutex);
        VZKernelCPURegistryEntryV5 *entry = cpu->registryEntry;
        if (RegisteredVM != vm || !CPURegisteredLockedV5(cpu) || !entry->creationComplete || !cpu->creationConfigComplete || cpu->mutationPoisoned || entry->draining)
            status = VZ_KERNEL_NOT_LIVE;
        else if (!OutputAllPrivateDisjointLockedV5(vm, outIdentity, sizeof(*outIdentity)))
            status = VZ_KERNEL_BAD_ARGUMENT;
        else if (entry->identityIssued || NextPublicIdentityV5 == UINT64_MAX)
            status = VZ_KERNEL_BUSY;
        else {
            entry->publicIdentity = ++NextPublicIdentityV5;
            entry->identityIssued = true; entry->published = true;
            *outIdentity = entry->publicIdentity;
        }
        Unlock(&vm->mutex); Unlock(&RegistryMutex);
    }
    EndOperation(&cpu->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUBorrowIdentityV5(uint64_t identity, VZKernelCPUBorrowV5 **outBorrow) {
    if (!identity || !outBorrow) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelCPUBorrowV5 *borrow = calloc(1, sizeof(*borrow));
    if (!borrow) return VZ_KERNEL_OUT_OF_MEMORY;
    VZKernelStatus status = VZ_KERNEL_BAD_ARGUMENT;
    Lock(&RegistryMutex);
    VZKernelVM *vm = RegisteredVM;
    if (!vm) status = VZ_KERNEL_NOT_LIVE;
    else {
        Lock(&vm->mutex);
        if (!vm->live) status = VZ_KERNEL_NOT_LIVE;
        else if (!OutputAllPrivateDisjointLockedV5(vm, outBorrow, sizeof(*outBorrow)))
            status = VZ_KERNEL_BAD_ARGUMENT;
        else for (VZKernelCPURegistryEntryV5 *entry = vm->cpuRegistry; entry; entry = entry->next) {
            if (!entry->identityIssued || entry->publicIdentity != identity) continue;
            if (!entry->published || entry->draining || !entry->creationComplete ||
                !entry->cpu->live || !CPURegisteredLockedV5(entry->cpu))
                break;
            if (entry->borrowCount == UINT_MAX) { status = VZ_KERNEL_BUSY; break; }
            borrow->vm = vm; borrow->entry = entry;
            borrow->vmEpoch = vm->generation; borrow->cpuGeneration = entry->cpuGeneration;
            borrow->borrowerPthread = pthread_self();
            atomic_init(&borrow->operationInProgress, false);
            borrow->next = entry->borrows; entry->borrows = borrow; ++entry->borrowCount;
            *outBorrow = borrow; status = VZ_KERNEL_OK;
            break;
        }
        Unlock(&vm->mutex);
    }
    Unlock(&RegistryMutex);
    if (status != VZ_KERNEL_OK) free(borrow);
    return status;
}

VZKernelStatus VZKernelCPUBorrowHandleV5(VZKernelCPUBorrowV5 *borrow, VZKernelCPU **outCPU) {
    if (!borrow || !outCPU) return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&borrow->operationInProgress)) return VZ_KERNEL_BUSY;
    if (!pthread_equal(pthread_self(), borrow->borrowerPthread)) {
        EndOperation(&borrow->operationInProgress); return VZ_KERNEL_WRONG_THREAD;
    }
    VZKernelVM *vm = borrow->vm;
    Lock(&vm->mutex);
    bool valid = BorrowRegisteredLockedV5(borrow);
    VZKernelCPU *cpu = valid ? borrow->entry->cpu : NULL;
    Unlock(&vm->mutex);
    if (!valid) { EndOperation(&borrow->operationInProgress); return VZ_KERNEL_NOT_LIVE; }
    // The retained entry keeps this pointer alive before guard acquisition.
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status == VZ_KERNEL_OK) {
        status = CPUOwnedV5(cpu);
        Lock(&vm->mutex);
        if (status == VZ_KERNEL_OK && (!BorrowRegisteredLockedV5(borrow) ||
            borrow->entry->draining || !borrow->entry->creationComplete))
            status = VZ_KERNEL_NOT_LIVE;
        if (status == VZ_KERNEL_OK && !OutputAllPrivateDisjointLockedV5(vm, outCPU, sizeof(*outCPU)))
            status = VZ_KERNEL_BAD_ARGUMENT;
        if (status == VZ_KERNEL_OK) *outCPU = cpu;
        Unlock(&vm->mutex);
    }
    if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
    EndOperation(&borrow->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *borrow) {
    if (!borrow) return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&borrow->operationInProgress)) return VZ_KERNEL_BUSY;
    if (!pthread_equal(pthread_self(), borrow->borrowerPthread)) {
        EndOperation(&borrow->operationInProgress); return VZ_KERNEL_WRONG_THREAD;
    }
    VZKernelVM *vm = borrow->vm;
    Lock(&vm->mutex);
    if (!BorrowRegisteredLockedV5(borrow)) {
        Unlock(&vm->mutex); EndOperation(&borrow->operationInProgress); return VZ_KERNEL_NOT_LIVE;
    }
    VZKernelCPURegistryEntryV5 *entry = borrow->entry;
    VZKernelCPUBorrowV5 **link = &entry->borrows;
    while (*link != borrow) link = &(*link)->next;
    *link = borrow->next; --entry->borrowCount;
    Unlock(&vm->mutex);
    memset(borrow, 0, sizeof(*borrow)); free(borrow);
    return VZ_KERNEL_OK;
}

VZKernelStatus VZKernelCPUUnpublishIdentityV5(VZKernelCPU *cpu) {
    if (!cpu) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return status;
    }
    status = CPUOwnedV5(cpu);
    if (status == VZ_KERNEL_OK) {
        Lock(&cpu->vm->mutex);
        VZKernelCPURegistryEntryV5 *entry = cpu->registryEntry;
        if (!entry->identityIssued) status = VZ_KERNEL_BAD_ARGUMENT;
        else { entry->published = false; entry->draining = true; }
        Unlock(&cpu->vm->mutex);
    }
    EndOperation(&cpu->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUSetPendingInterruptV3(VZKernelCPU *cpu,
    VZCPUPendingInterruptTypeV1 type, uint32_t pending) {
    if (!cpu) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return status;
    }
    status = PendingOwnedV3(cpu);
    if (status == VZ_KERNEL_OK) {
        VZCPUPendingInterruptValuesV1 staged;
        status = PendingValueStatusV3(VZCPUSetPendingInterruptValueV1(
            &cpu->pendingInterrupts, (uint32_t)type, pending, &staged));
        if (status == VZ_KERNEL_OK) cpu->pendingInterrupts = staged;
    }
    EndOperation(&cpu->operationInProgress);
    return status;
}

VZKernelStatus VZKernelCPUReadPendingInterruptsV3(VZKernelCPU *cpu,
    VZCPUPendingInterruptValuesV1 *out) {
    if (!cpu || !out) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status != VZ_KERNEL_OK) {
        if (status != VZ_KERNEL_BUSY) EndOperation(&cpu->operationInProgress);
        return status;
    }
    status = PendingOwnedV3(cpu);
    if (status == VZ_KERNEL_OK &&
        !PendingOutputAllPrivateDisjointV5(cpu, out, sizeof(*out)))
        status = VZ_KERNEL_BAD_ARGUMENT;
    if (status == VZ_KERNEL_OK) {
        // Reusing the frozen setter with the same IRQ value validates schema,
        // both booleans and reserved without mutating the actual CPU state.
        VZCPUPendingInterruptValuesV1 staged;
        status = PendingValueStatusV3(VZCPUSetPendingInterruptValueV1(
            &cpu->pendingInterrupts, VZ_CPU_PENDING_IRQ_V1,
            cpu->pendingInterrupts.irqPending, &staged));
        if (status == VZ_KERNEL_OK) memcpy(out, &staged, sizeof(staged));
    }
    EndOperation(&cpu->operationInProgress);
    return status;
}

// Each SYS field retains its real CPU guard and obtains its exact self-task
// permission boundary, even if a creator selected another trusted writer.
static bool SystemReadMappedV8(void *opaque,uint32_t offset,size_t bytes,void *out) {
    InitializationAccess *a=opaque;
    if(!InitializationOwned(a) || a->cpu->nativeContext>UINTPTR_MAX-offset-bytes ||
        !VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),bytes,false,NULL))return false;
    return InitializationRead(opaque,offset,bytes,out);
}
static bool SystemWriteMappedV8(void *opaque,uint32_t offset,size_t bytes,const void *value) {
    InitializationAccess *a=opaque;
    if(!InitializationOwned(a) || a->cpu->nativeContext>UINTPTR_MAX-offset-bytes ||
        !VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+offset),bytes,true,NULL))return false;
    return InitializationWrite(opaque,offset,bytes,value);
}
// Private CPU guard and actual owner/TLS remain held through this operation.
// native8 carries no caller packet and never accepts an externally-made token.
static VZKernelStatus PrepareSystemNative8V8(void *opaque,bool *invoked) {
    InitializationAccess *a=opaque;VZKernelCPU *cpu=a->cpu;
    *invoked=false;
    if(!InitializationOwned(a))return a->boundaryStatus;
    if(!VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
        return VZ_KERNEL_CONTEXT_UNREADABLE;
    if(!InitializationOwned(a))return a->boundaryStatus;
    *invoked=true;a->lifecycle->nativeInvoked=true;
    a->lifecycle->nativeReturn=cpu->vm->ops.nativeTrap(cpu->vm->ops.context,8,NULL);
    if(a->lifecycle->nativeReturn)return VZ_KERNEL_NATIVE_ERROR;
    if(!VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
        return VZ_KERNEL_CONTEXT_UNREADABLE;
    return InitializationOwned(a) ? VZ_KERNEL_OK : a->boundaryStatus;
}
static int ModernRequestedFeatureIndexV26(uint32_t identifier) {
    // These six registers describe extensions withheld by the actual own
    // CPU feature profile (selectors12/13/14/15/16/17). Only explicit zero writes
    // are admitted; fresh reads do not invent a requested value.
    switch(identifier) {
    case 0xc03b:return 0; // ID_AA64MMFR3_EL1
    case 0xc03c:return 1; // ID_AA64MMFR4_EL1
    case 0xc022:return 2; // ID_AA64PFR2_EL1
    case 0xc025:return 3; // ID_AA64SMFR0_EL1
    case 0xc024:return 4; // ID_AA64ZFR0_EL1
    case 0xc032:return 5; // ID_AA64ISAR2_EL1
    default:return -1;
    }
}
VZKernelStatus VZKernelCPUAccessSystemRegister(VZKernelCPU *cpu,
    const VZKernelSysRequest *input,const VZKernelInitWriter *writer,uint64_t *readOutput,
    VZKernelSysReceipt *outReceipt,VZKernelLifecycleResult *outLifecycle) {
    if(!cpu || !input || !outReceipt || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelStatus status=BeginCPUOperation(cpu);
    if(status==VZ_KERNEL_BUSY)return status;
    if(status!=VZ_KERNEL_OK){EndOperation(&cpu->operationInProgress);return status;}
    Lock(&RegistryMutex);Lock(&cpu->vm->mutex);
    bool disjoint=OutputAllPrivateDisjointLockedV5(cpu->vm,input,sizeof(*input)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm,outReceipt,sizeof(*outReceipt)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm,outLifecycle,sizeof(*outLifecycle)) &&
        (!readOutput || OutputAllPrivateDisjointLockedV5(cpu->vm,readOutput,sizeof(*readOutput))) &&
        (!writer || OutputAllPrivateDisjointLockedV5(cpu->vm,writer,sizeof(*writer))) &&
        PendingOutputDisjointV3(outReceipt,sizeof(*outReceipt),outLifecycle,sizeof(*outLifecycle)) &&
        PendingOutputDisjointV3(outReceipt,sizeof(*outReceipt),input,sizeof(*input)) &&
        PendingOutputDisjointV3(outLifecycle,sizeof(*outLifecycle),input,sizeof(*input)) &&
        (!readOutput || (PendingOutputDisjointV3(readOutput,sizeof(*readOutput),outReceipt,sizeof(*outReceipt)) &&
            PendingOutputDisjointV3(readOutput,sizeof(*readOutput),outLifecycle,sizeof(*outLifecycle)) &&
            PendingOutputDisjointV3(readOutput,sizeof(*readOutput),input,sizeof(*input))));
    Unlock(&cpu->vm->mutex);Unlock(&RegistryMutex);
    if(!disjoint){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
    VZKernelSysRequest q=*input;VZKernelInitWriter stagedWriter=writer?*writer:(VZKernelInitWriter){0};
    VZKernelLifecycleResult lifecycle={0};VZKernelSysReceipt receipt={0};uint64_t stagedOutput=0;
    int modernFeatureIndex=ModernRequestedFeatureIndexV26(q.identifier);
    if(modernFeatureIndex>=0) {
        receipt.descriptor=(VZKernelSysDescriptor){q.identifier,VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE,0,8,0,(uint32_t)(9+modernFeatureIndex)};
        status=VZ_KERNEL_OK;
    } else status=VZKernelSysLookup(q.identifier,&receipt.descriptor);
    if(status==VZ_KERNEL_OK) {
        if(q.action!=VZ_KERNEL_SYS_READ && q.action!=VZ_KERNEL_SYS_WRITE)status=VZ_KERNEL_UNSUPPORTED;
        else if(q.action==VZ_KERNEL_SYS_READ && !readOutput)status=VZ_KERNEL_BAD_ARGUMENT;
        else if(q.action==VZ_KERNEL_SYS_WRITE && receipt.descriptor.domain!=VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE &&
            !stagedWriter.writeMemory)status=VZ_KERNEL_BAD_ARGUMENT;
        else if(CPUOwnedV5(cpu)!=VZ_KERNEL_OK)status=VZ_KERNEL_NOT_LIVE;
        else if(q.expectedOwnerThread!=cpu->owner || q.expectedCPUGeneration!=cpu->generation ||
            q.expectedReturnedSlotWord!=cpu->returnedSlot)status=VZ_KERNEL_BAD_ARGUMENT;
        else if(q.schemaVersion!=1 || q.validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile ||
            q.validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 || q.nativeHVISA!=cpu->vm->nativeHVISA ||
            !VZKernelNativeISAHasValidatedContextV2(q.nativeHVISA))status=VZ_KERNEL_UNSUPPORTED;
        else if(cpu->mutationPoisoned || !cpu->creationPolicySliceComplete)status=VZ_KERNEL_BUSY;
    }
    if(status==VZ_KERNEL_OK && receipt.descriptor.domain==VZ_KERNEL_SYS_PHYSICAL &&
        !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4108,false,NULL))
        status=VZ_KERNEL_CONTEXT_UNREADABLE;
    if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
    if(status==VZ_KERNEL_OK) {
        InitializationAccess opaque={cpu,&stagedWriter,&lifecycle,VZ_KERNEL_OK};
        VZKernelInitAccess access={&opaque,SystemReadMappedV8,SystemWriteMappedV8};
        if(modernFeatureIndex>=0) {
            uint8_t bit=(uint8_t)(1u<<modernFeatureIndex);
            if(q.action==VZ_KERNEL_SYS_WRITE) {
                if(q.value)status=VZ_KERNEL_UNSUPPORTED;
                else {
                    cpu->requestedModernFeatures[modernFeatureIndex]=q.value;
                    cpu->requestedModernFeaturesValid|=bit;
                    receipt.privateFeatureWrites=1;
                }
            } else if(!(cpu->requestedModernFeaturesValid&bit))status=VZ_KERNEL_UNSUPPORTED;
            else {
                stagedOutput=cpu->requestedModernFeatures[modernFeatureIndex];
                receipt.privateFeatureRead=true;
            }
        } else status=VZKernelSysApplyVerifiedRouteV3(&q,&access,&cpu->requestedFeatures,
            &stagedOutput,&receipt,PrepareSystemNative8V8);
        if(status==VZ_KERNEL_OK && !InitializationOwned(&opaque))status=opaque.boundaryStatus;
        if(opaque.boundaryStatus!=VZ_KERNEL_OK)status=opaque.boundaryStatus;
        if(status!=VZ_KERNEL_OK && (receipt.attemptedNativeWrites || receipt.privateFeatureWrites))
            cpu->mutationPoisoned=true;
    }
    CPUResult(cpu,&lifecycle);receipt.status=status;receipt.mutationPoisoned=cpu->mutationPoisoned;
    receipt.cpuCleanupRequired=cpu->live;receipt.completeModernSYSContract=false;receipt.runAllowed=false;
    Finish(&lifecycle,status);
    if(status==VZ_KERNEL_OK && q.action==VZ_KERNEL_SYS_READ)*readOutput=stagedOutput;
    *outReceipt=receipt;*outLifecycle=lifecycle;
    EndOperation(&cpu->operationInProgress);return status;
}


VZKernelStatus VZKernelCPUApplyCreationConfigV6(VZKernelCPU *cpu,
    const VZKernelCreationConfigV6 *config, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *outReceipt, VZKernelLifecycleResult *outLifecycle) {
    if (!cpu || !config || !writer || !writer->writeMemory || !outReceipt || !outLifecycle)
        return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&cpu->operationInProgress)) return VZ_KERNEL_BUSY;
    Lock(&RegistryMutex); Lock(&cpu->vm->mutex);
    bool disjoint = OutputAllPrivateDisjointLockedV5(cpu->vm,config,sizeof(*config)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm,writer,sizeof(*writer)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm,outReceipt,sizeof(*outReceipt)) &&
        OutputAllPrivateDisjointLockedV5(cpu->vm,outLifecycle,sizeof(*outLifecycle)) &&
        PendingOutputDisjointV3(outReceipt,sizeof(*outReceipt),outLifecycle,sizeof(*outLifecycle));
    bool canApply = CPURegisteredLockedV5(cpu) && cpu->registryEntry->creationComplete &&
        !cpu->registryEntry->draining && !cpu->registryEntry->published &&
        !cpu->registryEntry->identityIssued && !cpu->registryEntry->borrowCount;
    Unlock(&cpu->vm->mutex); Unlock(&RegistryMutex);
    if (!disjoint) { EndOperation(&cpu->operationInProgress); return VZ_KERNEL_BAD_ARGUMENT; }
    VZKernelCreationConfigV6 staged = *config; VZKernelInitWriter stagedWriter = *writer;
    VZKernelLifecycleResult lifecycle = {0}; VZKernelInitReceipt receipt = {0};
    receipt.failedNativeOffset = UINT32_MAX; receipt.failedWriteOrdinal = UINT32_MAX;
    VZKernelStatus status = !canApply ? VZ_KERNEL_NOT_LIVE : CPUOwnedV5(cpu);
    if (status == VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        status = VZ_KERNEL_WRONG_THREAD;
    if (status == VZ_KERNEL_OK && (staged.schemaVersion != 1 ||
        staged.fineGrainedTraps > 1 || staged.trapTLBISW > 1 || staged.supportKnown > 1 ||
        staged.supportSupported > 1 || (!staged.supportKnown && staged.supportSupported) ||
        (staged.trapTLBISW && (!staged.supportKnown || !staged.supportSupported)) ||
        !staged.sourceConfigGeneration)) status = VZ_KERNEL_BAD_ARGUMENT;
    if (status == VZ_KERNEL_OK && (cpu->mutationPoisoned || cpu->creationConfigComplete ||
        cpu->creationPolicySliceComplete)) status = VZ_KERNEL_BUSY;
    if (status == VZ_KERNEL_OK) status = Version(cpu,&lifecycle);
    InitializationAccess opaque = {cpu,&stagedWriter,&lifecycle,VZ_KERNEL_OK};
    if (status == VZ_KERNEL_OK) {
        VZKernelInitRequest request = {1,cpu->vm->ops.validatedKernelProfile,cpu->owner,
            cpu->generation,cpu->returnedSlot,cpu->vm->nativeHVISA,
            VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY,0,staged.keyLow,staged.keyHigh};
        VZKernelInitAccess access = {&opaque,InitializationRead,InitializationWrite};
        status = VZKernelInitApplyCreationConfigV3(&request,&access,&receipt);
        if (status == VZ_KERNEL_OK && !InitializationOwned(&opaque)) status = opaque.boundaryStatus;
        if (opaque.boundaryStatus != VZ_KERNEL_OK) status = opaque.boundaryStatus;
    }
    if (status == VZ_KERNEL_OK) {
        cpu->creationConfig = staged; cpu->creationConfigComplete = true;
        cpu->creationPolicySliceComplete = true;
    } else if (receipt.attemptedWrites) cpu->mutationPoisoned = true;
    CPUResult(cpu,&lifecycle); lifecycle.status = status; receipt.status = status;
    receipt.creationPolicySliceComplete = cpu->creationPolicySliceComplete;
    receipt.mutationPoisoned = cpu->mutationPoisoned; receipt.cpuCleanupRequired = cpu->live;
    receipt.architecturalResetComplete = false; receipt.runAllowed = false;
    *outLifecycle = lifecycle; *outReceipt = receipt;
    EndOperation(&cpu->operationInProgress); return status;
}
VZKernelStatus VZKernelCPUCopyCreationConfigV6(VZKernelCPU *cpu,
    VZKernelCreationConfigV6 *out) {
    if (!cpu || !out) return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&cpu->operationInProgress)) return VZ_KERNEL_BUSY;
    Lock(&RegistryMutex); Lock(&cpu->vm->mutex);
    bool disjoint = OutputAllPrivateDisjointLockedV5(cpu->vm,out,sizeof(*out));
    Unlock(&cpu->vm->mutex); Unlock(&RegistryMutex);
    VZKernelStatus status = !disjoint ? VZ_KERNEL_BAD_ARGUMENT : CPUOwnedV5(cpu);
    if (status == VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        status = VZ_KERNEL_WRONG_THREAD;
    if (status == VZ_KERNEL_OK && (!cpu->creationConfigComplete || cpu->mutationPoisoned || cpu->registryEntry->draining))
        status = VZ_KERNEL_NOT_LIVE;
    if (status == VZ_KERNEL_OK) *out = cpu->creationConfig;
    EndOperation(&cpu->operationInProgress); return status;
}

typedef struct {
    VZKernelCPU *cpu;
    uint64_t vmEpoch, generation, owner, token;
    VZKernelLifecycleResult *lifecycle;
    VZKernelStatus status;
} RunPostAccessV7;
static bool RunPostOwnedV7(RunPostAccessV7 *a) {
    VZKernelCPU *cpu=a->cpu;
    if (!cpu->runPostReturnActive || cpu->runToken!=a->token ||
        cpu->generation!=a->generation || cpu->vm->generation!=a->vmEpoch ||
        cpu->owner!=a->owner || CPUOwnedV5(cpu)!=VZ_KERNEL_OK) {
        a->status=VZ_KERNEL_NOT_LIVE;return false;
    }
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context)!=a->owner) {
        a->status=VZ_KERNEL_WRONG_THREAD;return false;
    }
    // Recheck after callback, not merely its returned numeric owner value.
    if (CPUOwnedV5(cpu)!=VZ_KERNEL_OK || !cpu->runPostReturnActive || cpu->runToken!=a->token) {
        a->status=VZ_KERNEL_NOT_LIVE;return false;
    }
    a->status=Version(cpu,a->lifecycle);return a->status==VZ_KERNEL_OK;
}
static bool RunPostReadV7(RunPostAccessV7 *a,uint32_t offset,size_t bytes,void *out) {
    if (!((offset==0x4008 && bytes==4) || (offset==0x400c && bytes==4) ||
        (offset==0x4018 && bytes==8) || (offset==0x4020 && bytes==8)) || !RunPostOwnedV7(a)) return false;
    if (a->cpu->nativeContext>UINTPTR_MAX-offset-bytes) { a->status=VZ_KERNEL_BAD_ARGUMENT;return false; }
    if (!a->cpu->vm->ops.readMemory(a->cpu->vm->ops.context,
        (const void *)(a->cpu->nativeContext+offset),bytes,out)) {
        a->status=VZ_KERNEL_CONTEXT_UNREADABLE;return false;
    }
    return RunPostOwnedV7(a);
}
VZKernelStatus VZKernelCPURunOwnedStepV7(VZKernelCPU *cpu,VZKernelRunStepReceiptV7 *out) {
    if (!cpu || !out) return VZ_KERNEL_BAD_ARGUMENT;
    if (!BeginOperation(&cpu->operationInProgress)) return VZ_KERNEL_BUSY;
    Lock(&RegistryMutex);Lock(&cpu->vm->mutex);
    bool disjoint=OutputAllPrivateDisjointLockedV5(cpu->vm,out,sizeof(*out));
    bool published=CPURegisteredLockedV5(cpu) && cpu->registryEntry->published &&
        !cpu->registryEntry->draining && cpu->registryEntry->creationComplete;
    Unlock(&cpu->vm->mutex);Unlock(&RegistryMutex);
    if (!disjoint) { EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT; }
    VZKernelRunStepReceiptV7 receipt={0};VZKernelStatus status=CPUOwnedV5(cpu);
    if (status==VZ_KERNEL_OK && cpu->vm->ops.currentThread(cpu->vm->ops.context)!=cpu->owner)
        status=VZ_KERNEL_WRONG_THREAD;
    if (status==VZ_KERNEL_OK && (!published || !cpu->creationConfigComplete || cpu->mutationPoisoned))
        status=VZ_KERNEL_NOT_LIVE;
    if (status==VZ_KERNEL_OK && (cpu->pendingInterrupts.irqPending || cpu->pendingInterrupts.fiqPending ||
        cpu->creationConfig.fineGrainedTraps || cpu->creationConfig.trapTLBISW)) status=VZ_KERNEL_UNSUPPORTED;
    if (status==VZ_KERNEL_OK && cpu->runToken==UINT64_MAX) status=VZ_KERNEL_BUSY;
    if (status==VZ_KERNEL_OK) status=Version(cpu,&receipt.lifecycle);
    if (status==VZ_KERNEL_OK) {
        receipt.vmEpoch=cpu->vm->generation;receipt.cpuGeneration=cpu->generation;
        receipt.ownerThread=cpu->owner;receipt.runToken=++cpu->runToken;
        // No borrowed post-return claim from a caller: this same guarded
        // function invokes operation9 itself and creates its private token.
        receipt.lifecycle.nativeInvoked=true;
        receipt.lifecycle.nativeReturn=cpu->vm->ops.nativeTrap(cpu->vm->ops.context,9,NULL);
        memcpy(&receipt.nativeValues.nativeReturnBits,&receipt.lifecycle.nativeReturn,4);
        receipt.nativeValues.schemaVersion=VZ_CPU_EXIT_REDUCER_SCHEMA_V1;
        cpu->runPostReturnActive=true;
        RunPostAccessV7 access={cpu,receipt.vmEpoch,receipt.cpuGeneration,receipt.ownerThread,
            receipt.runToken,&receipt.lifecycle,VZ_KERNEL_OK};
        if (!RunPostOwnedV7(&access)) status=access.status;
        else if (receipt.lifecycle.nativeReturn) status=VZ_KERNEL_NATIVE_ERROR;
        else {
            receipt.nativeValues.nativeContextVersion=receipt.lifecycle.nativeContextVersion;
            if (!RunPostReadV7(&access,0x4008,4,&receipt.nativeValues.rawReason)) status=access.status;
            else {
                receipt.nativeValues.knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
                uint32_t reason=receipt.nativeValues.rawReason;
                if (reason==1 || reason==6 || reason==8) {
                    if (!RunPostReadV7(&access,0x400c,4,&receipt.nativeValues.syndrome32) ||
                        !RunPostReadV7(&access,0x4018,8,&receipt.nativeValues.virtualAddress) ||
                        !RunPostReadV7(&access,0x4020,8,&receipt.nativeValues.physicalAddress)) status=access.status;
                    else receipt.nativeValues.knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
                }
                if (status==VZ_KERNEL_OK && !RunPostOwnedV7(&access)) status=access.status;
                if (status==VZ_KERNEL_OK) {
                    receipt.postReturnIdentityValidated=true;
                    VZCPUExitReducerStatusV1 reduced=VZCPUReduceNativeExitV1(&receipt.nativeValues,&receipt.reduction);
                    if (reduced!=VZ_CPU_EXIT_REDUCER_OK_V1) status=VZ_KERNEL_UNSUPPORTED;
                    else {
                        receipt.reductionValid=true;
                        receipt.publicExceptionProduced=receipt.reduction.hasPublicException==1;
                        if (!receipt.publicExceptionProduced) status=VZ_KERNEL_BUSY;
                    }
                }
            }
        }
        // No post-return read capability or active token survives this call.
        cpu->runPostReturnActive=false;
    }
    CPUResult(cpu,&receipt.lifecycle);receipt.lifecycle.status=status;receipt.status=status;
    *out=receipt;EndOperation(&cpu->operationInProgress);return status;
}

// RAM is in the SAME VM registry as CPU handles. Registry acquisition binds
// opaque RAM to a live allocation before dereference; VM operation exclusion
// precedes every injected callback. No native call is made under VM mutex.
static VZKernelStatus RAMBeginV9(VZKernelVM *needleVM, VZKernelRAMV9 *needleRAM,
 VZKernelVM **outVM, VZKernelRAMV9 **outRAM) {
 Lock(&RegistryMutex);VZKernelVM *vm=RegisteredVM;
 VZKernelRAMV9 *ram=NULL;
 if(vm && needleRAM) {
  Lock(&vm->mutex);
  for(VZKernelRAMV9 *p=vm->ramRegistry;p;p=p->next)if(p==needleRAM){ram=p;break;}
  Unlock(&vm->mutex);
 }
 VZKernelStatus status=!vm || (needleVM && vm!=needleVM) || (needleRAM && !ram)?
  VZ_KERNEL_BAD_ARGUMENT:BeginOperation(&vm->operationInProgress)?VZ_KERNEL_OK:VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK){*outVM=vm;*outRAM=ram;}
 Unlock(&RegistryMutex);return status;
}
static bool RAMDisjointV9(VZKernelVM *vm,const void *p,size_t n) {
 return p && n && n<=UINTPTR_MAX-(uintptr_t)p && OutputAllPrivateDisjointLockedV5(vm,p,n);
}
// Mapping inputs may reuse caller-owned borrowed backing bytes. Unlike an
// output buffer they never receive provider metadata. Provider-owned mmap
// allocations (including guard pages) and every control allocation stay out.
// The caller holds vm->mutex; registry pinning follows the enclosing API.
static bool RAMHostInputDisjointLockedV52(VZKernelVM *vm,const void *p,size_t n) {
 if(!p || !n || n>UINTPTR_MAX-(uintptr_t)p ||
  !PendingOutputDisjointV3(p,n,vm,sizeof(*vm)) || !RAMMetadataDisjointV54(vm,p,n))return false;
 for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next)
  if(!PendingOutputDisjointV3(p,n,r,sizeof(*r)) ||
   (!r->borrowedHost && !PendingOutputDisjointV3(p,n,r->allocation,r->allocationBytes)))return false;
 for(VZKernelCPURegistryEntryV5 *e=vm->cpuRegistry;e;e=e->next) {
  if(!PendingOutputDisjointV3(p,n,e,sizeof(*e)) ||
   !PendingOutputDisjointV3(p,n,e->cpu,sizeof(*e->cpu)))return false;
  uintptr_t native=e->cpu->nativeContext;
  if(native && !PendingOutputDisjointV3(p,n,(const void *)native,0x8000))return false;
  for(VZKernelCPUBorrowV5 *b=e->borrows;b;b=b->next)
   if(!PendingOutputDisjointV3(p,n,b,sizeof(*b)))return false;
 }
 return true;
}
bool VZKernelRAMHostInputRangeDisjointV52(const void *p,size_t n) {
 if(!p || !n || n>UINTPTR_MAX-(uintptr_t)p ||
  !VZKernelCPUControllerOutputRangeDisjointV18(p,n))return false;
 // Controller sidecars are checked outside Registry/VM mutexes.
 Lock(&RegistryMutex);VZKernelVM *vm=RegisteredVM;bool valid=true;
 if(vm){Lock(&vm->mutex);valid=RAMHostInputDisjointLockedV52(vm,p,n);Unlock(&vm->mutex);}
 Unlock(&RegistryMutex);return valid;
}
static _Atomic unsigned RAMFailureLogsV52;
static void RAMFailureV52(const char *stage,VZKernelStatus status,uint64_t gpa,
 uint64_t bytes,bool nativeInvoked) {
 if(status==VZ_KERNEL_OK)return;
 int saved=errno;
 unsigned count=atomic_load_explicit(&RAMFailureLogsV52,memory_order_relaxed);
 while(count<8 && !atomic_compare_exchange_weak_explicit(&RAMFailureLogsV52,
  &count,count+1,memory_order_relaxed,memory_order_relaxed)){}
 if(count<8)dprintf(2,"[Independent27HV] failed stage=ram-%s ordinal=%u GPA=0x%llx bytes=0x%llx status=%u nativeInvoked=%u\n",
  stage,count+1,(unsigned long long)gpa,(unsigned long long)bytes,(unsigned)status,nativeInvoked);
 errno=saved;
}
static bool RAMOwnerV9(VZKernelVM *vm) {
 return vm->ops.currentThread(vm->ops.context)==vm->owner &&
  pthread_equal(pthread_self(),vm->ownerPthread);
}
// RAM add/adopt/map belongs to this task's actual VM, not its creator pthread.
// This hidden lookup compares the opaque VM before dereference. It does not
// invoke ownership/native callbacks while Registry/VM mutexes are held.
VZKernelStatus VZKernelRAMTaskScopeV53(VZKernelVM *needle,uint64_t epoch) {
 if(!needle || !epoch)return VZ_KERNEL_BAD_ARGUMENT;
 Lock(&RegistryMutex);VZKernelVM *vm=RegisteredVM;VZKernelStatus status=VZ_KERNEL_NOT_LIVE;
 if(vm==needle) {
  Lock(&vm->mutex);
  status=!vm->live || vm->generation!=epoch?VZ_KERNEL_NOT_LIVE:
   vm->taskPID<=0 || vm->taskPID!=getpid()?VZ_KERNEL_WRONG_THREAD:
   vm->ops.schemaVersion!=1 || vm->ops.validatedKernelProfile!=VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
   !vm->ops.context || !vm->ops.nativeTrap || !vm->ops.currentThread || !vm->ops.readMemory?
   VZ_KERNEL_BAD_ARGUMENT:VZ_KERNEL_OK;
  Unlock(&vm->mutex);
 }
 Unlock(&RegistryMutex);return status;
}
// The real VM operation exclusion is held before this injected callback.
static bool RAMTaskCallerV53(VZKernelVM *vm) {
 return VZKernelRAMTaskScopeV53(vm,vm->generation)==VZ_KERNEL_OK &&
  vm->ops.currentThread(vm->ops.context)!=0;
}
static VZKernelStatus RAMReadyV50(VZKernelVM *vm,VZKernelRAMV9 *ram,bool additive) {
 if(additive?!RAMTaskCallerV53(vm):!RAMOwnerV9(vm))return VZ_KERNEL_WRONG_THREAD;
 Lock(&vm->mutex);
 VZKernelStatus status=!vm->live?VZ_KERNEL_NOT_LIVE:
  (!additive && (vm->cpuHandles || vm->cpuRegistry))?VZ_KERNEL_BUSY:
  ram && (ram->vm!=vm || ram->epoch!=vm->generation)?VZ_KERNEL_NOT_LIVE:VZ_KERNEL_OK;
 Unlock(&vm->mutex);return status;
}
static VZKernelStatus RAMReadyV9(VZKernelVM *vm,VZKernelRAMV9 *ram) {
 return RAMReadyV50(vm,ram,false);
}
static void RAMResultV9(VZKernelVM *vm,VZKernelRAMV9 *ram,VZKernelStatus status,
 bool invoked,int32_t nativeReturn,VZKernelRAMResultV9 *out) {
 VZKernelRAMResultV9 r={0};r.status=status;r.nativeInvoked=invoked;r.nativeReturn=nativeReturn;
 r.vmEpoch=vm->generation;r.ownerThread=vm->owner;
 if(ram){r.bytes=ram->bytes;r.guestAddress=ram->guestAddress;r.flags=ram->flags;
 r.mapped=ram->mapped;r.mappingUncertain=ram->uncertain;r.cleanupPending=true;}
 memcpy(out,&r,sizeof(r));
}
VZKernelStatus VZKernelRAMCreateV9(VZKernelVM *needle,uint64_t bytes,
 VZKernelRAMV9 **outRAM,void **outHost,VZKernelRAMResultV9 *out) {
 if(!needle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelVM *vm=NULL;VZKernelRAMV9 *unused=NULL;
 VZKernelStatus status=RAMBeginV9(needle,NULL,&vm,&unused);if(status)return status;
 Lock(&vm->mutex);
 bool valid=RAMDisjointV9(vm,outRAM,sizeof(*outRAM)) && RAMDisjointV9(vm,outHost,sizeof(*outHost)) &&
  RAMDisjointV9(vm,out,sizeof(*out)) && PendingOutputDisjointV3(outRAM,sizeof(*outRAM),outHost,sizeof(*outHost)) &&
  PendingOutputDisjointV3(out,sizeof(*out),outRAM,sizeof(*outRAM)) &&
  PendingOutputDisjointV3(out,sizeof(*out),outHost,sizeof(*outHost));
 Unlock(&vm->mutex);
 if(!valid){EndOperation(&vm->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 status=RAMReadyV50(vm,NULL,true);VZKernelRAMV9 *ram=NULL;
 const size_t page=VZ_KERNEL_MEMORY_PROFILE_PAGE_BYTES;
 if(status==VZ_KERNEL_OK && (!bytes || bytes&(page-1) || bytes>(UINT64_C(1)<<36) || bytes>SIZE_MAX-3*page))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK) {
  ram=calloc(1,sizeof(*ram));if(!ram)status=VZ_KERNEL_OUT_OF_MEMORY;
 }
 if(status==VZ_KERNEL_OK) {
  size_t total=(size_t)bytes+3*page;
  void *allocation=mmap(NULL,total,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
  if(allocation==MAP_FAILED)status=VZ_KERNEL_OUT_OF_MEMORY;
  else {
   uintptr_t start=((uintptr_t)allocation+2*page-1)&~(uintptr_t)(page-1);
   if(mprotect((void *)start,(size_t)bytes,PROT_READ|PROT_WRITE)) {
    if(munmap(allocation,total))abort();status=VZ_KERNEL_NATIVE_ERROR;
   } else {ram->allocation=allocation;ram->allocationBytes=total;ram->host=(void *)start;}
  }
 }
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->generation;ram->bytes=bytes;
  Lock(&vm->mutex);ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock(&vm->mutex);
  *outRAM=ram;*outHost=ram->host;
 } else {free(ram);ram=NULL;}
 RAMResultV9(vm,ram,status,false,0,out);EndOperation(&vm->operationInProgress);return status;
}
VZKernelStatus VZKernelRAMAdoptHostRangeV11(VZKernelVM *needle,void *host,uint64_t bytes,
 VZKernelRAMV9 **outRAM,VZKernelRAMResultV9 *out) {
 if(!needle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelVM *vm=NULL;VZKernelRAMV9 *unused=NULL;
 VZKernelStatus status=RAMBeginV9(needle,NULL,&vm,&unused);
 if(status){RAMFailureV52("adopt-admission",status,0,bytes,false);return status;}
 bool controllerDisjoint=VZKernelCPUControllerOutputRangeDisjointV18(host,(size_t)bytes);
 Lock(&vm->mutex);
 bool valid=RAMDisjointV9(vm,outRAM,sizeof(*outRAM)) && RAMDisjointV9(vm,out,sizeof(*out)) &&
  controllerDisjoint && RAMHostInputDisjointLockedV52(vm,host,(size_t)bytes) &&
  PendingOutputDisjointV3(out,sizeof(*out),outRAM,sizeof(*outRAM)) &&
  PendingOutputDisjointV3(host,(size_t)bytes,outRAM,sizeof(*outRAM)) &&
  PendingOutputDisjointV3(host,(size_t)bytes,out,sizeof(*out));
 Unlock(&vm->mutex);
 if(!valid){RAMFailureV52("adopt-input-control",VZ_KERNEL_BAD_ARGUMENT,0,bytes,false);EndOperation(&vm->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 status=RAMReadyV50(vm,NULL,true);VZKernelRAMV9 *ram=NULL;
 const char *failure="adopt-owner-or-state";
 const size_t page=VZ_KERNEL_MEMORY_PROFILE_PAGE_BYTES;
 if(status==VZ_KERNEL_OK && (!bytes || bytes&(page-1) || (uintptr_t)host&(page-1) ||
  bytes>(UINT64_C(1)<<36) || bytes>SIZE_MAX)){status=VZ_KERNEL_BAD_ARGUMENT;failure="adopt-geometry";}
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1(host,(size_t)bytes,false,NULL)){status=VZ_KERNEL_CONTEXT_UNREADABLE;failure="adopt-host-read";}
 if(status==VZ_KERNEL_OK && !RAMTaskCallerV53(vm)){status=VZ_KERNEL_WRONG_THREAD;failure="adopt-task";}
 if(status==VZ_KERNEL_OK){ram=calloc(1,sizeof(*ram));if(!ram){status=VZ_KERNEL_OUT_OF_MEMORY;failure="adopt-allocation";}}
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->generation;ram->bytes=bytes;ram->host=host;
  ram->allocation=host;ram->allocationBytes=(size_t)bytes;ram->borrowedHost=true;
  Lock(&vm->mutex);ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock(&vm->mutex);*outRAM=ram;
 }
 RAMResultV9(vm,ram,status,false,0,out);RAMFailureV52(failure,status,0,bytes,false);EndOperation(&vm->operationInProgress);return status;
}
static VZKernelStatus RAMAdmitV9(VZKernelRAMV9 *needle,VZKernelRAMResultV9 *out,
 VZKernelVM **vm,VZKernelRAMV9 **ram) {
 if(!needle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=RAMBeginV9(NULL,needle,vm,ram);if(status)return status;
 Lock(&(*vm)->mutex);bool valid=RAMDisjointV9(*vm,out,sizeof(*out));Unlock(&(*vm)->mutex);
 if(!valid){EndOperation(&(*vm)->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 return VZ_KERNEL_OK;
}
VZKernelStatus VZKernelRAMWriteV9(VZKernelRAMV9 *needle,uint64_t offset,
 const void *source,size_t bytes,VZKernelRAMResultV9 *out) {
 VZKernelVM *vm=NULL;VZKernelRAMV9 *ram=NULL;
 VZKernelStatus status=RAMAdmitV9(needle,out,&vm,&ram);if(status)return status;
 Lock(&vm->mutex);bool valid=RAMDisjointV9(vm,source,bytes) &&
  PendingOutputDisjointV3(source,bytes,out,sizeof(*out));Unlock(&vm->mutex);
 if(!valid){EndOperation(&vm->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 status=RAMReadyV9(vm,ram);
 if(status==VZ_KERNEL_OK && ram->uncertain)status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK && (offset>ram->bytes || bytes>ram->bytes-offset))status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK) {
  void *target=(uint8_t *)ram->host+offset;
  if(!VM27CPUSelfMappedRangeV1(source,bytes,false,NULL) ||
     !VM27CPUSelfMappedRangeV1(target,bytes,true,NULL))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else memcpy(target,source,bytes);
 }
 RAMResultV9(vm,ram,status,false,0,out);EndOperation(&vm->operationInProgress);return status;
}
#include "../modern_cpu_ram_range_v54.inc"
VZKernelStatus VZKernelRAMFreeV9(VZKernelRAMV9 *needle) {
 if(!needle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelVM *vm=NULL;VZKernelRAMV9 *ram=NULL;
 VZKernelStatus status=RAMBeginV9(NULL,needle,&vm,&ram);if(status)return status;
 status=RAMReadyV9(vm,ram);
 if(status==VZ_KERNEL_OK && (ram->mapped || ram->uncertain || ram->segments))status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK && !ram->borrowedHost && munmap(ram->allocation,ram->allocationBytes))status=VZ_KERNEL_NATIVE_ERROR;
 if(status==VZ_KERNEL_OK) {
  Lock(&vm->mutex);VZKernelRAMV9 **link=&vm->ramRegistry;
  while(*link && *link!=ram)link=&(*link)->next;
  if(!*link)abort();*link=ram->next;Unlock(&vm->mutex);free(ram);
 }
 EndOperation(&vm->operationInProgress);return status;
}

__attribute__((visibility("hidden")))
bool VZKernelRAMOutputRangeDisjointV9(const void *out,size_t bytes) {
 if(!out || !bytes || bytes>UINTPTR_MAX-(uintptr_t)out)return false;
 Lock(&RegistryMutex);VZKernelVM *vm=RegisteredVM;bool valid=true;
 if(vm){Lock(&vm->mutex);valid=RAMMetadataDisjointV54(vm,out,bytes);for(VZKernelRAMV9 *r=vm->ramRegistry;valid && r;r=r->next)
  valid=PendingOutputDisjointV3(out,bytes,r,sizeof(*r)) &&
        PendingOutputDisjointV3(out,bytes,r->allocation,r->allocationBytes);
 Unlock(&vm->mutex);}
 Unlock(&RegistryMutex);return valid;
}

VZKernelStatus VZKernelCPUReadRegisterV10(VZKernelCPU *cpu,VZKernelInitOperation operation,
 uint32_t identifier,VZKernelRegisterValueV10 *out,VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !out || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=BeginCPUOperation(cpu);if(status==VZ_KERNEL_BUSY)return status;
 Lock(&cpu->vm->mutex);
 bool valid=OutputAllPrivateDisjointLockedV5(cpu->vm,out,sizeof(*out)) &&
  OutputAllPrivateDisjointLockedV5(cpu->vm,outLifecycle,sizeof(*outLifecycle)) &&
  PendingOutputDisjointV3(out,sizeof(*out),outLifecycle,sizeof(*outLifecycle));
 Unlock(&cpu->vm->mutex);
 if(!valid){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelLifecycleResult lifecycle={0};VZKernelRegisterValueV10 value={0};
 if(status==VZ_KERNEL_OK)status=CPUOwnedV5(cpu);
 if(status==VZ_KERNEL_OK && (!cpu->creationConfigComplete || cpu->mutationPoisoned))status=VZ_KERNEL_BUSY;
 uint32_t offset=0;size_t bytes=0;
 if(operation==VZ_KERNEL_INIT_SCALAR && identifier<=34) {
  bytes=identifier>31?4:8;
  const uint32_t special[]={0x108,0x344,0x340,0x110};
  offset=identifier<31?8+identifier*8:special[identifier-31];
 }else if(operation==VZ_KERNEL_INIT_SIMD && identifier<32){offset=0x140+identifier*16;bytes=16;}
 else if(status==VZ_KERNEL_OK)status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&lifecycle);
 if(status==VZ_KERNEL_OK) {
  InitializationAccess a={cpu,NULL,&lifecycle,VZ_KERNEL_OK};
  if(!SystemReadMappedV8(&a,offset,bytes,&value))status=a.boundaryStatus==VZ_KERNEL_OK?
   VZ_KERNEL_CONTEXT_UNREADABLE:a.boundaryStatus;
  else if(!InitializationOwned(&a))status=a.boundaryStatus;
 }
 CPUResult(cpu,&lifecycle);lifecycle.status=status;
 if(status==VZ_KERNEL_OK)*out=value;
 *outLifecycle=lifecycle;EndOperation(&cpu->operationInProgress);return status;
}

#include "modern_cpu_kernel_vtimer_v12.inc"
#include "modern_cpu_kernel_debug_v13.inc"
#include "modern_cpu_kernel_pending_run_v20_control0.inc"
#include "modern_cpu_kernel_debug_claim_v15.inc"
#include "modern_cpu_kernel_actlr_v16.inc"
#include "modern_cpu_kernel_physical_timer_v16.inc"
#include "../modern_cpu_kernel_physical_timer_v21_snapshot.inc"
#include "modern_cpu_wfx_wait_v31.h"
static VZKernelStatus GICWakeNotifyV30(const VZKernelRunPendingRequestV14 *,VZKernelStatus);
#include "modern_cpu_kernel_wake_owner_v32.inc"
#define VZKernelReadCounterDomainSampleV19 VZKernelReadCounterDomainSampleV21
#include "modern_cpu_kernel_gic_owner_v31.inc"
#undef VZKernelReadCounterDomainSampleV19
#include "modern_cpu_kernel_vtimer_mask_v20.inc"
#include "modern_cpu_kernel_gic_run_v70_timer_snapshot.inc"
VZKernelStatus VZKernelCPUProducerPoisonV20(VZKernelCPU *cpu,const VZKernelRunPendingRequestV14 *q) {
 if(!cpu || !q)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus s=BeginCPUOperation(cpu);if(s==VZ_KERNEL_BUSY)return s;
 if(s==VZ_KERNEL_OK)s=CPUOwnedV5(cpu);
 if(s==VZ_KERNEL_OK && (q->schemaVersion!=1 || q->reserved ||
  q->expectedVMEpoch!=cpu->vm->generation || q->expectedCPUGeneration!=cpu->generation ||
  q->expectedOwnerThread!=cpu->owner || q->expectedPublicIdentity!=cpu->registryEntry->publicIdentity ||
  q->expectedReturnedSlotWord!=cpu->returnedSlot || q->nativeHVISA!=cpu->vm->nativeHVISA ||
  q->validatedKernelProfile!=cpu->vm->ops.validatedKernelProfile))s=VZ_KERNEL_BAD_ARGUMENT;
 if(s==VZ_KERNEL_OK)GICPoisonV20(cpu);
 EndOperation(&cpu->operationInProgress);return s;
}

#include "modern_cpu_kernel_control_v26.inc"
#include "modern_cpu_kernel_dtr_v23.inc"
