#include "modern_cpu_kernel_profile_v2.h"
// Real native op1/op2/op6/op7 lifecycle, with explicit owner-thread cleanup.
// No Hypervisor framework is linked or loaded. Optional initialization uses
// explicit typed slices; create/read/destroy alone never writes native state.
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_kernel_lifecycle_v4.h"
#include "modern_cpu_native_fields.h"
#include "modern_cpu_kernel_initialization_private.h"
#include "modern_cpu_kernel_system_private.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdatomic.h>

_Static_assert(sizeof(void *) == 8, "Audited LP64 kernel ABI only");
_Static_assert(sizeof(VZKernelNativeVMConfig) == 32, "Native VM input width");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaLimit) == 8, "Native IPA field");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaGranule) == 16, "Native granule field");
_Static_assert(offsetof(VZKernelNativeVMConfig, nativeHVISA) == 24, "Native ISA field");
typedef struct { uint64_t requestedSlot; uintptr_t nativeContext; } NativeCPUCreate;
_Static_assert(sizeof(NativeCPUCreate) == 16, "Native CPU-create argument width");
_Static_assert(offsetof(NativeCPUCreate, nativeContext) == 8, "Kernel output field");

typedef struct VZKernelCPURegistryEntryV4 {
    struct VZKernelCPURegistryEntryV4 *next;
    struct VZKernelCPU *cpu;
    uint64_t vmEpoch, cpuGeneration;
    pthread_t ownerPthread;
} VZKernelCPURegistryEntryV4;

struct VZKernelVM {
    VZKernelLifecycleOps ops;
    pthread_mutex_t mutex;
    uint64_t owner, generation; // Stable VM allocation epoch.
    pthread_t ownerPthread;
    uint32_t nativeHVISA;
    bool live;
    _Atomic bool operationInProgress;
    unsigned cpuHandles;
    unsigned liveCPUs;
    VZKernelCPURegistryEntryV4 *cpuRegistry;
};
struct VZKernelCPU {
    struct VZKernelVM *vm;
    VZKernelCPURegistryEntryV4 *registryEntry;
    uint64_t owner, generation, returnedSlot;
    uintptr_t nativeContext;
    bool live;
    _Atomic bool operationInProgress;
    bool creationPolicySliceComplete;
    bool mutationPoisoned;
    VZKernelSysFeatureCache requestedFeatures;
    // Own calloc-backed IRQ/FIQ values, never native creation defaults.
    VZCPUPendingInterruptValuesV1 pendingInterrupts;
};

static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static VZKernelVM *RegisteredVM;
static uint64_t NextGeneration;
static uint64_t NextCPUGenerationV4;
static _Atomic bool VMCreateInProgress;
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
static void CPUResult(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    if (!r) return;
    Lock(&cpu->vm->mutex);
    r->vmLive = cpu->vm->live;
    r->cpuLive = cpu->live;
    r->cleanupPending = r->vmLive || r->cpuLive;
    r->ownerThread = cpu->owner;
    r->generation = cpu->generation;
    r->requestedSlot = 0;
    r->returnedSlotWord = cpu->returnedSlot;
    Unlock(&cpu->vm->mutex);
}

// Caller holds the VM mutex and CPU operation guard. Registry identity is
// separate from returned native packet words and original public CPU IDs.
static bool CPURegisteredLockedV4(VZKernelCPU *cpu) {
    VZKernelVM *vm = cpu->vm;
    for (VZKernelCPURegistryEntryV4 *entry = vm->cpuRegistry; entry; entry = entry->next) {
        if (entry == cpu->registryEntry && entry->cpu == cpu)
            return entry->vmEpoch == vm->generation && entry->cpuGeneration != 0 &&
                entry->cpuGeneration == cpu->generation;
    }
    return false;
}
static VZKernelStatus CPUOwnedV4(VZKernelCPU *cpu) {
    Lock(&cpu->vm->mutex);
    bool valid = cpu->vm->live && cpu->live && OwnedCPU == cpu && CPURegisteredLockedV4(cpu) &&
        pthread_equal(pthread_self(), cpu->registryEntry->ownerPthread);
    Unlock(&cpu->vm->mutex);
    return valid ? VZ_KERNEL_OK : VZ_KERNEL_NOT_LIVE;
}
static bool RemoveCPUEntryLockedV4(VZKernelCPU *cpu) {
    VZKernelCPURegistryEntryV4 **link = &cpu->vm->cpuRegistry;
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
    uint64_t thread = ops->currentThread(ops->context);
    if (!thread) { EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_WRONG_THREAD); }
    VZKernelVM *vm = calloc(1, sizeof(*vm));
    if (!vm) { EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    vm->ops = *ops; vm->owner = thread; vm->nativeHVISA = config.nativeHVISA;
    vm->ownerPthread = pthread_self();
    atomic_init(&vm->operationInProgress, true);
    if (pthread_mutex_init(&vm->mutex, NULL)) { free(vm); EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    Lock(&RegistryMutex);
    if (RegisteredVM || NextGeneration == UINT64_MAX) {
        Unlock(&RegistryMutex); pthread_mutex_destroy(&vm->mutex); free(vm);
        EndOperation(&VMCreateInProgress); return Finish(r, VZ_KERNEL_BUSY);
    }
    vm->generation = ++NextGeneration;
    RegisteredVM = vm; // Reserve before the real call; reentrant create is blocked.
    Unlock(&RegistryMutex);
    r->nativeInvoked = true;
    r->nativeReturn = ops->nativeTrap(ops->context, 1, &config);
    if (r->nativeReturn) {
        Lock(&RegistryMutex); RegisteredVM = NULL; Unlock(&RegistryMutex);
        pthread_mutex_destroy(&vm->mutex); free(vm);
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
    if (!vm->live || vm->cpuHandles || vm->cpuRegistry) {
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
    bool busy = vm->live || vm->cpuRegistry || vm->cpuHandles;
    Unlock(&vm->mutex);
    if (busy) { EndOperation(&vm->operationInProgress); return VZ_KERNEL_BUSY; }
    Lock(&RegistryMutex);
    if (RegisteredVM != vm) {
        Unlock(&RegistryMutex); EndOperation(&vm->operationInProgress);
        return VZ_KERNEL_BAD_ARGUMENT;
    }
    RegisteredVM = NULL; Unlock(&RegistryMutex);
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
    VZKernelCPURegistryEntryV4 *entry = calloc(1, sizeof(*entry));
    if (!entry) { free(cpu); EndOperation(&vm->operationInProgress); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    cpu->vm = vm; cpu->owner = thread; cpu->registryEntry = entry;
    entry->cpu = cpu; entry->ownerPthread = pthread_self();
    cpu->pendingInterrupts.schemaVersion = VZ_CPU_PENDING_VALUES_SCHEMA_V1;
    atomic_init(&cpu->operationInProgress, true);
    Lock(&vm->mutex);
    Lock(&RegistryMutex);
    if (!vm->live || NextCPUGenerationV4 == UINT64_MAX || vm->cpuHandles == UINT_MAX) {
        bool live = vm->live; Unlock(&RegistryMutex); Unlock(&vm->mutex); free(entry); free(cpu);
        EndOperation(&vm->operationInProgress);
        return Finish(r, live ? VZ_KERNEL_BUSY : VZ_KERNEL_NOT_LIVE);
    }
    // Existing typed requests carry CPU generation without VM epoch. Never
    // recycle that generation across VM lifetimes (including create failures).
    cpu->generation = ++NextCPUGenerationV4;
    Unlock(&RegistryMutex);
    entry->cpuGeneration = cpu->generation; entry->vmEpoch = vm->generation;
    entry->next = vm->cpuRegistry; vm->cpuRegistry = entry; ++vm->cpuHandles;
    Unlock(&vm->mutex);
    OwnedCPU = cpu; // The real kernel and the private handle use this worker.
    NativeCPUCreate args = {0, 0};
    r->nativeInvoked = true;
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 6, &args);
    if (r->nativeReturn) {
        OwnedCPU = NULL; Lock(&vm->mutex);
        if (!RemoveCPUEntryLockedV4(cpu)) abort();
        Unlock(&vm->mutex); free(entry); free(cpu); EndOperation(&vm->operationInProgress);
        return Finish(r, VZ_KERNEL_NATIVE_ERROR);
    }
    cpu->returnedSlot = args.requestedSlot;
    cpu->nativeContext = args.nativeContext;
    // Record real ownership BEFORE checking a read or version, preserving
    // a valid cleanup handle even if the returned context cannot be consumed.
    Lock(&vm->mutex); cpu->live = true; ++vm->liveCPUs; Unlock(&vm->mutex);
    VZKernelStatus status = Version(cpu, r);
    // Publish only after the version callback has returned under exclusion.
    // A real successful creation still supplies its live cleanup handle on a
    // version/read error; no version validity is required for owner teardown.
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
    status = CPUOwnedV4(cpu);
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
    status = CPUOwnedV4(cpu);
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
    if (CPUOwnedV4(cpu) != VZ_KERNEL_OK) {
        EndOperation(&cpu->operationInProgress); return Finish(r, VZ_KERNEL_NOT_LIVE);
    }
    r->nativeInvoked = true;
    // Original old native destroy is op7 with NULL, CURRENT owner; the ID
    // selects a userspace table slot only. Never send a fabricated ID struct.
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 7, NULL);
    if (!r->nativeReturn) {
        Lock(&vm->mutex); cpu->live = false; cpu->nativeContext = 0;
        memset(&cpu->pendingInterrupts, 0, sizeof(cpu->pendingInterrupts));
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
    if (!CPURegisteredLockedV4(cpu)) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_BAD_ARGUMENT;
    }
    if (!pthread_equal(pthread_self(), cpu->registryEntry->ownerPthread)) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_WRONG_THREAD;
    }
    if (cpu->live || OwnedCPU == cpu) {
        Unlock(&vm->mutex); EndOperation(&cpu->operationInProgress); return VZ_KERNEL_BUSY;
    }
    if (!RemoveCPUEntryLockedV4(cpu)) abort();
    VZKernelCPURegistryEntryV4 *entry = cpu->registryEntry;
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
        CPUOwnedV4(cpu) != VZ_KERNEL_OK) {
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
    if (CPUOwnedV4(cpu) != VZ_KERNEL_OK)
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
    return CPUOwnedV4(cpu);
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

static bool PendingOutputAllPrivateDisjointV4(VZKernelCPU *cpu, const void *out, size_t bytes) {
    VZKernelVM *vm = cpu->vm;
    Lock(&vm->mutex);
    bool disjoint = PendingOutputDisjointV3(out, bytes, vm, sizeof(*vm));
    for (VZKernelCPURegistryEntryV4 *entry = vm->cpuRegistry; disjoint && entry; entry = entry->next)
        disjoint = PendingOutputDisjointV3(out, bytes, entry, sizeof(*entry)) &&
            PendingOutputDisjointV3(out, bytes, entry->cpu, sizeof(*entry->cpu));
    Unlock(&vm->mutex);
    return disjoint;
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
        !PendingOutputAllPrivateDisjointV4(cpu, out, sizeof(*out)))
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

VZKernelStatus VZKernelCPUAccessSystemRegister(VZKernelCPU *cpu,
    const VZKernelSysRequest *q, const VZKernelInitWriter *writer, uint64_t *readOutput,
    VZKernelSysReceipt *receipt, VZKernelLifecycleResult *r) {
    Start(r);
    if (receipt) memset(receipt, 0, sizeof(*receipt));
    if (!cpu || !q || !receipt || !r ||
        (q->action == VZ_KERNEL_SYS_READ && !readOutput)) {
        if (receipt) receipt->status = VZ_KERNEL_BAD_ARGUMENT;
        return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    }
    VZKernelStatus status = BeginCPUOperation(cpu);
    if (status == VZ_KERNEL_BUSY) {
        receipt->status = status; return Finish(r, status);
    }
    if (status != VZ_KERNEL_OK) goto finish;
    status = VZKernelSysLookup(q->identifier, &receipt->descriptor);
    if (status != VZ_KERNEL_OK) goto finish;
    if (q->action != VZ_KERNEL_SYS_READ && q->action != VZ_KERNEL_SYS_WRITE)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (q->action == VZ_KERNEL_SYS_WRITE &&
        receipt->descriptor.domain != VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE &&
        (!writer || !writer->writeMemory))
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (CPUOwnedV4(cpu) != VZ_KERNEL_OK)
        status = VZ_KERNEL_NOT_LIVE;
    else if (q->expectedOwnerThread != cpu->owner || q->expectedCPUGeneration != cpu->generation ||
        q->expectedReturnedSlotWord != cpu->returnedSlot)
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (q->schemaVersion != 1 || q->validatedKernelProfile != cpu->vm->ops.validatedKernelProfile ||
        q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->nativeHVISA != cpu->vm->nativeHVISA || !VZKernelNativeISAHasValidatedContextV2(q->nativeHVISA))
        status = VZ_KERNEL_UNSUPPORTED;
    else if (cpu->mutationPoisoned || !cpu->creationPolicySliceComplete)
        status = VZ_KERNEL_BUSY;
    if (status != VZ_KERNEL_OK) goto finish;
    status = Version(cpu, r);
    if (status != VZ_KERNEL_OK) goto finish;
    InitializationAccess opaque = {cpu, writer, r, VZ_KERNEL_OK};
    VZKernelInitAccess access = {&opaque, InitializationRead, InitializationWrite};
    uint64_t stagedOutput = 0;
    status = VZKernelSysApplyVerifiedRoute(q, &access, &cpu->requestedFeatures, &stagedOutput, receipt);
    if (status == VZ_KERNEL_OK && !InitializationOwned(&opaque)) status = opaque.boundaryStatus;
    if (opaque.boundaryStatus != VZ_KERNEL_OK) status = opaque.boundaryStatus;
    if (status != VZ_KERNEL_OK && (receipt->attemptedNativeWrites || receipt->privateFeatureWrites))
        cpu->mutationPoisoned = true;
    if (status == VZ_KERNEL_OK && q->action == VZ_KERNEL_SYS_READ) *readOutput = stagedOutput;
finish:
    CPUResult(cpu, r);
    receipt->status = status;
    receipt->mutationPoisoned = cpu->mutationPoisoned;
    receipt->cpuCleanupRequired = cpu->live;
    receipt->nativeOp8Invoked = false;
    receipt->completeModernSYSContract = false;
    receipt->runAllowed = false;
    EndOperation(&cpu->operationInProgress);
    return Finish(r, status);
}
