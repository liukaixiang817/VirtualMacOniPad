// Real native op1/op2/op6/op7 lifecycle, with explicit owner-thread cleanup.
// No Hypervisor framework is linked or loaded. Optional initialization uses
// explicit typed slices; create/read/destroy alone never writes native state.
#include "modern_cpu_kernel_lifecycle.h"
#include "modern_cpu_native_fields.h"
#include "modern_cpu_kernel_initialization_private.h"
#include "modern_cpu_kernel_system_private.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

_Static_assert(sizeof(void *) == 8, "Audited LP64 kernel ABI only");
_Static_assert(sizeof(VZKernelNativeVMConfig) == 32, "Native VM input width");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaLimit) == 8, "Native IPA field");
_Static_assert(offsetof(VZKernelNativeVMConfig, ipaGranule) == 16, "Native granule field");
_Static_assert(offsetof(VZKernelNativeVMConfig, nativeHVISA) == 24, "Native ISA field");
typedef struct { uint64_t requestedSlot; uintptr_t nativeContext; } NativeCPUCreate;
_Static_assert(sizeof(NativeCPUCreate) == 16, "Native CPU-create argument width");
_Static_assert(offsetof(NativeCPUCreate, nativeContext) == 8, "Kernel output field");

struct VZKernelVM {
    VZKernelLifecycleOps ops;
    pthread_mutex_t mutex;
    uint64_t owner, generation;
    uint32_t nativeHVISA;
    bool live;
    unsigned cpuHandles;
    struct VZKernelCPU *activeCPU;
};
struct VZKernelCPU {
    struct VZKernelVM *vm;
    uint64_t owner, generation, returnedSlot;
    uintptr_t nativeContext;
    bool live;
    bool initializationInProgress;
    bool creationPolicySliceComplete;
    bool mutationPoisoned;
    VZKernelSysFeatureCache requestedFeatures;
};

static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static VZKernelVM *RegisteredVM;
static uint64_t NextGeneration;
// This is private compatibility-module TLS. Apple's VMM TLV is untouched.
static _Thread_local VZKernelCPU *OwnedCPU;

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
    r->cpuLive = vm->activeCPU && vm->activeCPU->live;
    r->cleanupPending = r->vmLive || vm->activeCPU;
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
    // Only the exact old constructor default has an established call contract
    // for this first milestone. This does not advertise a hardware maximum.
    // +24 is the genuine Hypervisor config's native selector; it is NOT a
    // serialized guest ISA value. The conversion helper is a separate step.
    if (options->ipaBits != 36 || options->ipaGranule != 0 ||
        options->nativeHVISA != VZ_KERNEL_NATIVE_HV_ISA_1 || options->el2Enabled || options->vheEnabled)
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
    uint64_t thread = ops->currentThread(ops->context);
    if (!thread) return Finish(r, VZ_KERNEL_WRONG_THREAD);
    VZKernelVM *vm = calloc(1, sizeof(*vm));
    if (!vm) return Finish(r, VZ_KERNEL_OUT_OF_MEMORY);
    vm->ops = *ops; vm->owner = thread; vm->nativeHVISA = config.nativeHVISA;
    if (pthread_mutex_init(&vm->mutex, NULL)) { free(vm); return Finish(r, VZ_KERNEL_OUT_OF_MEMORY); }
    Lock(&RegistryMutex);
    if (RegisteredVM || NextGeneration == UINT64_MAX) {
        Unlock(&RegistryMutex); pthread_mutex_destroy(&vm->mutex); free(vm);
        return Finish(r, VZ_KERNEL_BUSY);
    }
    vm->generation = ++NextGeneration;
    RegisteredVM = vm; // Reserve before the real call; reentrant create is blocked.
    Unlock(&RegistryMutex);
    r->nativeInvoked = true;
    r->nativeReturn = ops->nativeTrap(ops->context, 1, &config);
    if (r->nativeReturn) {
        Lock(&RegistryMutex); RegisteredVM = NULL; Unlock(&RegistryMutex);
        pthread_mutex_destroy(&vm->mutex); free(vm);
        return Finish(r, VZ_KERNEL_NATIVE_ERROR);
    }
    vm->live = true; *outVM = vm; VMResult(vm, r);
    return Finish(r, VZ_KERNEL_OK);
}

VZKernelStatus VZKernelVMDestroy(VZKernelVM *vm, VZKernelLifecycleResult *r) {
    Start(r);
    if (!vm || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    if (vm->ops.currentThread(vm->ops.context) != vm->owner)
        return Finish(r, VZ_KERNEL_WRONG_THREAD);
    Lock(&vm->mutex);
    VMResult(vm, r);
    if (!vm->live) { Unlock(&vm->mutex); return Finish(r, VZ_KERNEL_NOT_LIVE); }
    if (vm->activeCPU) { Unlock(&vm->mutex); return Finish(r, VZ_KERNEL_BUSY); }
    // CPU creation checks this same lock, so cannot race the native destroy.
    r->nativeInvoked = true;
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 2, NULL);
    if (!r->nativeReturn) vm->live = false;
    VMResult(vm, r); Unlock(&vm->mutex);
    return Finish(r, r->nativeReturn ? VZ_KERNEL_NATIVE_ERROR : VZ_KERNEL_OK);
}

VZKernelStatus VZKernelVMFree(VZKernelVM *vm) {
    if (!vm) return VZ_KERNEL_BAD_ARGUMENT;
    if (vm->ops.currentThread(vm->ops.context) != vm->owner) return VZ_KERNEL_WRONG_THREAD;
    Lock(&vm->mutex);
    bool busy = vm->live || vm->activeCPU || vm->cpuHandles;
    Unlock(&vm->mutex);
    if (busy) return VZ_KERNEL_BUSY;
    Lock(&RegistryMutex);
    if (RegisteredVM != vm) { Unlock(&RegistryMutex); return VZ_KERNEL_BAD_ARGUMENT; }
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
    uint64_t thread = vm->ops.currentThread(vm->ops.context);
    if (!thread) return Finish(r, VZ_KERNEL_WRONG_THREAD);
    if (OwnedCPU) return Finish(r, VZ_KERNEL_BUSY);
    VZKernelCPU *cpu = calloc(1, sizeof(*cpu));
    if (!cpu) return Finish(r, VZ_KERNEL_OUT_OF_MEMORY);
    cpu->vm = vm; cpu->owner = thread;
    Lock(&vm->mutex);
    if (!vm->live || vm->activeCPU || vm->generation == UINT64_MAX) {
        bool live = vm->live; Unlock(&vm->mutex); free(cpu);
        return Finish(r, live ? VZ_KERNEL_BUSY : VZ_KERNEL_NOT_LIVE);
    }
    cpu->generation = ++vm->generation;
    vm->activeCPU = cpu; ++vm->cpuHandles;
    Unlock(&vm->mutex);
    OwnedCPU = cpu; // The real kernel and the private handle use this worker.
    NativeCPUCreate args = {0, 0};
    r->nativeInvoked = true;
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 6, &args);
    if (r->nativeReturn) {
        OwnedCPU = NULL; Lock(&vm->mutex);
        vm->activeCPU = NULL; --vm->cpuHandles; Unlock(&vm->mutex);
        free(cpu); return Finish(r, VZ_KERNEL_NATIVE_ERROR);
    }
    cpu->returnedSlot = args.requestedSlot;
    cpu->nativeContext = args.nativeContext;
    // Record real ownership BEFORE checking a read or version, preserving
    // a valid cleanup handle even if the returned context cannot be consumed.
    Lock(&vm->mutex); cpu->live = true; Unlock(&vm->mutex);
    *outCPU = cpu;
    return Version(cpu, r);
}

VZKernelStatus VZKernelCPUContextVersion(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        return Finish(r, VZ_KERNEL_WRONG_THREAD);
    CPUResult(cpu, r);
    if (!cpu->live || OwnedCPU != cpu) return Finish(r, VZ_KERNEL_NOT_LIVE);
    return Version(cpu, r);
}

static bool NativeFieldRead(VZKernelCPU *cpu, uint32_t offset, uint32_t bytes,
    void *out, VZKernelNativeReadDiagnostics *d) {
    ++d->attemptedReads;
    if (!bytes || bytes > 16 || cpu->nativeContext > UINTPTR_MAX - offset - bytes)
        return false;
    return cpu->vm->ops.readMemory(cpu->vm->ops.context,
        (const void *)(cpu->nativeContext + offset), bytes, out);
}

VZKernelStatus VZKernelCPUReadNativeFields(VZKernelCPU *cpu, VZKernelNativeSnapshot *out,
    VZKernelNativeReadDiagnostics *d, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !out || !d || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    memset(d, 0, sizeof(*d)); d->failedFieldIndex = UINT32_MAX;
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        return Finish(r, VZ_KERNEL_WRONG_THREAD);
    CPUResult(cpu, r);
    if (!cpu->live || OwnedCPU != cpu) return Finish(r, VZ_KERNEL_NOT_LIVE);
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

VZKernelStatus VZKernelCPUDestroy(VZKernelCPU *cpu, VZKernelLifecycleResult *r) {
    Start(r);
    if (!cpu || !r) return Finish(r, VZ_KERNEL_BAD_ARGUMENT);
    VZKernelVM *vm = cpu->vm;
    if (vm->ops.currentThread(vm->ops.context) != cpu->owner)
        return Finish(r, VZ_KERNEL_WRONG_THREAD);
    CPUResult(cpu, r);
    if (!cpu->live || OwnedCPU != cpu) return Finish(r, VZ_KERNEL_NOT_LIVE);
    // A trusted read/write callback may reenter; it must not invalidate the
    // owned context while an initialization slice is using it.
    if (cpu->initializationInProgress) return Finish(r, VZ_KERNEL_BUSY);
    r->nativeInvoked = true;
    // Original old native destroy is op7 with NULL, CURRENT owner; the ID
    // selects a userspace table slot only. Never send a fabricated ID struct.
    r->nativeReturn = vm->ops.nativeTrap(vm->ops.context, 7, NULL);
    if (!r->nativeReturn) {
        Lock(&vm->mutex); cpu->live = false; cpu->nativeContext = 0;
        vm->activeCPU = NULL; Unlock(&vm->mutex);
        OwnedCPU = NULL;
    }
    CPUResult(cpu, r);
    return Finish(r, r->nativeReturn ? VZ_KERNEL_NATIVE_ERROR : VZ_KERNEL_OK);
}

VZKernelStatus VZKernelCPUFree(VZKernelCPU *cpu) {
    if (!cpu) return VZ_KERNEL_BAD_ARGUMENT;
    VZKernelVM *vm = cpu->vm;
    if (vm->ops.currentThread(vm->ops.context) != cpu->owner) return VZ_KERNEL_WRONG_THREAD;
    if (cpu->live || OwnedCPU == cpu) return VZ_KERNEL_BUSY;
    Lock(&vm->mutex);
    if (!vm->cpuHandles) { Unlock(&vm->mutex); return VZ_KERNEL_BAD_ARGUMENT; }
    --vm->cpuHandles; Unlock(&vm->mutex); free(cpu);
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
    if (!cpu->live || OwnedCPU != cpu || !cpu->initializationInProgress ||
        cpu->vm->activeCPU != cpu) {
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
    VZKernelStatus status = VZ_KERNEL_OK;
    if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        status = VZ_KERNEL_WRONG_THREAD;
    else if (!cpu->live || OwnedCPU != cpu || cpu->vm->activeCPU != cpu)
        status = VZ_KERNEL_NOT_LIVE;
    else if (q->expectedOwnerThread != cpu->owner ||
        q->expectedCPUGeneration != cpu->generation ||
        q->expectedReturnedSlotWord != cpu->returnedSlot)
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (q->schemaVersion != 1 ||
        q->validatedKernelProfile != cpu->vm->ops.validatedKernelProfile ||
        q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->nativeHVISA != cpu->vm->nativeHVISA ||
        q->nativeHVISA != VZ_KERNEL_NATIVE_HV_ISA_1)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (q->operation < VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY ||
        q->operation > VZ_KERNEL_INIT_CONTROL)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (cpu->initializationInProgress || cpu->mutationPoisoned)
        status = VZ_KERNEL_BUSY;
    else if (q->operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY ?
        cpu->creationPolicySliceComplete : !cpu->creationPolicySliceComplete)
        status = VZ_KERNEL_BUSY;
    if (status != VZ_KERNEL_OK) goto finish;
    status = Version(cpu, r);
    if (status != VZ_KERNEL_OK) goto finish;
    cpu->initializationInProgress = true;
    InitializationAccess opaque = {cpu, writer, r, VZ_KERNEL_OK};
    VZKernelInitAccess access = {&opaque, InitializationRead, InitializationWrite};
    status = VZKernelInitApplyVerifiedSlice(q, &access, receipt);
    if (opaque.boundaryStatus != VZ_KERNEL_OK) status = opaque.boundaryStatus;
    if (status == VZ_KERNEL_OK && q->operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY)
        cpu->creationPolicySliceComplete = true;
    // A false writer may already have partially written. Never claim that
    // failedWriteOrdinal/completedWrites prove exact restoration or no change.
    if (status != VZ_KERNEL_OK && receipt->attemptedWrites) cpu->mutationPoisoned = true;
    cpu->initializationInProgress = false;
finish:
    CPUResult(cpu, r);
    receipt->status = status;
    receipt->creationPolicySliceComplete = cpu->creationPolicySliceComplete;
    receipt->mutationPoisoned = cpu->mutationPoisoned;
    receipt->cpuCleanupRequired = cpu->live;
    receipt->architecturalResetComplete = false;
    receipt->runAllowed = false;
    return Finish(r, status);
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
    VZKernelStatus status = VZKernelSysLookup(q->identifier, &receipt->descriptor);
    if (status != VZ_KERNEL_OK) goto finish;
    if (q->action != VZ_KERNEL_SYS_READ && q->action != VZ_KERNEL_SYS_WRITE)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (q->action == VZ_KERNEL_SYS_WRITE &&
        receipt->descriptor.domain != VZ_KERNEL_SYS_REQUESTED_FEATURE_CACHE &&
        (!writer || !writer->writeMemory))
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (cpu->vm->ops.currentThread(cpu->vm->ops.context) != cpu->owner)
        status = VZ_KERNEL_WRONG_THREAD;
    else if (!cpu->live || OwnedCPU != cpu || cpu->vm->activeCPU != cpu)
        status = VZ_KERNEL_NOT_LIVE;
    else if (q->expectedOwnerThread != cpu->owner || q->expectedCPUGeneration != cpu->generation ||
        q->expectedReturnedSlotWord != cpu->returnedSlot)
        status = VZ_KERNEL_BAD_ARGUMENT;
    else if (q->schemaVersion != 1 || q->validatedKernelProfile != cpu->vm->ops.validatedKernelProfile ||
        q->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 ||
        q->nativeHVISA != cpu->vm->nativeHVISA || q->nativeHVISA != VZ_KERNEL_NATIVE_HV_ISA_1)
        status = VZ_KERNEL_UNSUPPORTED;
    else if (cpu->initializationInProgress || cpu->mutationPoisoned || !cpu->creationPolicySliceComplete)
        status = VZ_KERNEL_BUSY;
    if (status != VZ_KERNEL_OK) goto finish;
    status = Version(cpu, r);
    if (status != VZ_KERNEL_OK) goto finish;
    cpu->initializationInProgress = true;
    InitializationAccess opaque = {cpu, writer, r, VZ_KERNEL_OK};
    VZKernelInitAccess access = {&opaque, InitializationRead, InitializationWrite};
    uint64_t stagedOutput = 0;
    status = VZKernelSysApplyVerifiedRoute(q, &access, &cpu->requestedFeatures, &stagedOutput, receipt);
    if (status == VZ_KERNEL_OK && !InitializationOwned(&opaque)) status = opaque.boundaryStatus;
    if (opaque.boundaryStatus != VZ_KERNEL_OK) status = opaque.boundaryStatus;
    if (status != VZ_KERNEL_OK && (receipt->attemptedNativeWrites || receipt->privateFeatureWrites))
        cpu->mutationPoisoned = true;
    cpu->initializationInProgress = false;
    if (status == VZ_KERNEL_OK && q->action == VZ_KERNEL_SYS_READ) *readOutput = stagedOutput;
finish:
    CPUResult(cpu, r);
    receipt->status = status;
    receipt->mutationPoisoned = cpu->mutationPoisoned;
    receipt->cpuCleanupRequired = cpu->live;
    receipt->nativeOp8Invoked = false;
    receipt->completeModernSYSContract = false;
    receipt->runAllowed = false;
    return Finish(r, status);
}
