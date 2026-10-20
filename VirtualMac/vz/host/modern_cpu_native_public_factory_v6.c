#include "modern_cpu_native_public_factory_v2.h"
#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include "modern_cpu_config_os_object_v4_private.h"
#include "modern_cpu_native_public_factory_v3.h"
#include "modern_cpu_native_public_factory_v6.h"
#include "modern_cpu_kernel_lifecycle_v9_private.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

_Static_assert(sizeof(void *) == 8, "LP64 only");
_Static_assert(sizeof(VM27CPUFactoryExitV2) == 32, "Actual public exit storage");
_Static_assert(offsetof(VM27CPUFactoryExitV2, reason) == 0, "Public reason");
_Static_assert(offsetof(VM27CPUFactoryExitV2, syndrome) == 8, "Public syndrome");
_Static_assert(offsetof(VM27CPUFactoryExitV2, virtualAddress) == 16, "Public VA");
_Static_assert(offsetof(VM27CPUFactoryExitV2, physicalAddress) == 24, "Public IPA");

typedef struct Entry {
    struct Entry *next;
    VM27CPUFactoryVMV2 *vm;
    VZKernelCPU *cpu;
    VM27CPUFactoryExitV2 *exitStorage;
    VM27CPUFactoryIDV2 identity;
    uint64_t generation, nativeOwnerThread, returnedSlotWord;
    VM27CPUConfigBorrowV3 *configBorrow;
    VZKernelCreationConfigV6 config;
    VZKernelInitReceipt creationReceipt;
    bool configComplete;
    pthread_t owner;
    bool live, complete, published, draining;
    bool exitRecordValid;
    unsigned borrowCount;
    VM27CPUFactoryBorrowV2 *borrows;
    _Atomic bool operation;
} Entry;
struct VM27CPUFactoryVMV2 {
    VZKernelVM *kernel;
    uint64_t epoch;
    VZKernelInitWriter writer;
    uint32_t profile, nativeISA;
    pthread_t owner;
    bool live;
    Entry *entries;
    VM27CPUFactoryRAMV5 *ramRegistry;
    _Atomic bool operation;
};
struct VM27CPUFactoryBorrowV2 {
    VM27CPUFactoryBorrowV2 *next;
    Entry *entry;
    VZKernelCPUBorrowV5 *kernel;
    uint64_t epoch, generation;
    pthread_t borrower;
    _Atomic bool operation;
};
struct VM27CPUFactoryRAMV5 {
 VM27CPUFactoryRAMV5 *next;
 VM27CPUFactoryVMV2 *vm;
 VZKernelRAMV9 *kernel;
 void *host;
 uint64_t epoch, bytes;
};
static pthread_mutex_t Registry = PTHREAD_MUTEX_INITIALIZER;
static VM27CPUFactoryVMV2 *Registered;
static _Atomic bool Admission;
static _Thread_local Entry *Owned;
static void Lock(void) { if (pthread_mutex_lock(&Registry)) abort(); }
static void Unlock(void) { if (pthread_mutex_unlock(&Registry)) abort(); }
static bool Begin(_Atomic bool *flag) {
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(flag, &expected, true,
        memory_order_acquire, memory_order_relaxed);
}
static void End(_Atomic bool *flag) { atomic_store_explicit(flag, false, memory_order_release); }
static VM27CPUFactoryMachStatusV2 Mach(VZKernelStatus status) {
    // Explicit facade policy using actual SDK constants; never enum casting,
    // native status passthrough, errno interpretation or raw exit conversion.
    uint32_t bits;
    switch (status) {
    case VZ_KERNEL_OK: bits = 0; break;
    case VZ_KERNEL_BUSY: bits = 0xfae94002u; break;
    case VZ_KERNEL_BAD_ARGUMENT: case VZ_KERNEL_WRONG_THREAD: case VZ_KERNEL_NOT_LIVE:
        bits = 0xfae94003u; break;
    case VZ_KERNEL_OUT_OF_MEMORY: bits = 0xfae94005u; break;
    case VZ_KERNEL_UNSUPPORTED: bits = 0xfae9400fu; break;
    default: bits = 0xfae94001u; break;
    }
    int32_t result; memcpy(&result, &bits, sizeof(result)); return result;
}
static bool Disjoint(const void *a, size_t n, const void *b, size_t m) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!x || !y || n > UINTPTR_MAX - x || m > UINTPTR_MAX - y) return false;
    return x + n <= y || y + m <= x;
}
// Registry held; includes all retained exit allocations and own borrows.
static bool FactoryOutputLocked(const void *out, size_t bytes) {
    if (!out || bytes > UINTPTR_MAX - (uintptr_t)out) return false;
    if (!Registered) return true;
    if (!Disjoint(out, bytes, Registered, sizeof(*Registered))) return false;
    for(VM27CPUFactoryRAMV5 *r=Registered->ramRegistry;r;r=r->next)
        if(!Disjoint(out,bytes,r,sizeof(*r)) || !Disjoint(out,bytes,r->host,(size_t)r->bytes))return false;
    for (Entry *e = Registered->entries; e; e = e->next) {
        if (!Disjoint(out, bytes, e, sizeof(*e)) ||
            !Disjoint(out, bytes, e->exitStorage, sizeof(*e->exitStorage))) return false;
        for (VM27CPUFactoryBorrowV2 *b = e->borrows; b; b = b->next)
            if (!Disjoint(out, bytes, b, sizeof(*b))) return false;
    }
    return VZKernelRAMOutputRangeDisjointV9(out,bytes);
}
__attribute__((visibility("hidden")))
bool VM27CPUFactoryOutputRangeDisjointV3(const void *out, size_t bytes) {
    Lock(); bool valid = FactoryOutputLocked(out,bytes); Unlock(); return valid;
}
static bool Output(const void *out, size_t bytes) {
    // Single nested direction: Factory Registry -> OS Registry. The OS's
    // inverse check acquires/releases Factory before acquiring OS, no cycle.
    return FactoryOutputLocked(out,bytes) && VM27CPUConfigOutputRangeDisjointV3(out,bytes);
}
static bool DiagnosticOutput(VM27CPUFactoryDiagnosticV2 *d) { return !d || Output(d, sizeof(*d)); }
static void Diagnose(VM27CPUFactoryDiagnosticV2 *out, VZKernelStatus status,
    const VZKernelLifecycleResult *native, VM27CPUFactoryVMV2 *vm, Entry *entry, bool destroy) {
    if (!out) return;
    VM27CPUFactoryDiagnosticV2 d = {0}; d.ownStatus = status;
    d.vmEpoch = vm ? vm->epoch : 0;
    if (entry) { d.exitRecordValid = entry->exitRecordValid; d.creationConfigComplete = d.nativeKeyPolicyApplied = entry->configComplete;
        d.creationReceipt = entry->creationReceipt; d.cpuGeneration = entry->generation; d.cleanupPending = entry->cpu != NULL;
        d.nativeCPUCreationComplete = entry->complete; }
    if (native) { d.nativeInvoked = native->nativeInvoked; d.nativeReturn = native->nativeReturn; }
    d.callerDestroyFailureIsFatal = destroy && status != VZ_KERNEL_OK;
    memcpy(out, &d, sizeof(d));
}
static bool Contains(Entry *entry) {
    if (!Registered || entry->vm != Registered) return false;
    for (Entry *e = Registered->entries; e; e = e->next) if (e == entry) return true;
    return false;
}
static bool ContainsBorrow(VM27CPUFactoryBorrowV2 *b) {
    if (!Contains(b->entry) || b->epoch != b->entry->vm->epoch ||
        b->generation != b->entry->generation) return false;
    for (VM27CPUFactoryBorrowV2 *q = b->entry->borrows; q; q = q->next) if (q == b) return true;
    return false;
}
// Compare opaque handles against live registry pointers before dereferencing.
// The registry lock prevents free until the per-object guard has been taken.
static VM27CPUFactoryBorrowV2 *FindBorrowLocked(VM27CPUFactoryBorrowV2 *needle) {
    if (!needle || !Registered) return NULL;
    for (Entry *entry = Registered->entries; entry; entry = entry->next)
        for (VM27CPUFactoryBorrowV2 *b = entry->borrows; b; b = b->next)
            if (b == needle) return b;
    return NULL;
}
static VZKernelStatus BeginVM(VM27CPUFactoryVMV2 *vm) {
    Lock();
    VZKernelStatus status = !vm || Registered != vm ? VZ_KERNEL_BAD_ARGUMENT :
        Begin(&vm->operation) ? VZ_KERNEL_OK : VZ_KERNEL_BUSY;
    Unlock(); return status;
}
static VZKernelStatus BeginBorrow(VM27CPUFactoryBorrowV2 *borrow) {
    Lock(); VM27CPUFactoryBorrowV2 *live = FindBorrowLocked(borrow);
    VZKernelStatus status = !live ? VZ_KERNEL_BAD_ARGUMENT :
        Begin(&live->operation) ? VZ_KERNEL_OK : VZ_KERNEL_BUSY;
    Unlock(); return status;
}
static void Remove(Entry *entry) {
    Entry **link = &entry->vm->entries;
    while (*link && *link != entry) link = &(*link)->next;
    if (!*link || entry->borrowCount || entry->borrows || entry->cpu) abort();
    *link = entry->next;
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMCreateV2(const VZKernelLifecycleOps *ops,
    const VZKernelVMOptions *options, const VZKernelInitWriter *writer, VM27CPUFactoryVMV2 **out,
    VM27CPUFactoryDiagnosticV2 *diagnostic) {
    Lock(); bool valid = ops && writer && writer->writeMemory && writer->context == ops->context &&
        Output(out, sizeof(*out)) && DiagnosticOutput(diagnostic) &&
        (!diagnostic || Disjoint(out, sizeof(*out), diagnostic, sizeof(*diagnostic))); Unlock();
    if (!valid) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&Admission)) return Mach(VZ_KERNEL_BUSY);
    Lock(); bool busy = Registered != NULL; Unlock();
    if (busy) { End(&Admission); Diagnose(diagnostic, VZ_KERNEL_BUSY, NULL, NULL, NULL, false); return Mach(VZ_KERNEL_BUSY); }
    VM27CPUFactoryVMV2 *vm = calloc(1, sizeof(*vm));
    if (!vm) { End(&Admission); Diagnose(diagnostic, VZ_KERNEL_OUT_OF_MEMORY, NULL, NULL, NULL, false); return Mach(VZ_KERNEL_OUT_OF_MEMORY); }
    VZKernelLifecycleOps stagedOps = *ops; VZKernelVMOptions stagedOptions = options ? *options : (VZKernelVMOptions){0};
    atomic_init(&vm->operation, true); vm->owner = pthread_self();
    vm->writer = *writer; vm->profile = stagedOps.validatedKernelProfile; vm->nativeISA = stagedOptions.nativeHVISA;
    Lock(); Registered = vm; Unlock();
    VZKernelLifecycleResult r = {0};
    VZKernelStatus status = VZKernelVMCreate(&stagedOps, &stagedOptions, &vm->kernel, &r);
    if (status == VZ_KERNEL_OK) { vm->epoch = r.generation; vm->live = true; *out = vm;
        Diagnose(diagnostic, status, &r, vm, NULL, false); End(&vm->operation); }
    else { Lock(); Registered = NULL; Unlock(); free(vm); Diagnose(diagnostic, status, &r, NULL, NULL, false); }
    End(&Admission); return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMDestroyV2(VM27CPUFactoryVMV2 *vm,
    VM27CPUFactoryDiagnosticV2 *diagnostic) {
    VZKernelStatus admitted = BeginVM(vm);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    Lock(); bool valid = Registered == vm && DiagnosticOutput(diagnostic);
    bool busy = vm->entries != NULL || vm->ramRegistry != NULL; Unlock();
    if (!valid) { End(&vm->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    VZKernelStatus status = !pthread_equal(pthread_self(), vm->owner) ? VZ_KERNEL_WRONG_THREAD :
        busy ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    VZKernelLifecycleResult r = {0};
    if (status == VZ_KERNEL_OK) { status = VZKernelVMDestroy(vm->kernel, &r); if (status == VZ_KERNEL_OK) vm->live = false; }
    Diagnose(diagnostic, status, &r, vm, NULL, false); End(&vm->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryVMFreeV2(VM27CPUFactoryVMV2 *vm) {
    VZKernelStatus admitted = BeginVM(vm);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    Lock(); bool registered = Registered == vm, busy = vm->live || vm->entries != NULL || vm->ramRegistry != NULL; Unlock();
    VZKernelStatus status = !registered ? VZ_KERNEL_BAD_ARGUMENT :
        !pthread_equal(pthread_self(), vm->owner) ? VZ_KERNEL_WRONG_THREAD : busy ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    if (status == VZ_KERNEL_OK) status = VZKernelVMFree(vm->kernel);
    if (status == VZ_KERNEL_OK) { Lock(); Registered = NULL; Unlock(); free(vm); }
    else End(&vm->operation);
    return Mach(status);
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryCreateV2(VM27CPUFactoryVMV2 *vm,
    VM27CPUFactoryIDV2 *outID, VM27CPUFactoryExitV2 **outExit,
    VM27CPUFactoryForeignConfigV2 config, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    VZKernelStatus admitted = BeginVM(vm);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    Lock(); bool valid = Registered == vm && Output(outID, sizeof(*outID)) &&
        Output(outExit, sizeof(*outExit)) && DiagnosticOutput(diagnostic) &&
        Disjoint(outID, sizeof(*outID), outExit, sizeof(*outExit)) &&
        (!diagnostic || (Disjoint(diagnostic, sizeof(*diagnostic), outID, sizeof(*outID)) &&
        Disjoint(diagnostic, sizeof(*diagnostic), outExit, sizeof(*outExit))));
    bool live = vm->live; Unlock();
    if (!valid) { End(&vm->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    VZKernelStatus status = !live ? VZ_KERNEL_NOT_LIVE : Owned ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    if (status != VZ_KERNEL_OK) { Diagnose(diagnostic, status, NULL, vm, NULL, false); End(&vm->operation); return Mach(status); }
    const void *defaultConfig = NULL;
    if (!config) { defaultConfig = VM27CPUConfigCreateObjectV3(); config = defaultConfig; }
    VM27CPUConfigBorrowV3 *configBorrow = NULL; VM27CPUConfigSnapshotV3 snapshot = {0};
    int32_t cfgStatus = config ? VM27CPUConfigBorrowObjectV3(config,&configBorrow) : VM27_CPU_CONFIG_ERROR_V3;
    if (!cfgStatus) cfgStatus = VM27CPUConfigReadBorrowV3(configBorrow,&snapshot);
    if (defaultConfig) CFRelease((CFTypeRef)defaultConfig);
    if (cfgStatus) {
        if (configBorrow) (void)VM27CPUConfigReleaseBorrowV3(configBorrow);
        status = cfgStatus == VM27_CPU_CONFIG_BUSY_V3 ? VZ_KERNEL_BUSY :
            cfgStatus == VM27_CPU_CONFIG_BAD_ARGUMENT_V3 ? VZ_KERNEL_BAD_ARGUMENT : VZ_KERNEL_NATIVE_ERROR;
        Diagnose(diagnostic,status,NULL,vm,NULL,false); End(&vm->operation); return Mach(status);
    }
    Entry *entry = calloc(1, sizeof(*entry));
    if (entry) entry->exitStorage = calloc(1, sizeof(*entry->exitStorage));
    if (!entry || !entry->exitStorage) { free(entry); (void)VM27CPUConfigReleaseBorrowV3(configBorrow); Diagnose(diagnostic, VZ_KERNEL_OUT_OF_MEMORY, NULL, vm, NULL, false);
        End(&vm->operation); return Mach(VZ_KERNEL_OUT_OF_MEMORY); }
    entry->configBorrow = configBorrow;
    entry->config = (VZKernelCreationConfigV6){1,snapshot.fineGrainedTraps,snapshot.trapTLBISW,
        snapshot.supportKnown,snapshot.supportKnown,
        snapshot.vmKeyLow,snapshot.vmKeyHigh,snapshot.generation};
    entry->vm = vm; entry->owner = pthread_self(); atomic_init(&entry->operation, true);
    Lock(); entry->next = vm->entries; vm->entries = entry; Unlock(); Owned = entry;
    VZKernelLifecycleResult r = {0}; status = VZKernelCPUCreate(vm->kernel, &entry->cpu, &r);
    VM27CPUFactoryIDV2 identity = 0;
    if (status == VZ_KERNEL_OK) {
        VZKernelLifecycleResult configured = {0};
        status = VZKernelCPUApplyCreationConfigV6(entry->cpu,&entry->config,&vm->writer,
            &entry->creationReceipt,&configured);
        entry->configComplete = status == VZ_KERNEL_OK;
        // Keep op6's actual native invocation/result; use the same handle's
        // populated creation metadata, without claiming a write callback is HV.
        r.ownerThread = configured.ownerThread; r.generation = configured.generation;
        r.returnedSlotWord = configured.returnedSlotWord;
    }
    if (VM27CPUConfigReleaseBorrowV3(entry->configBorrow) == 0) entry->configBorrow = NULL;
    else if (status == VZ_KERNEL_OK) status = VZ_KERNEL_NATIVE_ERROR;
    if (status == VZ_KERNEL_OK) status = VZKernelCPUPublishIdentityV5(entry->cpu, &identity);
    Lock(); entry->generation = r.generation; entry->nativeOwnerThread = r.ownerThread;
    entry->returnedSlotWord = r.returnedSlotWord; entry->live = r.cpuLive;
    entry->identity = identity; entry->complete = status == VZ_KERNEL_OK; Unlock();
    if (status == VZ_KERNEL_OK) {
        Lock(); entry->published = true; Unlock();
        *outID = entry->identity; memcpy(outExit,&entry->exitStorage,sizeof(entry->exitStorage));
        Diagnose(diagnostic, status, &r, vm, entry, false); End(&entry->operation);
    } else if (entry->cpu || entry->configBorrow) {
        // Native ownership survives failed version/publication. Never rollback
        // by freeing live CPU/exit memory or manufacturing public success.
        Lock(); entry->draining = true; Unlock();
        Diagnose(diagnostic, status, &r, vm, entry, false); End(&entry->operation);
    } else {
        Diagnose(diagnostic, status, &r, vm, NULL, false);
        Lock(); Remove(entry); Unlock(); Owned = NULL; free(entry->exitStorage); free(entry);
    }
    End(&vm->operation); return Mach(status);
}

// Entry guard held before any V5 currentThread/native callback. Registry is
// never held over a V5 call. On any failure entry/storage/TLS stay retained.
static VZKernelStatus DestroyEntry(Entry *entry, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    VM27CPUFactoryVMV2 *vm = entry->vm; VZKernelLifecycleResult r = {0};
    if (!pthread_equal(pthread_self(), entry->owner) || Owned != entry) {
        Diagnose(diagnostic, VZ_KERNEL_WRONG_THREAD, NULL, vm, entry, true); End(&entry->operation); return VZ_KERNEL_WRONG_THREAD;
    }
    Lock(); entry->published = false; entry->draining = true; entry->exitRecordValid = false; bool borrowed = entry->borrowCount != 0; Unlock();
    VZKernelStatus status = VZ_KERNEL_OK;
    if (entry->identity && entry->live) status = VZKernelCPUUnpublishIdentityV5(entry->cpu);
    if (status == VZ_KERNEL_OK && borrowed) status = VZ_KERNEL_BUSY;
    if (status == VZ_KERNEL_OK && entry->live) {
        status = VZKernelCPUDestroy(entry->cpu, &r); if (status == VZ_KERNEL_OK) entry->live = false;
    }
    if (status == VZ_KERNEL_OK && entry->configBorrow) {
        if (VM27CPUConfigReleaseBorrowV3(entry->configBorrow) == 0) entry->configBorrow = NULL;
        else status = VZ_KERNEL_NATIVE_ERROR;
    }
    if (status == VZ_KERNEL_OK && entry->cpu) status = VZKernelCPUFree(entry->cpu);
    if (status == VZ_KERNEL_OK) {
        entry->cpu = NULL; Diagnose(diagnostic, status, &r, vm, entry, true);
        Lock(); Remove(entry); Unlock(); Owned = NULL;
        memset(entry->exitStorage, 0, sizeof(*entry->exitStorage)); free(entry->exitStorage);
        memset(&entry->config,0,sizeof(entry->config)); free(entry);
    } else { Diagnose(diagnostic, status, &r, vm, entry, true); End(&entry->operation); }
    return status;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryDestroyV2(VM27CPUFactoryIDV2 identity,
    VM27CPUFactoryDiagnosticV2 *diagnostic) {
    Lock(); Entry *entry = NULL;
    if (identity && Registered && DiagnosticOutput(diagnostic))
        for (Entry *q = Registered->entries; q; q = q->next)
            if (q->published && q->identity == identity) { entry = q; break; }
    bool begun = entry && Begin(&entry->operation); Unlock();
    if (!entry) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!begun) return Mach(VZ_KERNEL_BUSY);
    return Mach(DestroyEntry(entry, diagnostic));
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryOwnerCleanupV2(VM27CPUFactoryVMV2 *vm,
    VM27CPUFactoryDiagnosticV2 *diagnostic) {
    Lock(); Entry *entry = Owned;
    bool valid = vm && Registered == vm && entry && Contains(entry) && entry->vm == vm && DiagnosticOutput(diagnostic);
    bool begun = valid && Begin(&entry->operation); Unlock();
    if (!valid) return Mach(VZ_KERNEL_NOT_LIVE);
    if (!begun) return Mach(VZ_KERNEL_BUSY);
    return Mach(DestroyEntry(entry, diagnostic));
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAcquireV2(VM27CPUFactoryIDV2 identity,
    VM27CPUFactoryBorrowV2 **out) {
    Lock(); Entry *entry = NULL;
    bool output = Output(out, sizeof(*out));
    if (identity && Registered && output)
        for (Entry *e = Registered->entries; e; e = e->next)
            if (e->identity == identity && e->published && !e->draining && e->complete) { entry = e; break; }
    if (!entry) { Unlock(); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!Begin(&entry->operation)) { Unlock(); return Mach(VZ_KERNEL_BUSY); }
    if (entry->borrowCount == UINT_MAX) { End(&entry->operation); Unlock(); return Mach(VZ_KERNEL_BUSY); }
    Unlock();
    VM27CPUFactoryBorrowV2 *borrow = calloc(1, sizeof(*borrow));
    VZKernelStatus status = borrow ? VZ_KERNEL_OK : VZ_KERNEL_OUT_OF_MEMORY;
    if (status == VZ_KERNEL_OK) status = VZKernelCPUBorrowIdentityV5(identity, &borrow->kernel);
    if (status == VZ_KERNEL_OK) {
        borrow->entry = entry; borrow->epoch = entry->vm->epoch; borrow->generation = entry->generation;
        borrow->borrower = pthread_self(); atomic_init(&borrow->operation, false);
        Lock(); borrow->next = entry->borrows; entry->borrows = borrow; ++entry->borrowCount; Unlock(); *out = borrow;
    } else free(borrow);
    End(&entry->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowViewV2(VM27CPUFactoryBorrowV2 *borrow,
    VM27CPUFactoryViewV2 *out) {
    if (!out) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    VZKernelStatus admitted = BeginBorrow(borrow);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    if (!pthread_equal(pthread_self(), borrow->borrower)) { End(&borrow->operation); return Mach(VZ_KERNEL_WRONG_THREAD); }
    Lock(); bool valid = ContainsBorrow(borrow) && Output(out, sizeof(*out));
    Entry *entry = valid ? borrow->entry : NULL;
    bool begun = entry && Begin(&entry->operation); Unlock();
    if (!valid) { End(&borrow->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!begun) { End(&borrow->operation); return Mach(VZ_KERNEL_BUSY); }
    VZKernelCPU *cpu = NULL;
    VZKernelStatus status = entry->draining ? VZ_KERNEL_NOT_LIVE : VZKernelCPUBorrowHandleV5(borrow->kernel, &cpu);
    if (status == VZ_KERNEL_OK && cpu != entry->cpu) status = VZ_KERNEL_NOT_LIVE;
    if (status == VZ_KERNEL_OK) { VM27CPUFactoryViewV2 view = {entry->identity, borrow->epoch,
        borrow->generation, entry->exitStorage, entry->exitRecordValid}; memcpy(out, &view, sizeof(view)); }
    End(&entry->operation); End(&borrow->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowReleaseV2(VM27CPUFactoryBorrowV2 *borrow) {
    VZKernelStatus admitted = BeginBorrow(borrow);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    if (!pthread_equal(pthread_self(), borrow->borrower)) { End(&borrow->operation); return Mach(VZ_KERNEL_WRONG_THREAD); }
    Lock(); bool valid = ContainsBorrow(borrow); Unlock();
    if (!valid) { End(&borrow->operation); return Mach(VZ_KERNEL_NOT_LIVE); }
    VZKernelStatus status = VZKernelCPUReleaseBorrowV5(borrow->kernel);
    if (status != VZ_KERNEL_OK) { End(&borrow->operation); return Mach(status); }
    Lock(); Entry *entry = borrow->entry; VM27CPUFactoryBorrowV2 **link = &entry->borrows;
    while (*link && *link != borrow) link = &(*link)->next;
    if (!*link || !entry->borrowCount) abort();
    *link = borrow->next; --entry->borrowCount; Unlock(); memset(borrow, 0, sizeof(*borrow)); free(borrow); return 0;
}

static VM27CPUFactoryMachStatusV2 BorrowApplyV6(VM27CPUFactoryBorrowV2 *borrow,
    VZKernelInitOperation operation, uint32_t identifier, uint64_t low, uint64_t high,
    const VZKernelInitWriter *writer, VZKernelInitReceipt *receipt,
    VM27CPUFactoryDiagnosticV2 *diagnostic,bool boundWriter) {
    if ((!boundWriter && !writer) || !receipt) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    VZKernelStatus admitted = BeginBorrow(borrow);
    if (admitted != VZ_KERNEL_OK) return Mach(admitted);
    if (!pthread_equal(pthread_self(),borrow->borrower)) { End(&borrow->operation); return Mach(VZ_KERNEL_WRONG_THREAD); }
    Lock(); bool valid = ContainsBorrow(borrow) && Output(receipt,sizeof(*receipt)) &&
        DiagnosticOutput(diagnostic) && (!diagnostic || Disjoint(receipt,sizeof(*receipt),diagnostic,sizeof(*diagnostic)));
    Entry *entry = valid ? borrow->entry : NULL; bool begun = entry && Begin(&entry->operation); Unlock();
    if (!valid) { End(&borrow->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!begun) { End(&borrow->operation); return Mach(VZ_KERNEL_BUSY); }
    VZKernelCPU *cpu = NULL; VZKernelLifecycleResult lifecycle = {0};
    VZKernelStatus status = entry->draining || !entry->configComplete ? VZ_KERNEL_NOT_LIVE :
        VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
    if (status == VZ_KERNEL_OK && (cpu != entry->cpu ||
        (!boundWriter && (writer->context != entry->vm->writer.context || writer->writeMemory != entry->vm->writer.writeMemory))))
        status = VZ_KERNEL_BAD_ARGUMENT;
    if (status == VZ_KERNEL_OK && operation != VZ_KERNEL_INIT_SCALAR && operation != VZ_KERNEL_INIT_SIMD &&
        operation != VZ_KERNEL_INIT_CONTROL) status = VZ_KERNEL_UNSUPPORTED;
    if (status == VZ_KERNEL_OK) {
        entry->exitRecordValid = false;
        VZKernelInitRequest request = {1,entry->vm->profile,entry->nativeOwnerThread,
            entry->generation,entry->returnedSlotWord,entry->vm->nativeISA,
            operation,identifier,low,high};
        status = VZKernelCPUApplyInitialization(cpu,&request,&entry->vm->writer,receipt,&lifecycle);
        if (status != VZ_KERNEL_OK && receipt->mutationPoisoned && receipt->attemptedWrites) {
            Lock(); entry->published = false; entry->draining = true; Unlock();
            // Current borrow still retains CPU/storage. OwnerCleanup can retry
            // destroy; no further ID lookup or register publication succeeds.
            (void)VZKernelCPUUnpublishIdentityV5(entry->cpu);
        }
    }
    Diagnose(diagnostic,status,&lifecycle,entry->vm,entry,false);
    End(&entry->operation); End(&borrow->operation); return Mach(status);
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowApplyV2(VM27CPUFactoryBorrowV2 *b,
 VZKernelInitOperation operation,uint32_t identifier,uint64_t low,uint64_t high,
 const VZKernelInitWriter *writer,VZKernelInitReceipt *receipt,VM27CPUFactoryDiagnosticV2 *diagnostic) {
 return BorrowApplyV6(b,operation,identifier,low,high,writer,receipt,diagnostic,false);
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryRunOwnedStepV3(VM27CPUFactoryBorrowV2 *borrow,
    VM27CPUFactoryRunDiagnosticV3 *out) {
    VZKernelStatus admitted=BeginBorrow(borrow);
    if (admitted!=VZ_KERNEL_OK) return Mach(admitted);
    if (!pthread_equal(pthread_self(),borrow->borrower)) {
        End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);
    }
    Lock();bool valid=ContainsBorrow(borrow) && (!out || Output(out,sizeof(*out)));
    Entry *entry=valid ? borrow->entry : NULL;bool begun=entry && Begin(&entry->operation);Unlock();
    if (!valid) { End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!begun) { End(&borrow->operation);return Mach(VZ_KERNEL_BUSY); }
    VM27CPUFactoryRunDiagnosticV3 diagnostic={0};VZKernelCPU *cpu=NULL;
    VZKernelStatus status=entry->draining || !entry->configComplete ? VZ_KERNEL_NOT_LIVE :
        VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
    if (status==VZ_KERNEL_OK && cpu!=entry->cpu) status=VZ_KERNEL_NOT_LIVE;
    if (status==VZ_KERNEL_OK) {
        entry->exitRecordValid=false;
        status=VZKernelCPURunOwnedStepV7(cpu,&diagnostic.step);
        VZKernelRunStepReceiptV7 *step=&diagnostic.step;
        if (status==VZ_KERNEL_OK && (!step->lifecycle.nativeInvoked || step->lifecycle.nativeReturn ||
            !step->postReturnIdentityValidated || !step->runToken ||
            step->vmEpoch!=entry->vm->epoch || step->cpuGeneration!=entry->generation ||
            step->ownerThread!=entry->nativeOwnerThread || !step->reductionValid ||
            !step->publicExceptionProduced || step->reduction.hasPublicException!=1 ||
            step->reduction.kind!=VZ_CPU_EXIT_DECODED_EXCEPTION_V1)) status=VZ_KERNEL_NOT_LIVE;
        if (status==VZ_KERNEL_OK) {
            // Same allocation returned at Create, still retained by this real
            // borrow/entry. The token was privately created by actual call9;
            // no caller-supplied value can manufacture this publication.
            memcpy(entry->exitStorage,&step->reduction.exception,sizeof(*entry->exitStorage));
            entry->exitRecordValid=true;diagnostic.exitStoragePublished=true;
        }
    }
    Diagnose(&diagnostic.factory,status,&diagnostic.step.lifecycle,entry->vm,entry,false);
    if (out) *out=diagnostic;
    End(&entry->operation);End(&borrow->operation);return Mach(status);
}

VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessSystemV4(VM27CPUFactoryBorrowV2 *borrow,
    VZKernelSysAction action,uint32_t identifier,uint64_t value,uint64_t *readOutput,
    VZKernelSysReceipt *outReceipt,VM27CPUFactoryDiagnosticV2 *outDiagnostic) {
    if(!outReceipt || (action==VZ_KERNEL_SYS_READ && !readOutput))return Mach(VZ_KERNEL_BAD_ARGUMENT);
    VZKernelStatus admitted=BeginBorrow(borrow);
    if(admitted!=VZ_KERNEL_OK)return Mach(admitted);
    if(!pthread_equal(pthread_self(),borrow->borrower)) {
        End(&borrow->operation);return Mach(VZ_KERNEL_WRONG_THREAD);
    }
    Lock();
    bool valid=ContainsBorrow(borrow) && Output(outReceipt,sizeof(*outReceipt)) &&
        DiagnosticOutput(outDiagnostic) && (!readOutput || Output(readOutput,sizeof(*readOutput))) &&
        (!outDiagnostic || Disjoint(outReceipt,sizeof(*outReceipt),outDiagnostic,sizeof(*outDiagnostic))) &&
        (!readOutput || (Disjoint(readOutput,sizeof(*readOutput),outReceipt,sizeof(*outReceipt)) &&
            (!outDiagnostic || Disjoint(readOutput,sizeof(*readOutput),outDiagnostic,sizeof(*outDiagnostic)))));
    Entry *entry=valid?borrow->entry:NULL;bool begun=entry && Begin(&entry->operation);Unlock();
    if(!valid){End(&borrow->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
    if(!begun){End(&borrow->operation);return Mach(VZ_KERNEL_BUSY);}
    VZKernelCPU *cpu=NULL;VZKernelSysReceipt receipt={0};
    VZKernelLifecycleResult lifecycle={0};uint64_t output=0;
    VZKernelStatus status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:
        VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
    if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
    if(status==VZ_KERNEL_OK && action!=VZ_KERNEL_SYS_READ && action!=VZ_KERNEL_SYS_WRITE)
        status=VZ_KERNEL_UNSUPPORTED;
    if(status==VZ_KERNEL_OK) {
        entry->exitRecordValid=false;
        VZKernelSysRequest request={1,entry->vm->profile,entry->nativeOwnerThread,
            entry->generation,entry->returnedSlotWord,entry->vm->nativeISA,action,identifier,value};
        status=VZKernelCPUAccessSystemRegister(cpu,&request,&entry->vm->writer,
            action==VZ_KERNEL_SYS_READ?&output:NULL,&receipt,&lifecycle);
        if(status!=VZ_KERNEL_OK && receipt.mutationPoisoned &&
            (receipt.attemptedNativeWrites || receipt.privateFeatureWrites)) {
            Lock();entry->published=false;entry->draining=true;Unlock();
            (void)VZKernelCPUUnpublishIdentityV5(entry->cpu);
        }
    }
    receipt.status=status;
    if(status==VZ_KERNEL_OK && action==VZ_KERNEL_SYS_READ)*readOutput=output;
    *outReceipt=receipt;
    Diagnose(outDiagnostic,status,&lifecycle,entry->vm,entry,false);
    End(&entry->operation);End(&borrow->operation);return Mach(status);
}

// Registry ownership is the real factory's, not an independent VM map cache.
// Compare RAM handles before dereference and take the same VM operation guard
// before any lifecycle/currentThread/native callback. No callbacks under lock.
static VZKernelStatus RAMBeginV5(VM27CPUFactoryVMV2 *needleVM,VM27CPUFactoryRAMV5 *needleRAM,
 VM27CPUFactoryVMV2 **outVM,VM27CPUFactoryRAMV5 **outRAM) {
 Lock();VM27CPUFactoryVMV2 *vm=Registered;VM27CPUFactoryRAMV5 *ram=NULL;
 if(vm && needleRAM)for(VM27CPUFactoryRAMV5 *p=vm->ramRegistry;p;p=p->next)
  if(p==needleRAM){ram=p;break;}
 VZKernelStatus status=!vm || (needleVM && vm!=needleVM) || (needleRAM && !ram)?VZ_KERNEL_BAD_ARGUMENT:
  Begin(&vm->operation)?VZ_KERNEL_OK:VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK){*outVM=vm;*outRAM=ram;}
 Unlock();return status;
}
static VZKernelStatus RAMReadyV5(VM27CPUFactoryVMV2 *vm,VM27CPUFactoryRAMV5 *ram) {
 Lock();bool live=vm->live,CPUs=vm->entries!=NULL;
 bool identity=Registered==vm && (!ram || (ram->vm==vm && ram->epoch==vm->epoch));Unlock();
 return !identity || !live?VZ_KERNEL_NOT_LIVE:
  !pthread_equal(pthread_self(),vm->owner)?VZ_KERNEL_WRONG_THREAD:CPUs?VZ_KERNEL_BUSY:VZ_KERNEL_OK;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMCreateV5(VM27CPUFactoryVMV2 *needle,
 uint64_t bytes,VM27CPUFactoryRAMV5 **outRAM,void **outHost,VZKernelRAMResultV9 *out) {
 if(!needle)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *unused=NULL;
 VZKernelStatus status=RAMBeginV5(needle,NULL,&vm,&unused);if(status)return Mach(status);
 Lock();bool valid=Output(outRAM,sizeof(*outRAM)) && Output(outHost,sizeof(*outHost)) && Output(out,sizeof(*out)) &&
  Disjoint(outRAM,sizeof(*outRAM),outHost,sizeof(*outHost)) && Disjoint(out,sizeof(*out),outRAM,sizeof(*outRAM)) &&
  Disjoint(out,sizeof(*out),outHost,sizeof(*outHost));Unlock();
 if(!valid){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 status=RAMReadyV5(vm,NULL);VM27CPUFactoryRAMV5 *ram=NULL;VZKernelRAMResultV9 staged={0};
 if(status==VZ_KERNEL_OK) {
  ram=calloc(1,sizeof(*ram));if(!ram)status=VZ_KERNEL_OUT_OF_MEMORY;
 }
 if(status==VZ_KERNEL_OK)status=VZKernelRAMCreateV9(vm->kernel,bytes,&ram->kernel,&ram->host,&staged);
 if(status==VZ_KERNEL_OK) {
  ram->vm=vm;ram->epoch=vm->epoch;ram->bytes=bytes;
  Lock();ram->next=vm->ramRegistry;vm->ramRegistry=ram;Unlock();
  *outRAM=ram;*outHost=ram->host;
 }else{free(ram);ram=NULL;}
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
static VZKernelRAMResultV9 RAMSeedV5(VM27CPUFactoryVMV2 *vm,VM27CPUFactoryRAMV5 *ram) {
 VZKernelRAMResultV9 r={0};r.vmEpoch=vm->epoch;
 if(ram){r.bytes=ram->bytes;r.cleanupPending=true;}
 return r;
}
static VZKernelStatus RAMAdmitV5(VM27CPUFactoryRAMV5 *needle,VZKernelRAMResultV9 *out,
 VM27CPUFactoryVMV2 **vm,VM27CPUFactoryRAMV5 **ram) {
 if(!needle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus status=RAMBeginV5(NULL,needle,vm,ram);if(status)return status;
 Lock();bool valid=Output(out,sizeof(*out));Unlock();
 if(!valid){End(&(*vm)->operation);return VZ_KERNEL_BAD_ARGUMENT;}
 return VZ_KERNEL_OK;
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMWriteV5(VM27CPUFactoryRAMV5 *needle,
 uint64_t offset,const void *source,size_t bytes,VZKernelRAMResultV9 *out) {
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *ram=NULL;
 VZKernelStatus status=RAMAdmitV5(needle,out,&vm,&ram);if(status)return Mach(status);
 Lock();bool valid=Output(source,bytes) && Disjoint(source,bytes,out,sizeof(*out));Unlock();
 if(!valid || !bytes){End(&vm->operation);return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 status=RAMReadyV5(vm,ram);VZKernelRAMResultV9 staged=RAMSeedV5(vm,ram);
 if(status==VZ_KERNEL_OK)status=VZKernelRAMWriteV9(ram->kernel,offset,source,bytes,&staged);
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
static VM27CPUFactoryMachStatusV2 RAMNativeV5(VM27CPUFactoryRAMV5 *needle,VZKernelMemoryOperation operation,
 uint64_t guestAddress,uint64_t flags,VZKernelRAMResultV9 *out) {
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *ram=NULL;
 VZKernelStatus status=RAMAdmitV5(needle,out,&vm,&ram);if(status)return Mach(status);
 status=RAMReadyV5(vm,ram);VZKernelRAMResultV9 staged=RAMSeedV5(vm,ram);
 if(status==VZ_KERNEL_OK) {
  if(operation==VZKernelMemoryMap)status=VZKernelRAMMapV9(ram->kernel,guestAddress,flags,&staged);
  else if(operation==VZKernelMemoryProtect)status=VZKernelRAMProtectV9(ram->kernel,flags,&staged);
  else status=VZKernelRAMUnmapV9(ram->kernel,&staged);
 }
 staged.status=status;memcpy(out,&staged,sizeof(staged));End(&vm->operation);return Mach(status);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMMapV5(VM27CPUFactoryRAMV5 *r,uint64_t guestAddress,uint64_t flags,VZKernelRAMResultV9 *out) {
 return RAMNativeV5(r,VZKernelMemoryMap,guestAddress,flags,out);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMProtectV5(VM27CPUFactoryRAMV5 *r,uint64_t flags,VZKernelRAMResultV9 *out) {
 return RAMNativeV5(r,VZKernelMemoryProtect,0,flags,out);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMUnmapV5(VM27CPUFactoryRAMV5 *r,VZKernelRAMResultV9 *out) {
 return RAMNativeV5(r,VZKernelMemoryUnmap,0,0,out);
}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMFreeV5(VM27CPUFactoryRAMV5 *needle) {
 if(!needle)return Mach(VZ_KERNEL_BAD_ARGUMENT);
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryRAMV5 *ram=NULL;
 VZKernelStatus status=RAMBeginV5(NULL,needle,&vm,&ram);if(status)return Mach(status);
 status=RAMReadyV5(vm,ram);
 if(status==VZ_KERNEL_OK)status=VZKernelRAMFreeV9(ram->kernel);
 if(status==VZ_KERNEL_OK) {
  Lock();VM27CPUFactoryRAMV5 **link=&vm->ramRegistry;while(*link && *link!=ram)link=&(*link)->next;
  if(!*link)abort();*link=ram->next;Unlock();free(ram);
 }
 End(&vm->operation);return Mach(status);
}

_Static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_reg_t)==4 && sizeof(hv_sys_reg_t)==2,"Actual public ID/register ABI");
_Static_assert(sizeof(hv_simd_fp_uchar16_t)==16 && _Alignof(hv_simd_fp_uchar16_t)==16,"Actual public SIMD vector ABI");
_Static_assert(sizeof(hv_vcpu_exit_t)==32,"Actual persistent public exit bytes");
static _Thread_local bool PublicOperationV6;
static _Thread_local VM27CPUFactoryBorrowV2 *PublicDeferredBorrowV6;
static bool PublicBeginV6(void){if(PublicOperationV6 || PublicDeferredBorrowV6)return false;PublicOperationV6=true;return true;}
static void PublicEndV6(void){PublicOperationV6=false;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryPublicDrainBorrowV6(void) {
 if(PublicOperationV6)return Mach(VZ_KERNEL_BUSY);
 if(!PublicDeferredBorrowV6)return 0;
 PublicOperationV6=true;VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowReleaseV2(PublicDeferredBorrowV6);
 if(!status)PublicDeferredBorrowV6=NULL;PublicEndV6();return status;
}
static hv_return_t PublicReleaseV6(VM27CPUFactoryBorrowV2 *borrow,hv_return_t status) {
 hv_return_t release=VM27CPUFactoryBorrowReleaseV2(borrow);
 if(release){PublicDeferredBorrowV6=borrow;if(!status)status=release;}
 return status;
}
hv_vcpu_config_t hv_vcpu_config_create(void) {
 // SDK promises a non-null +1 OS object and gives no error-return channel.
 // Own config allocation is ordinary CF/ObjC only, no native callback/VM state.
 hv_vcpu_config_t result=(hv_vcpu_config_t)VM27CPUConfigCreateObjectV3();
 if(!result)abort();return result;
}
hv_return_t hv_vcpu_create(hv_vcpu_t *outCPU,hv_vcpu_exit_t **outExit,hv_vcpu_config_t config) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 Lock();VM27CPUFactoryVMV2 *vm=Registered;Unlock();
 // True public pointer shapes, no arithmetic cast from hv_vcpu_t to native slot.
 hv_return_t result=vm?VM27CPUFactoryCreateV2(vm,(VM27CPUFactoryIDV2 *)outCPU,
  (VM27CPUFactoryExitV2 **)outExit,(const void *)config,NULL):Mach(VZ_KERNEL_NOT_LIVE);
 PublicEndV6();return result;
}
hv_return_t hv_vcpu_destroy(hv_vcpu_t identifier) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 hv_return_t result=VM27CPUFactoryDestroyV2(identifier,NULL);PublicEndV6();return result;
}
static hv_return_t PublicSetV6(hv_vcpu_t identifier,VZKernelInitOperation operation,uint32_t reg,uint64_t low,uint64_t high) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 if((operation==VZ_KERNEL_INIT_SCALAR && reg>34) || (operation==VZ_KERNEL_INIT_SIMD && reg>31)) {
  PublicEndV6();return Mach(VZ_KERNEL_BAD_ARGUMENT);
 }
 VM27CPUFactoryBorrowV2 *borrow=NULL;hv_return_t status=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!status){VZKernelInitReceipt receipt={0};status=BorrowApplyV6(borrow,operation,reg,low,high,NULL,&receipt,NULL,true);
  status=PublicReleaseV6(borrow,status);}
 PublicEndV6();return status;
}
hv_return_t hv_vcpu_set_reg(hv_vcpu_t identifier,hv_reg_t reg,uint64_t value) {
 return PublicSetV6(identifier,VZ_KERNEL_INIT_SCALAR,(uint32_t)reg,value,0);
}
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t identifier,hv_simd_fp_reg_t reg,hv_simd_fp_uchar16_t value) {
 uint64_t words[2];memcpy(words,&value,16);
 return PublicSetV6(identifier,VZ_KERNEL_INIT_SIMD,(uint32_t)reg,words[0],words[1]);
}
static hv_return_t PublicGetV6(hv_vcpu_t identifier,VZKernelInitOperation operation,uint32_t reg,void *out,size_t bytes) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 if((operation==VZ_KERNEL_INIT_SCALAR && reg>34) || (operation==VZ_KERNEL_INIT_SIMD && reg>31)) {
  PublicEndV6();return Mach(VZ_KERNEL_BAD_ARGUMENT);
 }
 VZKernelRegisterValueV10 staged={0};bool publish=false;
 VM27CPUFactoryBorrowV2 *borrow=NULL;hv_return_t result=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!result) {
  VZKernelStatus status=BeginBorrow(borrow);
  if(status==VZ_KERNEL_OK) {
   Lock();bool valid=ContainsBorrow(borrow) && Output(out,bytes);Entry *entry=valid?borrow->entry:NULL;
   bool begun=entry && Begin(&entry->operation);Unlock();
   if(!valid)status=VZ_KERNEL_BAD_ARGUMENT;else if(!begun)status=VZ_KERNEL_BUSY;
   else {
    VZKernelCPU *cpu=NULL;VZKernelRegisterValueV10 value={0};VZKernelLifecycleResult lifecycle={0};
    status=entry->draining || !entry->configComplete?VZ_KERNEL_NOT_LIVE:VZKernelCPUBorrowHandleV5(borrow->kernel,&cpu);
    if(status==VZ_KERNEL_OK && cpu!=entry->cpu)status=VZ_KERNEL_NOT_LIVE;
    if(status==VZ_KERNEL_OK)status=VZKernelCPUReadRegisterV10(cpu,operation,reg,&value,&lifecycle);
    if(status==VZ_KERNEL_OK){staged=value;publish=true;}
    End(&entry->operation);
   }
   End(&borrow->operation);
  }
  result=PublicReleaseV6(borrow,Mach(status));
 }
 if(!result && publish)memcpy(out,&staged,bytes);
 PublicEndV6();return result;
}
hv_return_t hv_vcpu_get_reg(hv_vcpu_t identifier,hv_reg_t reg,uint64_t *value) {
 return PublicGetV6(identifier,VZ_KERNEL_INIT_SCALAR,(uint32_t)reg,value,8);
}
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t identifier,hv_simd_fp_reg_t reg,hv_simd_fp_uchar16_t *value) {
 return PublicGetV6(identifier,VZ_KERNEL_INIT_SIMD,(uint32_t)reg,value,16);
}
static hv_return_t PublicSYSV6(hv_vcpu_t identifier,VZKernelSysAction action,hv_sys_reg_t reg,uint64_t writeValue,uint64_t *out) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 Lock();bool valid=action!=VZ_KERNEL_SYS_READ || Output(out,sizeof(*out));Unlock();
 if(!valid){PublicEndV6();return Mach(VZ_KERNEL_BAD_ARGUMENT);}
 uint64_t value=0;VM27CPUFactoryBorrowV2 *borrow=NULL;hv_return_t result=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!result){VZKernelSysReceipt receipt={0};result=VM27CPUFactoryBorrowAccessSystemV4(borrow,action,(uint32_t)reg,writeValue,
  action==VZ_KERNEL_SYS_READ?&value:NULL,&receipt,NULL);
 result=PublicReleaseV6(borrow,result);}
 if(!result && action==VZ_KERNEL_SYS_READ)*out=value;
 PublicEndV6();return result;
}
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t identifier,hv_sys_reg_t reg,uint64_t *value) {
 return PublicSYSV6(identifier,VZ_KERNEL_SYS_READ,reg,0,value);
}
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t identifier,hv_sys_reg_t reg,uint64_t value) {
 return PublicSYSV6(identifier,VZ_KERNEL_SYS_WRITE,reg,value,NULL);
}
