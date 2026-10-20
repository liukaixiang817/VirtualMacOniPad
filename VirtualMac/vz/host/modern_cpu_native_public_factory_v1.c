#include "modern_cpu_native_public_factory_v1.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

_Static_assert(sizeof(void *) == 8, "LP64 only");
_Static_assert(sizeof(VM27CPUFactoryExitV1) == 32, "Actual public exit storage");
_Static_assert(offsetof(VM27CPUFactoryExitV1, reason) == 0, "Public reason");
_Static_assert(offsetof(VM27CPUFactoryExitV1, syndrome) == 8, "Public syndrome");
_Static_assert(offsetof(VM27CPUFactoryExitV1, virtualAddress) == 16, "Public VA");
_Static_assert(offsetof(VM27CPUFactoryExitV1, physicalAddress) == 24, "Public IPA");

typedef struct Entry {
    struct Entry *next;
    VM27CPUFactoryVMV1 *vm;
    VZKernelCPU *cpu;
    VM27CPUFactoryExitV1 *exitStorage;
    VM27CPUFactoryIDV1 identity;
    uint64_t generation;
    pthread_t owner;
    bool live, complete, published, draining;
    unsigned borrowCount;
    VM27CPUFactoryBorrowV1 *borrows;
    _Atomic bool operation;
} Entry;
struct VM27CPUFactoryVMV1 {
    VZKernelVM *kernel;
    uint64_t epoch;
    pthread_t owner;
    bool live;
    Entry *entries;
    _Atomic bool operation;
};
struct VM27CPUFactoryBorrowV1 {
    VM27CPUFactoryBorrowV1 *next;
    Entry *entry;
    VZKernelCPUBorrowV5 *kernel;
    uint64_t epoch, generation;
    pthread_t borrower;
    _Atomic bool operation;
};
static pthread_mutex_t Registry = PTHREAD_MUTEX_INITIALIZER;
static VM27CPUFactoryVMV1 *Registered;
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
static VM27CPUFactoryMachStatusV1 Mach(VZKernelStatus status) {
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
static bool Output(const void *out, size_t bytes) {
    if (!out || bytes > UINTPTR_MAX - (uintptr_t)out) return false;
    if (!Registered) return true;
    if (!Disjoint(out, bytes, Registered, sizeof(*Registered))) return false;
    for (Entry *e = Registered->entries; e; e = e->next) {
        if (!Disjoint(out, bytes, e, sizeof(*e)) ||
            !Disjoint(out, bytes, e->exitStorage, sizeof(*e->exitStorage))) return false;
        for (VM27CPUFactoryBorrowV1 *b = e->borrows; b; b = b->next)
            if (!Disjoint(out, bytes, b, sizeof(*b))) return false;
    }
    return true;
}
static bool DiagnosticOutput(VM27CPUFactoryDiagnosticV1 *d) { return !d || Output(d, sizeof(*d)); }
static void Diagnose(VM27CPUFactoryDiagnosticV1 *out, VZKernelStatus status,
    const VZKernelLifecycleResult *native, VM27CPUFactoryVMV1 *vm, Entry *entry, bool destroy) {
    if (!out) return;
    VM27CPUFactoryDiagnosticV1 d = {0}; d.ownStatus = status;
    d.vmEpoch = vm ? vm->epoch : 0;
    if (entry) { d.cpuGeneration = entry->generation; d.cleanupPending = entry->cpu != NULL;
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
static bool ContainsBorrow(VM27CPUFactoryBorrowV1 *b) {
    if (!Contains(b->entry) || b->epoch != b->entry->vm->epoch ||
        b->generation != b->entry->generation) return false;
    for (VM27CPUFactoryBorrowV1 *q = b->entry->borrows; q; q = q->next) if (q == b) return true;
    return false;
}
static void Remove(Entry *entry) {
    Entry **link = &entry->vm->entries;
    while (*link && *link != entry) link = &(*link)->next;
    if (!*link || entry->borrowCount || entry->borrows || entry->cpu) abort();
    *link = entry->next;
}

VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMCreateV1(const VZKernelLifecycleOps *ops,
    const VZKernelVMOptions *options, VM27CPUFactoryVMV1 **out,
    VM27CPUFactoryDiagnosticV1 *diagnostic) {
    Lock(); bool valid = Output(out, sizeof(*out)) && DiagnosticOutput(diagnostic) &&
        (!diagnostic || Disjoint(out, sizeof(*out), diagnostic, sizeof(*diagnostic))); Unlock();
    if (!valid) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&Admission)) return Mach(VZ_KERNEL_BUSY);
    Lock(); bool busy = Registered != NULL; Unlock();
    if (busy) { End(&Admission); Diagnose(diagnostic, VZ_KERNEL_BUSY, NULL, NULL, NULL, false); return Mach(VZ_KERNEL_BUSY); }
    VM27CPUFactoryVMV1 *vm = calloc(1, sizeof(*vm));
    if (!vm) { End(&Admission); Diagnose(diagnostic, VZ_KERNEL_OUT_OF_MEMORY, NULL, NULL, NULL, false); return Mach(VZ_KERNEL_OUT_OF_MEMORY); }
    atomic_init(&vm->operation, true); vm->owner = pthread_self();
    Lock(); Registered = vm; Unlock();
    VZKernelLifecycleResult r = {0};
    VZKernelStatus status = VZKernelVMCreate(ops, options, &vm->kernel, &r);
    if (status == VZ_KERNEL_OK) { vm->epoch = r.generation; vm->live = true; *out = vm;
        Diagnose(diagnostic, status, &r, vm, NULL, false); End(&vm->operation); }
    else { Lock(); Registered = NULL; Unlock(); free(vm); Diagnose(diagnostic, status, &r, NULL, NULL, false); }
    End(&Admission); return Mach(status);
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMDestroyV1(VM27CPUFactoryVMV1 *vm,
    VM27CPUFactoryDiagnosticV1 *diagnostic) {
    if (!vm) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&vm->operation)) return Mach(VZ_KERNEL_BUSY);
    Lock(); bool valid = Registered == vm && DiagnosticOutput(diagnostic);
    bool busy = vm->entries != NULL; Unlock();
    if (!valid) { End(&vm->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    VZKernelStatus status = !pthread_equal(pthread_self(), vm->owner) ? VZ_KERNEL_WRONG_THREAD :
        busy ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    VZKernelLifecycleResult r = {0};
    if (status == VZ_KERNEL_OK) { status = VZKernelVMDestroy(vm->kernel, &r); if (status == VZ_KERNEL_OK) vm->live = false; }
    Diagnose(diagnostic, status, &r, vm, NULL, false); End(&vm->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryVMFreeV1(VM27CPUFactoryVMV1 *vm) {
    if (!vm) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&vm->operation)) return Mach(VZ_KERNEL_BUSY);
    Lock(); bool registered = Registered == vm, busy = vm->live || vm->entries != NULL; Unlock();
    VZKernelStatus status = !registered ? VZ_KERNEL_BAD_ARGUMENT :
        !pthread_equal(pthread_self(), vm->owner) ? VZ_KERNEL_WRONG_THREAD : busy ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    if (status == VZ_KERNEL_OK) status = VZKernelVMFree(vm->kernel);
    if (status == VZ_KERNEL_OK) { Lock(); Registered = NULL; Unlock(); free(vm); }
    else End(&vm->operation);
    return Mach(status);
}

VM27CPUFactoryMachStatusV1 VM27CPUFactoryCreateV1(VM27CPUFactoryVMV1 *vm,
    VM27CPUFactoryIDV1 *outID, VM27CPUFactoryExitV1 **outExit,
    VM27CPUFactoryForeignConfigV1 config, VM27CPUFactoryDiagnosticV1 *diagnostic) {
    if (!vm) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&vm->operation)) return Mach(VZ_KERNEL_BUSY);
    Lock(); bool valid = Registered == vm && Output(outID, sizeof(*outID)) &&
        Output(outExit, sizeof(*outExit)) && DiagnosticOutput(diagnostic) &&
        Disjoint(outID, sizeof(*outID), outExit, sizeof(*outExit)) &&
        (!diagnostic || (Disjoint(diagnostic, sizeof(*diagnostic), outID, sizeof(*outID)) &&
        Disjoint(diagnostic, sizeof(*diagnostic), outExit, sizeof(*outExit))));
    bool live = vm->live; Unlock();
    if (!valid) { End(&vm->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    VZKernelStatus status = config ? VZ_KERNEL_UNSUPPORTED : !live ? VZ_KERNEL_NOT_LIVE : Owned ? VZ_KERNEL_BUSY : VZ_KERNEL_OK;
    if (status != VZ_KERNEL_OK) { Diagnose(diagnostic, status, NULL, vm, NULL, false); End(&vm->operation); return Mach(status); }
    Entry *entry = calloc(1, sizeof(*entry));
    if (entry) entry->exitStorage = calloc(1, sizeof(*entry->exitStorage));
    if (!entry || !entry->exitStorage) { free(entry); Diagnose(diagnostic, VZ_KERNEL_OUT_OF_MEMORY, NULL, vm, NULL, false);
        End(&vm->operation); return Mach(VZ_KERNEL_OUT_OF_MEMORY); }
    entry->vm = vm; entry->owner = pthread_self(); atomic_init(&entry->operation, true);
    Lock(); entry->next = vm->entries; vm->entries = entry; Unlock(); Owned = entry;
    VZKernelLifecycleResult r = {0}; status = VZKernelCPUCreate(vm->kernel, &entry->cpu, &r);
    VM27CPUFactoryIDV1 identity = 0;
    if (status == VZ_KERNEL_OK) status = VZKernelCPUPublishIdentityV5(entry->cpu, &identity);
    Lock(); entry->generation = r.generation; entry->live = r.cpuLive;
    entry->identity = identity; entry->complete = status == VZ_KERNEL_OK; Unlock();
    if (status == VZ_KERNEL_OK) {
        Lock(); entry->published = true; Unlock();
        *outID = entry->identity; *outExit = entry->exitStorage;
        Diagnose(diagnostic, status, &r, vm, entry, false); End(&entry->operation);
    } else if (entry->cpu) {
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
static VZKernelStatus DestroyEntry(Entry *entry, VM27CPUFactoryDiagnosticV1 *diagnostic) {
    VM27CPUFactoryVMV1 *vm = entry->vm; VZKernelLifecycleResult r = {0};
    if (!pthread_equal(pthread_self(), entry->owner) || Owned != entry) {
        Diagnose(diagnostic, VZ_KERNEL_WRONG_THREAD, NULL, vm, entry, true); End(&entry->operation); return VZ_KERNEL_WRONG_THREAD;
    }
    Lock(); entry->published = false; entry->draining = true; bool borrowed = entry->borrowCount != 0; Unlock();
    VZKernelStatus status = VZ_KERNEL_OK;
    if (entry->identity && entry->live) status = VZKernelCPUUnpublishIdentityV5(entry->cpu);
    if (status == VZ_KERNEL_OK && borrowed) status = VZ_KERNEL_BUSY;
    if (status == VZ_KERNEL_OK && entry->live) {
        status = VZKernelCPUDestroy(entry->cpu, &r); if (status == VZ_KERNEL_OK) entry->live = false;
    }
    if (status == VZ_KERNEL_OK) status = VZKernelCPUFree(entry->cpu);
    if (status == VZ_KERNEL_OK) {
        entry->cpu = NULL; Diagnose(diagnostic, status, &r, vm, entry, true);
        Lock(); Remove(entry); Unlock(); Owned = NULL;
        memset(entry->exitStorage, 0, sizeof(*entry->exitStorage)); free(entry->exitStorage); free(entry);
    } else { Diagnose(diagnostic, status, &r, vm, entry, true); End(&entry->operation); }
    return status;
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryDestroyV1(VM27CPUFactoryIDV1 identity,
    VM27CPUFactoryDiagnosticV1 *diagnostic) {
    Lock(); Entry *entry = NULL;
    if (identity && Registered && DiagnosticOutput(diagnostic))
        for (Entry *q = Registered->entries; q; q = q->next)
            if (q->published && q->identity == identity) { entry = q; break; }
    bool begun = entry && Begin(&entry->operation); Unlock();
    if (!entry) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!begun) return Mach(VZ_KERNEL_BUSY);
    return Mach(DestroyEntry(entry, diagnostic));
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryOwnerCleanupV1(VM27CPUFactoryVMV1 *vm,
    VM27CPUFactoryDiagnosticV1 *diagnostic) {
    Lock(); Entry *entry = Owned;
    bool valid = vm && Registered == vm && entry && Contains(entry) && entry->vm == vm && DiagnosticOutput(diagnostic);
    bool begun = valid && Begin(&entry->operation); Unlock();
    if (!valid) return Mach(VZ_KERNEL_NOT_LIVE);
    if (!begun) return Mach(VZ_KERNEL_BUSY);
    return Mach(DestroyEntry(entry, diagnostic));
}

VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowAcquireV1(VM27CPUFactoryIDV1 identity,
    VM27CPUFactoryBorrowV1 **out) {
    Lock(); Entry *entry = NULL;
    bool output = Output(out, sizeof(*out));
    if (identity && Registered && output)
        for (Entry *e = Registered->entries; e; e = e->next)
            if (e->identity == identity && e->published && !e->draining && e->complete) { entry = e; break; }
    if (!entry) { Unlock(); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!Begin(&entry->operation)) { Unlock(); return Mach(VZ_KERNEL_BUSY); }
    if (entry->borrowCount == UINT_MAX) { End(&entry->operation); Unlock(); return Mach(VZ_KERNEL_BUSY); }
    Unlock();
    VM27CPUFactoryBorrowV1 *borrow = calloc(1, sizeof(*borrow));
    VZKernelStatus status = borrow ? VZ_KERNEL_OK : VZ_KERNEL_OUT_OF_MEMORY;
    if (status == VZ_KERNEL_OK) status = VZKernelCPUBorrowIdentityV5(identity, &borrow->kernel);
    if (status == VZ_KERNEL_OK) {
        borrow->entry = entry; borrow->epoch = entry->vm->epoch; borrow->generation = entry->generation;
        borrow->borrower = pthread_self(); atomic_init(&borrow->operation, false);
        Lock(); borrow->next = entry->borrows; entry->borrows = borrow; ++entry->borrowCount; Unlock(); *out = borrow;
    } else free(borrow);
    End(&entry->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowViewV1(VM27CPUFactoryBorrowV1 *borrow,
    VM27CPUFactoryViewV1 *out) {
    if (!borrow || !out) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&borrow->operation)) return Mach(VZ_KERNEL_BUSY);
    if (!pthread_equal(pthread_self(), borrow->borrower)) { End(&borrow->operation); return Mach(VZ_KERNEL_WRONG_THREAD); }
    Lock(); bool valid = ContainsBorrow(borrow) && Output(out, sizeof(*out));
    Entry *entry = valid ? borrow->entry : NULL;
    bool begun = entry && Begin(&entry->operation); Unlock();
    if (!valid) { End(&borrow->operation); return Mach(VZ_KERNEL_BAD_ARGUMENT); }
    if (!begun) { End(&borrow->operation); return Mach(VZ_KERNEL_BUSY); }
    VZKernelCPU *cpu = NULL;
    VZKernelStatus status = entry->draining ? VZ_KERNEL_NOT_LIVE : VZKernelCPUBorrowHandleV5(borrow->kernel, &cpu);
    if (status == VZ_KERNEL_OK && cpu != entry->cpu) status = VZ_KERNEL_NOT_LIVE;
    if (status == VZ_KERNEL_OK) { VM27CPUFactoryViewV1 view = {entry->identity, borrow->epoch,
        borrow->generation, entry->exitStorage, false}; memcpy(out, &view, sizeof(view)); }
    End(&entry->operation); End(&borrow->operation); return Mach(status);
}
VM27CPUFactoryMachStatusV1 VM27CPUFactoryBorrowReleaseV1(VM27CPUFactoryBorrowV1 *borrow) {
    if (!borrow) return Mach(VZ_KERNEL_BAD_ARGUMENT);
    if (!Begin(&borrow->operation)) return Mach(VZ_KERNEL_BUSY);
    if (!pthread_equal(pthread_self(), borrow->borrower)) { End(&borrow->operation); return Mach(VZ_KERNEL_WRONG_THREAD); }
    Lock(); bool valid = ContainsBorrow(borrow); Unlock();
    if (!valid) { End(&borrow->operation); return Mach(VZ_KERNEL_NOT_LIVE); }
    VZKernelStatus status = VZKernelCPUReleaseBorrowV5(borrow->kernel);
    if (status != VZ_KERNEL_OK) { End(&borrow->operation); return Mach(status); }
    Lock(); Entry *entry = borrow->entry; VM27CPUFactoryBorrowV1 **link = &entry->borrows;
    while (*link && *link != borrow) link = &(*link)->next;
    if (!*link || !entry->borrowCount) abort();
    *link = borrow->next; --entry->borrowCount; Unlock(); memset(borrow, 0, sizeof(*borrow)); free(borrow); return 0;
}
