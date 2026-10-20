// Local model only: every lifecycle operation and context byte is owned here.
// No native trap, Apple provider, device access, mapping or guest run is used.
#include "modern_cpu_kernel_initialization.h"
#include "modern_cpu_native_fields.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

typedef enum { STABLE, CHANGE_VERSION, FAIL_VERSION_READ, CHANGE_THREAD } Fault;
typedef struct {
    unsigned char bytes[0x4130];
    uint64_t thread;
    uint32_t writes, faultAfterWrite, traps;
    Fault fault;
    bool checkSnapshotReentry;
    uint32_t snapshotReentryChecks;
    uint32_t reads, failReadAt;
    VZKernelVM *vm;
    VZKernelCPU *cpu;
    VZKernelLifecycleResult lifecycle;
} Fixture;

static void SetVersion(Fixture *f, uint64_t value) {
    memcpy(f->bytes + 0x4000, &value, sizeof(value));
}

static VZKernelHVReturn MockTrap(void *context, uint64_t operation, void *input) {
    Fixture *f = context;
    ++f->traps;
    CHECK(operation == 1 || operation == 6 || operation == 7 || operation == 2);
    if (operation == 6) {
        uint64_t *words = input;
        CHECK(words && words[0] == 0 && words[1] == 0);
        words[1] = (uintptr_t)f->bytes;
    }
    return 0;
}

static uint64_t MockThread(void *context) {
    return ((Fixture *)context)->thread;
}

static bool MockRead(void *context, const void *address, size_t bytes, void *out) {
    Fixture *f = context;
    uintptr_t base = (uintptr_t)f->bytes;
    uintptr_t source = (uintptr_t)address;
    if (source < base || source - base > sizeof(f->bytes) ||
        bytes > sizeof(f->bytes) - (source - base)) return false;
    ++f->reads;
    if (f->failReadAt && f->reads == f->failReadAt) return false;
    if (f->checkSnapshotReentry) {
        VZKernelLifecycleResult lifecycle;
        VZKernelNativeSnapshot snapshot, before;
        VZKernelNativeReadDiagnostics diagnostics;
        memset(&snapshot, 0xa5, sizeof(snapshot));
        before = snapshot;
        CHECK(VZKernelCPUDestroy(f->cpu, &lifecycle) == VZ_KERNEL_BUSY);
        CHECK(!lifecycle.nativeInvoked && VZKernelCPUFree(f->cpu) == VZ_KERNEL_BUSY);
        CHECK(VZKernelCPUReadNativeFields(f->cpu, &snapshot, &diagnostics,
            &lifecycle) == VZ_KERNEL_BUSY);
        CHECK(!memcmp(&snapshot, &before, sizeof(snapshot)));
        ++f->snapshotReentryChecks;
    }
    if (source - base == 0x4000 && f->fault == FAIL_VERSION_READ &&
        f->faultAfterWrite && f->writes >= f->faultAfterWrite) return false;
    memcpy(out, address, bytes);
    return true;
}

static bool MockWrite(void *context, void *address, size_t bytes, const void *value) {
    Fixture *f = context;
    uintptr_t base = (uintptr_t)f->bytes;
    uintptr_t target = (uintptr_t)address;
    CHECK(target >= base && target - base <= sizeof(f->bytes));
    CHECK(bytes <= sizeof(f->bytes) - (target - base));
    memcpy(address, value, bytes);
    ++f->writes;
    if (f->faultAfterWrite && f->writes == f->faultAfterWrite) {
        if (f->fault == CHANGE_VERSION) SetVersion(f, 0);
        if (f->fault == CHANGE_THREAD) f->thread = 2;
    }
    return true;
}

static void Create(Fixture *f, uint32_t isa, bool policyBit4) {
    memset(f, 0, sizeof(*f));
    f->thread = 1;
    SetVersion(f, VZ_KERNEL_NATIVE_CONTEXT_VERSION);
    f->bytes[0x4030] = policyBit4 ? 0x10 : 0;
    VZKernelLifecycleOps ops = {1, VZ_KERNEL_PROFILE_IPADOS_16_1_1,
        f, MockTrap, MockThread, MockRead};
    VZKernelVMOptions options = {36, 0, isa, false, false};
    CHECK(VZKernelVMCreate(&ops, &options, &f->vm, &f->lifecycle) == VZ_KERNEL_OK);
    CHECK(VZKernelCPUCreate(f->vm, &f->cpu, &f->lifecycle) == VZ_KERNEL_OK);
}

static VZKernelStatus Apply(Fixture *f, uint32_t isa, VZKernelInitOperation operation,
    VZKernelInitReceipt *receipt) {
    VZKernelInitRequest q = {0};
    q.schemaVersion = 1;
    q.validatedKernelProfile = VZ_KERNEL_PROFILE_IPADOS_16_1_1;
    q.expectedOwnerThread = f->lifecycle.ownerThread;
    q.expectedCPUGeneration = f->lifecycle.generation;
    q.expectedReturnedSlotWord = f->lifecycle.returnedSlotWord;
    q.nativeHVISA = isa;
    q.operation = operation;
    VZKernelInitWriter writer = {f, MockWrite};
    return VZKernelCPUApplyInitialization(f->cpu, &q, &writer, receipt, &f->lifecycle);
}

static void Destroy(Fixture *f) {
    // Simulate return to the recorded owner. Leave invalid/unreadable version
    // state in place: CPU cleanup must not need a repaired context version.
    f->thread = 1;
    CHECK(VZKernelCPUDestroy(f->cpu, &f->lifecycle) == VZ_KERNEL_OK);
    CHECK(VZKernelCPUFree(f->cpu) == VZ_KERNEL_OK);
    CHECK(VZKernelVMDestroy(f->vm, &f->lifecycle) == VZ_KERNEL_OK);
    CHECK(VZKernelVMFree(f->vm) == VZ_KERNEL_OK);
    CHECK(f->traps == 4);
}

static void RejectFinalCallback(Fault fault, uint32_t isa, bool policyBit4,
    VZKernelInitOperation operation) {
    Fixture f;
    VZKernelInitReceipt receipt;
    Create(&f, isa, policyBit4);
    uint32_t policyWrites = policyBit4 ? 7 : 6;
    if (operation != VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY) {
        CHECK(Apply(&f, isa, VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY, &receipt) == VZ_KERNEL_OK);
        CHECK(receipt.creationPolicySliceComplete && !receipt.mutationPoisoned);
    }
    f.fault = fault;
    f.faultAfterWrite = operation == VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY ?
        policyWrites : f.writes + (operation == VZ_KERNEL_INIT_CONTROL ? 4 : 1);
    VZKernelStatus expected = fault == CHANGE_VERSION ? VZ_KERNEL_CONTEXT_VERSION_MISMATCH :
        fault == CHANGE_THREAD ? VZ_KERNEL_WRONG_THREAD : VZ_KERNEL_CONTEXT_UNREADABLE;
    CHECK(Apply(&f, isa, operation, &receipt) == expected);
    CHECK(receipt.status == expected && receipt.mutationPoisoned && receipt.cpuCleanupRequired);
    CHECK(receipt.creationPolicySliceComplete == (operation != VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY));
    CHECK(!receipt.architecturalResetComplete && !receipt.runAllowed);
    CHECK(f.writes == f.faultAfterWrite && receipt.completedWrites == receipt.attemptedWrites);
    CHECK(f.traps == 2); // Initialization never introduces a lifecycle call.
    f.thread = 1;
    uint32_t previousWrites = f.writes;
    CHECK(Apply(&f, isa, VZ_KERNEL_INIT_SCALAR, &receipt) == VZ_KERNEL_BUSY);
    CHECK(f.writes == previousWrites && receipt.mutationPoisoned);
    Destroy(&f);
}

static void AcceptStable(uint32_t isa, bool policyBit4) {
    Fixture f;
    VZKernelInitReceipt receipt;
    Create(&f, isa, policyBit4);
    for (VZKernelInitOperation operation = VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY;
        operation <= VZ_KERNEL_INIT_CONTROL; ++operation) {
        CHECK(Apply(&f, isa, operation, &receipt) == VZ_KERNEL_OK);
        CHECK(receipt.creationPolicySliceComplete && !receipt.mutationPoisoned);
        CHECK(!receipt.architecturalResetComplete && !receipt.runAllowed);
    }
    CHECK(f.writes == (policyBit4 ? 7u : 6u) + 6u);
    Destroy(&f);
}

static void ProtectSnapshot(uint32_t isa) {
    Fixture f;
    Create(&f, isa, false);
    VZKernelNativeSnapshot snapshot, before;
    VZKernelNativeReadDiagnostics diagnostics;
    VZKernelLifecycleResult lifecycle;
    f.checkSnapshotReentry = true;
    CHECK(VZKernelCPUReadNativeFields(f.cpu, &snapshot, &diagnostics,
        &lifecycle) == VZ_KERNEL_OK);
    CHECK(f.snapshotReentryChecks == diagnostics.attemptedReads && f.traps == 2);
    f.checkSnapshotReentry = false;
    memset(&snapshot, 0xa5, sizeof(snapshot));
    before = snapshot;
    // A failed read must release the same in-use exclusion for owner cleanup.
    f.fault = FAIL_VERSION_READ;
    f.faultAfterWrite = 1;
    f.writes = 1;
    CHECK(VZKernelCPUReadNativeFields(f.cpu, &snapshot, &diagnostics,
        &lifecycle) == VZ_KERNEL_CONTEXT_UNREADABLE);
    CHECK(!memcmp(&snapshot, &before, sizeof(snapshot)));
    Destroy(&f);
}

static void ReleaseFailedSnapshot(uint32_t isa) {
    Fixture f;
    VZKernelNativeSnapshot snapshot, before;
    VZKernelNativeReadDiagnostics diagnostics;
    VZKernelLifecycleResult lifecycle;
    Create(&f, isa, false);
    f.reads = 0;
    CHECK(VZKernelCPUReadNativeFields(f.cpu, &snapshot, &diagnostics,
        &lifecycle) == VZ_KERNEL_OK);
    uint32_t totalReads = f.reads;
    CHECK(totalReads == diagnostics.attemptedReads && totalReads == 84);
    Destroy(&f);
    for (uint32_t failure = 1; failure <= totalReads; ++failure) {
        Create(&f, isa, false);
        f.reads = 0;
        f.failReadAt = failure;
        memset(&snapshot, 0xa5, sizeof(snapshot));
        before = snapshot;
        CHECK(VZKernelCPUReadNativeFields(f.cpu, &snapshot, &diagnostics,
            &lifecycle) == VZ_KERNEL_CONTEXT_UNREADABLE);
        CHECK(f.reads == failure && !memcmp(&snapshot, &before, sizeof(snapshot)));
        f.failReadAt = 0;
        CHECK(VZKernelCPUReadNativeFields(f.cpu, &snapshot, &diagnostics,
            &lifecycle) == VZ_KERNEL_OK);
        Destroy(&f);
    }
}

int main(void) {
    for (uint32_t isa = 1; isa <= 2; ++isa) {
        ProtectSnapshot(isa);
        ReleaseFailedSnapshot(isa);
        for (unsigned policyBit4 = 0; policyBit4 <= 1; ++policyBit4) {
            AcceptStable(isa, policyBit4);
            for (Fault fault = CHANGE_VERSION; fault <= CHANGE_THREAD; ++fault)
                for (VZKernelInitOperation operation = VZ_KERNEL_INIT_DEFAULT_CREATION_POLICY;
                    operation <= VZ_KERNEL_INIT_CONTROL; ++operation)
                    RejectFinalCallback(fault, isa, policyBit4, operation);
        }
    }
    puts("PASS: 4 stable, 48 final-callback rejection, 2 snapshot reentry, 168 read failures; local mocks only");
    return 0;
}
