#ifndef VM27_MODERN_CPU_CONFIG_OS_OBJECT_V3_H
#define VM27_MODERN_CPU_CONFIG_OS_OBJECT_V3_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// An application-owned OS_object, created at +1 and released with CFRelease.
// It is not OS_hv_vcpu_config and is never passed to an Apple/native entry.
// Each concurrent caller must hold a real CF reference. The generation rejects
// an old handle even if a later allocation reuses its address.
typedef struct {
    const void *object;
    uint64_t generation;
} VM27CPUConfigHandleV3;
typedef struct {
    uint32_t schemaVersion;
    uint32_t fineGrainedTraps;
    uint32_t trapTLBISW;
    uint32_t supportKnown;
    uint64_t vmKeyLow, vmKeyHigh, generation;
} VM27CPUConfigSnapshotV3;
typedef int32_t VM27CPUConfigStatusV3;

// These status bits match the genuine public signed32 constants. They are not
// errno, native reason values, or a successful native configuration claim.
#define VM27_CPU_CONFIG_OK_V3 ((int32_t)0)
#define VM27_CPU_CONFIG_BUSY_V3 ((int32_t)UINT32_C(0xfae94002))
#define VM27_CPU_CONFIG_ERROR_V3 ((int32_t)UINT32_C(0xfae94001))
#define VM27_CPU_CONFIG_BAD_ARGUMENT_V3 ((int32_t)UINT32_C(0xfae94003))
#define VM27_CPU_CONFIG_UNSUPPORTED_V3 ((int32_t)UINT32_C(0xfae9400f))

VM27CPUConfigStatusV3 VM27CPUConfigCreateV3(VM27CPUConfigHandleV3 *out);
VM27CPUConfigStatusV3 VM27CPUConfigCopyV3(VM27CPUConfigHandleV3,
    VM27CPUConfigSnapshotV3 *out);
VM27CPUConfigStatusV3 VM27CPUConfigSetVMKeyV3(VM27CPUConfigHandleV3,
    uint64_t low, uint64_t high);
VM27CPUConfigStatusV3 VM27CPUConfigSetFGTV3(VM27CPUConfigHandleV3,
    uint32_t enabled);
// False is the genuine query-free lane. True uses independent process-once
// guarded op0 plus strict sysctl acquisition. UNKNOWN never writes the bit.
VM27CPUConfigStatusV3 VM27CPUConfigSetTLBIV3(VM27CPUConfigHandleV3,
    uint32_t enabled);

// Opaque-object bridge with the genuine caller's pointer representation. These
// remain own APIs and accept only registry-known OS_VM27CPUConfigV3 objects.
// Lookup occurs before any foreign pointer dereference. Borrow keeps a real CF
// reference and a stable copied configuration; caller owns a real reference too.
// A released borrow is no longer a C handle. Pointer reuse does not grant a
// new generation; callers must not retain/use the pointer after Release.
typedef struct VM27CPUConfigBorrowV3 VM27CPUConfigBorrowV3;
const void *VM27CPUConfigCreateObjectV3(void);
VM27CPUConfigStatusV3 VM27CPUConfigSetTLBIObjectV3(const void *, bool enabled);
VM27CPUConfigStatusV3 VM27CPUConfigBorrowObjectV3(const void *, VM27CPUConfigBorrowV3 **);
VM27CPUConfigStatusV3 VM27CPUConfigReadBorrowV3(VM27CPUConfigBorrowV3 *, VM27CPUConfigSnapshotV3 *);
VM27CPUConfigStatusV3 VM27CPUConfigReleaseBorrowV3(VM27CPUConfigBorrowV3 *);
#ifdef __cplusplus
}
#endif
#endif
