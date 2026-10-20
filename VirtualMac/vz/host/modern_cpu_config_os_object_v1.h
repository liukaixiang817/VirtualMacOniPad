#ifndef VM27_MODERN_CPU_CONFIG_OS_OBJECT_V1_H
#define VM27_MODERN_CPU_CONFIG_OS_OBJECT_V1_H
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
} VM27CPUConfigHandleV1;
typedef struct {
    uint32_t schemaVersion;
    uint32_t fineGrainedTraps;
    uint32_t trapTLBISW;
    uint32_t supportKnown;
    uint64_t vmKeyLow, vmKeyHigh, generation;
} VM27CPUConfigSnapshotV1;
typedef int32_t VM27CPUConfigStatusV1;

// These status bits match the genuine public signed32 constants. They are not
// errno, native reason values, or a successful native configuration claim.
#define VM27_CPU_CONFIG_OK_V1 ((int32_t)0)
#define VM27_CPU_CONFIG_ERROR_V1 ((int32_t)UINT32_C(0xfae94001))
#define VM27_CPU_CONFIG_BAD_ARGUMENT_V1 ((int32_t)UINT32_C(0xfae94003))
#define VM27_CPU_CONFIG_UNSUPPORTED_V1 ((int32_t)UINT32_C(0xfae9400f))

VM27CPUConfigStatusV1 VM27CPUConfigCreateV1(VM27CPUConfigHandleV1 *out);
VM27CPUConfigStatusV1 VM27CPUConfigCopyV1(VM27CPUConfigHandleV1,
    VM27CPUConfigSnapshotV1 *out);
VM27CPUConfigStatusV1 VM27CPUConfigSetVMKeyV1(VM27CPUConfigHandleV1,
    uint64_t low, uint64_t high);
VM27CPUConfigStatusV1 VM27CPUConfigSetFGTV1(VM27CPUConfigHandleV1,
    uint32_t enabled);
// False is the genuine query-free lane. True is rejected while an actual
// host capability acquisition has not been integrated. UNKNOWN is preserved.
VM27CPUConfigStatusV1 VM27CPUConfigSetTLBIV1(VM27CPUConfigHandleV1,
    uint32_t enabled);

#ifdef __cplusplus
}
#endif
#endif
