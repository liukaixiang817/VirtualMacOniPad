#ifndef VM27_MODERN_CPU_TLBI_CAPABILITY_VALUES_V1_H
#define VM27_MODERN_CPU_TLBI_CAPABILITY_VALUES_V1_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define VM27_CPU_TLBI_HOST_MASK_V1 UINT64_C(0x2c0000000000)
typedef struct {
    uint32_t schemaVersion;
    uint32_t queryCalls;
    uint64_t actualOwnerThread;
    int32_t nativeReturn;
    int32_t sysctlReturn;
    uint64_t sysctlOutputBytes;
    int32_t vmmPresent;
    uint32_t guardedContextKnown;
    uint64_t hostContextWord40;
} VM27CPUTLBICapabilityInputV1;
typedef struct { bool known, supported; } VM27CPUTLBICapabilityValueV1;
// Pure interpretation of explicit values only. This function does not prove
// acquisition, invoke a query, authorize config mutation, or enable Run.
// Failure preserves output and returns false; UNKNOWN never becomes success.
bool VM27CPUInterpretTLBICapabilityV1(const VM27CPUTLBICapabilityInputV1 *,
    VM27CPUTLBICapabilityValueV1 *);
#ifdef __cplusplus
}
#endif
#endif
