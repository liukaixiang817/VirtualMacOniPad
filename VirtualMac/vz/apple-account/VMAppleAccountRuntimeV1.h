#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// This is a private App -> its own VMM handoff, not an Apple identity format.
// Native MachineIdentifier/HardwareModel files remain untouched and bind it.
typedef struct {
    uint8_t magic[8]; // "VMAID001"
    uint32_t schema, appPID;
    uint8_t profileUUID[16];
    char build[16], serial[32], mlb[32], model[32];
    uint8_t mac[4][8];
    uint8_t machineSHA256[32], hardwareSHA256[32];
    char bundlePath[1024];
} VMAppleAccountHandoffV1;

// Called only from the owned native bootstrap/factory and validated native
// post-return boundary. Ordinary VMs have no valid handoff and remain unchanged.
__attribute__((visibility("hidden"))) void VMAppleAccountRecordMapV1(void *, uint64_t, size_t, uint64_t);
__attribute__((visibility("hidden"))) void VMAppleAccountRecordUnmapV1(uint64_t, size_t);
__attribute__((visibility("hidden"))) void VMAppleAccountRecordProtectV1(uint64_t, size_t, uint64_t);
__attribute__((visibility("hidden"))) bool VMAppleAccountBeforeRunV1(void);
__attribute__((visibility("hidden"))) void VMAppleAccountRecordFirstCPUV1(uint64_t);
__attribute__((visibility("hidden"))) void VMAppleAccountCPUResetV1(uint64_t, uint64_t);
__attribute__((visibility("hidden"))) bool VMAppleAccountOverrideConfigReadV1(uint64_t, uint32_t, uint64_t, uint64_t *);
__attribute__((visibility("hidden"))) bool VMAppleAccountKernelPendingV1(void);
__attribute__((visibility("hidden"))) int VMAppleAccountEarlyKernelV1(uint64_t, const uint64_t[31], uint64_t, uint64_t);
