#ifndef VM27_PRODUCTION_NATIVE_OPS_V1_H
#define VM27_PRODUCTION_NATIVE_OPS_V1_H
#include "modern_cpu_hv_public_abi_v3.h"
#ifdef __cplusplus
extern "C" {
#endif
// Call in the child VMM, on its actual VM setup pthread, before its first
// configuration creation. Pure capability queries must not choose VM owner.
// Repeated calls on that same pthread are OK.
// The process must already have its own platform/hypervisor entitlement and
// unlimited CPU limit. This installer changes neither privilege nor limits.
__attribute__((visibility("hidden"))) hv_return_t
VM27InstallProductionNativeOpsV1(void);
// Use only after actual CPU destruction, successful unmaps, VM destruction,
// and configuration releases. Failures retain all provider ownership.
__attribute__((visibility("hidden"))) hv_return_t
VM27UninstallProductionNativeOpsV1(void);
#ifdef __cplusplus
}
#endif
#endif
