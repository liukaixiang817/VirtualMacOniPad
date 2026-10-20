#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V8_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V8_H
#include "modern_cpu_native_public_factory_v7.h"
#ifdef __cplusplus
extern "C" {
#endif
// Genuine SDK first/only argument and return ABI. The implementation invokes
// exactly one owned native9 and publishes only its closed exception lane after
// borrower release. raw2/11 -> BUSY; all other unclosed lanes -> real failure.
// This inert provider cannot yet replace the original complete hv_vcpu_run.
hv_return_t hv_vcpu_run(hv_vcpu_t);
#ifdef __cplusplus
}
#endif
#endif
