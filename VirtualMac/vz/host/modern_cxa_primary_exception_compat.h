// Scoped diagnostic ABI description, verified against the system image pins.
#ifndef VM27_CXA_PRIMARY_EXCEPTION_COMPAT_H
#define VM27_CXA_PRIMARY_EXCEPTION_COMPAT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// 1 means every native function, UUID and cleanup code pin was verified.
int VM27PrimaryExceptionNativeABIStatus(void);
uint64_t VM27PrimaryExceptionInitializeCalls(void);
uintptr_t VM27PrimaryExceptionNativeCleanupAddress(void);
#ifdef __cplusplus
}
#endif
#endif
