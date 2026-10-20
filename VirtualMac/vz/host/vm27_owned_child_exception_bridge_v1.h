#pragma once
#ifdef __cplusplus
#define VM27_DIAG_NOEXCEPT noexcept
extern "C" {
#else
#define VM27_DIAG_NOEXCEPT
#endif
__attribute__((visibility("hidden")))
void *VM27ChildInitExceptionOriginalV1(void *caller,int *log) VM27_DIAG_NOEXCEPT;
__attribute__((visibility("hidden")))
void VM27ChildInitExceptionEnterV1(void) VM27_DIAG_NOEXCEPT;
__attribute__((visibility("hidden")))
void VM27ChildInitExceptionReturnedV1(const void *result) VM27_DIAG_NOEXCEPT;
__attribute__((visibility("hidden")))
void VM27ChildInitExceptionTextV1(const char *kind,const char *name,const char *reason,const void *typeInfo) VM27_DIAG_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef VM27_DIAG_NOEXCEPT
