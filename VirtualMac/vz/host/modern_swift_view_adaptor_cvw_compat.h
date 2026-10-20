#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct VM27ViewCVWInfo { size_t size, stride; uint32_t flags, extraInhabitants; };
int VM27ViewCVWQuery(const void *metadata, struct VM27ViewCVWInfo *info);
void VM27ViewCVWDestroy(void *value, const void *metadata);
void *VM27ViewCVWInitWithCopy(void *dest, const void *src, const void *metadata);
void *VM27ViewCVWAssignWithCopy(void *dest, const void *src, const void *metadata);
void *VM27ViewCVWAssignWithTake(void *dest, void *src, const void *metadata);
void *VM27ViewCVWBufferCopy(void *dest, const void *src, const void *metadata);
#ifdef __cplusplus
}
#endif
