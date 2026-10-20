#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Explicit private API for genuine UUID-pinned VZ27 VZEFISignature only.
// Values must occupy disjoint aligned 24-byte storage; no global Swift override.
struct VM27EFICVWInfo { size_t size, stride; uint32_t flags, extraInhabitants; };
int VM27EFICVWQuery(const void *metadata, struct VM27EFICVWInfo *info);
unsigned VM27EFICVWGetEnumTag(const void *value, const void *metadata);
void VM27EFICVWDestroy(void *value, const void *metadata);
void *VM27EFICVWInitWithCopy(void *dest, const void *src, const void *metadata);
void *VM27EFICVWAssignWithCopy(void *dest, const void *src, const void *metadata);
void *VM27EFICVWAssignWithTake(void *dest, void *src, const void *metadata);
void *VM27EFICVWBufferCopy(void *dest, const void *src, const void *metadata);
#ifdef __cplusplus
}
#endif
