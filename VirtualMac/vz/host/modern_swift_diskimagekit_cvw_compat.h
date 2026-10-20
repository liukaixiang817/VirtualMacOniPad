#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct VM27DIKCVWInfo { size_t size, stride; uint32_t flags, extraInhabitants, type; };
int VM27DIKCVWQuery(const void *, struct VM27DIKCVWInfo *);
void swift_cvw_destroy(void *, const void *);
void *swift_cvw_initWithCopy(void *, const void *, const void *);
void *swift_cvw_initWithTake(void *, void *, const void *);
void *swift_cvw_assignWithCopy(void *, const void *, const void *);
void *swift_cvw_assignWithTake(void *, void *, const void *);
void *swift_cvw_initializeBufferWithCopyOfBuffer(void *, const void *, const void *);
void swift_cvw_initStructMetadataWithLayoutString(void *, size_t, size_t,
    const unsigned char *const *, const unsigned char *, uint32_t *);
#ifdef __cplusplus
}
#endif
