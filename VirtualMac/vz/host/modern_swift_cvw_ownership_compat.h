// Scoped default Swift compact ownership witness ABI; no compatibility registry.
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    size_t size;
    size_t stride;
    uint32_t flags;
    uint32_t extraInhabitants;
} VM27CVWOwnershipInfo;
// Only the genuine, authenticated VZ27 CachingOptions compact type is supported.
// A false query makes no value mutation or ownership call. The witness entries
// trap before mutation on unsupported metadata/overlap. Destinations of init
// calls are uninitialized; assign destinations and destroy values initialized.
// Take consumes its source. Both 24-byte storage cells must be disjoint.
int VM27CVWOwnershipQuery(const void *metadata, VM27CVWOwnershipInfo *info);
void swift_cvw_destroy(void *value, const void *metadata);
void *swift_cvw_initWithCopy(void *dest, const void *src, const void *metadata);
void *swift_cvw_assignWithCopy(void *dest, const void *src, const void *metadata);
void *swift_cvw_assignWithTake(void *dest, void *src, const void *metadata);
void *swift_cvw_initializeBufferWithCopyOfBuffer(void *dest, const void *src,
                                               const void *metadata);
#ifdef __cplusplus
}
#endif
