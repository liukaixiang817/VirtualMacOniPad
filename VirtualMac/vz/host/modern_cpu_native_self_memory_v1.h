// Own-task Mach memory boundary. This contains no native HV operation.
#ifndef VM27_MODERN_CPU_NATIVE_SELF_MEMORY_V1_H
#define VM27_MODERN_CPU_NATIVE_SELF_MEMORY_V1_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t queries, releasedObjectPorts;
    int32_t queryStatus, portReleaseStatus;
    uintptr_t firstRegionStart, finalRegionEnd;
    bool requestedRangeMapped, writableRequested;
} VM27CPUSelfMappedReceiptV1;
// Query actual self-task regions covering the requested finite range. Holes,
// permission failures, overflow, more than eight regions, or a leaked returned
// object port all fail. The observed region end is not a kernel allocation size.
// Lifecycle ownership binds the address to its own successful native6 handle.
// This helper does not establish CPU identity or accept a synthetic lease.
bool VM27CPUSelfMappedRangeV1(const void *, size_t, bool writable,
    VM27CPUSelfMappedReceiptV1 *);
bool VM27CPUSelfReadV1(void *, const void *, size_t, void *);
bool VM27CPUSelfWriteV1(void *, void *, size_t, const void *);
#endif
