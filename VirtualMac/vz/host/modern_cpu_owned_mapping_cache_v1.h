/* Private acceleration for mappings owned by one successful native6 CPU.
 * This is not a CPU admission API. Only Production11 publishes, after its
 * real native6 result and actual Mach-region checks; it withdraws before7.
 * Generic V1 queries, their receipts, and all external ranges stay unchanged.
 */
#ifndef VM27_CPU_OWNED_MAPPING_CACHE_V1_H
#define VM27_CPU_OWNED_MAPPING_CACHE_V1_H
#include "modern_cpu_native_self_memory_v1.h"

typedef struct {
    uint64_t contextHits, stackHits, fallbacks;
} VM27CPUOwnedMappingCountsV1;

#define VM27_MAPPING_PRIVATE_V1 __attribute__((visibility("hidden")))
VM27_MAPPING_PRIVATE_V1 bool VM27CPUOwnedMappingPublishV1(uint64_t slot,
    uintptr_t ownerToken, uint64_t ownerThread, uintptr_t nativeContext,
    unsigned contextReadPages, unsigned contextWritePages,
    uintptr_t stackStart, size_t stackBytes, bool wholeStackWritable);
VM27_MAPPING_PRIVATE_V1 void VM27CPUOwnedMappingWithdrawV1(uint64_t slot,
    uintptr_t ownerToken, VM27CPUOwnedMappingCountsV1 *counts);
VM27_MAPPING_PRIVATE_V1 bool VM27CPUSelfOwnedMappedRangeV1(const void *,
    size_t, bool writable, VM27CPUSelfMappedReceiptV1 *);
#undef VM27_MAPPING_PRIVATE_V1
#endif
