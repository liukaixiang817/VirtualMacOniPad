/* Force-include only for the frozen Factory15 translation unit. Its genuine
 * disjointness, registry and ownership checks remain. Permission queries on
 * an admitted owner's native pages/stack use Mapping7's epoch/PID-checked
 * cache. Foreign, heap, pre-create and withdrawn accesses retain the original
 * Mach query fallback; this does not admit arbitrary client memory. */
#define VM27CPUSelfMappedRangeV1 VM27CPUSelfOwnedMappedRangeV1
