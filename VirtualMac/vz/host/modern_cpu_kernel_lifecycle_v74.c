/* Life65 semantics, with private live-owner mapping validation at these call
 * sites. Production11 publishes only actual native6 mappings and withdraws
 * before native7. Generic V1, owner/epoch/slot/disjoint/version checks, native
 * execution, GIC and timer behavior remain intact. */
#include "modern_cpu_owned_mapping_cache_v1.h"
#define VM27CPUSelfMappedRangeV1 VM27CPUSelfOwnedMappedRangeV1
#include "modern_cpu_kernel_lifecycle_v74_base.c"
#undef VM27CPUSelfMappedRangeV1
