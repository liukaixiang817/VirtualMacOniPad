#ifndef VM27_MODERN_GIC_V3_ENGINE_V2_H
#define VM27_MODERN_GIC_V3_ENGINE_V2_H
#include "modern_gic_v3_engine_v1.h"
// Base alignment is independent from the unchanged 128 KiB per-CPU stride.
#define VM27_GIC_REDIST_ALIGNMENT_V2 UINT64_C(0x10000)
static inline uint64_t VM27GICRedistributorBaseAlignmentV2(void) {
 return VM27_GIC_REDIST_ALIGNMENT_V2;
}
#endif
