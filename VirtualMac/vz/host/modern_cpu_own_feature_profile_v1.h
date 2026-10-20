/* Architectural values of the actual EL2-off own CPU profile. The extra
 * registers are not fields read from the old native capability response. */
#ifndef VM27_CPU_OWN_FEATURE_PROFILE_V1_H
#define VM27_CPU_OWN_FEATURE_PROFILE_V1_H
#include "modern_cpu_native_capability_seed.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Source is the bounded, validated original Native0-derived seed. Values
 * 0..11 retain that provenance, with explicitly withheld architecture bits.
 * 12..17 describe extensions that this own CPU does not implement. */
__attribute__((visibility("hidden")))
VZKernelStatus VM27CPUOwnProfileGetFeatureV1(const VZKernelCapabilitySeed *,
    uint32_t selector,uint64_t *);
/* This gate is applied beneath public and borrowed SYS adapters, after the
 * genuine lifecycle owner/version checks and before requested ID mutation. */
__attribute__((visibility("hidden")))
VZKernelStatus VM27CPUOwnProfileValidateSYSWriteV1(uint32_t,uint64_t);
#ifdef __cplusplus
}
#endif
#endif
