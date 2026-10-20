// Pure original-kernel capability -> feature seed transform. No native calls.
#ifndef VZ_MODERN_CPU_NATIVE_CAPABILITY_SEED_H
#define VZ_MODERN_CPU_NATIVE_CAPABILITY_SEED_H
#include "modern_cpu_kernel_lifecycle.h"
#define VZ_KERNEL_CAPABILITY_CONSUMED_PREFIX_BYTES 0x148u
#define VZ_KERNEL_FEATURE_SEED_BYTES 0xe0u
#define VZ_KERNEL_FEATURE_SEED_SDK_TOKEN UINT64_C(0x07e60901ffffffff)
typedef struct {
    uint32_t schemaVersion;
    uint32_t validatedKernelProfile;
    const unsigned char *capabilityPrefix;
    size_t prefixBytes;
    // Three real _dyld_program_sdk_at_least results, in original call order.
    // The pure transform accepts each explicit boolean, without calling dyld
    // or claiming any hardware/SDK observation has happened.
    uint32_t sdkPredicateResults[3];
} VZKernelCapabilitySeedInput;
typedef struct {
    uint64_t featureWords[12];
    uint64_t instructionCCSIDR[8];
    uint64_t dataUnifiedCCSIDR[8];
} VZKernelCapabilitySeed;
typedef struct {
    VZKernelStatus status;
    uint32_t prefixBytesConsumed, seedBytesProduced, sdkResultsConsumed;
    bool pureTransform, nativeOp0Invoked, CPUCacheInstalled, realCapabilitiesProved;
} VZKernelCapabilitySeedReceipt;
VZKernelStatus VZKernelComputeNativeCapabilitySeed(const VZKernelCapabilitySeedInput *,
    VZKernelCapabilitySeed *, VZKernelCapabilitySeedReceipt *);
// Original config-feature selector10/11 swaps CLIDR/DCZID relative to seed.
VZKernelStatus VZKernelCapabilitySeedGetFeature(const VZKernelCapabilitySeed *,uint32_t selector,uint64_t *out);
VZKernelStatus VZKernelCapabilitySeedGetSYSFeature(const VZKernelCapabilitySeed *,uint32_t encodedSelector,uint64_t *out);
// Original selector0 is data/unified; selector1 is instruction. Unknown out
// remains unchanged. These are values, not a fabricated Apple cache object.
VZKernelStatus VZKernelCapabilitySeedGetCCSIDR(const VZKernelCapabilitySeed *,uint32_t selector,uint64_t out[8]);
VZKernelStatus VZKernelCapabilitySeedEncodeLE(const VZKernelCapabilitySeed *,unsigned char out[VZ_KERNEL_FEATURE_SEED_BYTES]);
#endif
