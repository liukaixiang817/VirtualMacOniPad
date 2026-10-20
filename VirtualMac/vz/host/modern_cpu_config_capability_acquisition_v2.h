#ifndef VM27_CPU_CONFIG_CAPABILITY_ACQUISITION_V2_H
#define VM27_CPU_CONFIG_CAPABILITY_ACQUISITION_V2_H
#include "modern_cpu_config_capability_acquisition_v1.h"
#include "modern_cpu_native_capability_seed.h"
typedef struct {
    bool known; // Successful bounded source, never proof of supported IPA size.
    uint64_t rawFieldA,rawFieldB;
} VM27CPURawIPAPairV2;
typedef struct {
    VM27CPUTLBICapabilityValueV1 TLBI;
    bool featureSeedKnown;
    VZKernelCapabilitySeed featureSeed;
    VM27CPURawIPAPairV2 IPA;
} VM27CPUCapabilitiesV2;
// One private process-once acquisition serves both properties. Only this
// module owns the actual op0 bytes and calls the three original SDK predicates.
// The buffer's 352-byte capacity is not the kernel's write length. No receipt,
// old observation or caller-supplied feature word authorizes a successful read.
__attribute__((visibility("hidden")))
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *);
// Actual unaligned old native offsets0x149/0x151 from the same response. The
// caller must use the separate IPA pure-transform profile1, not lifecycle
// profile0x16110001, and must still validate both fields. No maximum fallback.
__attribute__((visibility("hidden")))
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *);
#endif
