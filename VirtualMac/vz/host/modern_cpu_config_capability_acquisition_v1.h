#ifndef VM27_CPU_CONFIG_CAPABILITY_ACQUISITION_V1_H
#define VM27_CPU_CONFIG_CAPABILITY_ACQUISITION_V1_H
#include "modern_cpu_tlbi_capability_values_v1.h"
// Private source boundary. Only this module acquires the actual input; a caller
// cannot submit a fabricated receipt to authorize a true configuration bit.
// One op0 attempt per process. UNKNOWN remains UNKNOWN, without a retry/default.
__attribute__((visibility("hidden")))
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *);
#endif
