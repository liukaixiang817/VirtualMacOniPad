#ifndef VM27_VMM_AMX_AVAILABILITY_V1_H
#define VM27_VMM_AMX_AVAILABILITY_V1_H
#include "modern_cpu_native_public_factory_v6.h"
/* A successful metadata query writes ABSENT(0) or PRESENT(1). Errors do not
 * write the output. This does not initialize, emulate, or execute AMX state. */
VM27CPUFactoryMachStatusV2 VM27VMMGetAMXAvailabilityV1(hv_vcpu_t, uint32_t *);
#endif
