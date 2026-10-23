#pragma once
#include "modern_gic_v3_engine_v1.h"
/* Versioned, pointer-free device state. CPU identities are rebound by affinity. */
__attribute__((visibility("hidden"))) size_t VM27GICStateBytesV1(void);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICStateTransferV1(
 VM27GICV3V1 *,void *,size_t,bool restore);
