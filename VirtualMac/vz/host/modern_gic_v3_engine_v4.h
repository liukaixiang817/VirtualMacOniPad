#ifndef VM27_GIC_V3_ENGINE_V4_H
#define VM27_GIC_V3_ENGINE_V4_H
#include "modern_gic_v3_engine_v2.h"
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICHasWakePendingV30(
 VM27GICV3V1 *,const VZKernelRunPendingRequestV14 *,bool *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICRouteVirtualTimerV35(
 void *,const VZKernelRunPendingRequestV14 *,bool,bool *);
#endif
