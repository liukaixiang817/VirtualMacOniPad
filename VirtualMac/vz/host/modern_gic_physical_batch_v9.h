#ifndef VM27_GIC_PHYSICAL_BATCH_V9_H
#define VM27_GIC_PHYSICAL_BATCH_V9_H
#include "modern_gic_v3_engine_v5.h"
typedef struct {bool irq,routeComplete,deadlineAttempted;} VM27GICPhysicalBatchResultV9;
typedef VZKernelStatus (*VM27GICPhysicalBoundaryV9)(void *);
/* Only the concrete GIC binding uses this path. It combines IRQ arbitration
 * and the deadline callback lifetime pin in one mutex acquisition. The native
 * ownership boundary and the real scheduler still run with the mutex dropped. */
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICRouteAndDeadlineV9(
 void *,const VZKernelRunPendingRequestV14 *,bool,bool,uint64_t,
 VM27GICPhysicalBoundaryV9,void *,VM27GICPhysicalBatchResultV9 *);
#endif
