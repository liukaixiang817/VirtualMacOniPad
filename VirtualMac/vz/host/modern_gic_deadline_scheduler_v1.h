#ifndef VM27_MODERN_GIC_DEADLINE_SCHEDULER_V1_H
#define VM27_MODERN_GIC_DEADLINE_SCHEDULER_V1_H
#include "modern_cpu_kernel_lifecycle_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VM27GICDeadlineSchedulerV1 VM27GICDeadlineSchedulerV1;
typedef struct {
 void *clockContext,*wakeContext;
 bool (*readCounter)(void *,uint64_t *);
 bool (*readFrequency)(void *,uint64_t *);
 VZKernelStatus (*wakeCPU)(void *,const VZKernelRunPendingRequestV14 *);
} VM27GICDeadlineBindingsV1;
// VM owner creates/destroys. Per-CPU arm/drain must run on that CPU's actual
// owner pthread. The actual factory validates the identity before each call.
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDeadlineCreateV1(
 uint64_t,const VM27GICDeadlineBindingsV1 *,VM27GICDeadlineSchedulerV1 **);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDeadlineDestroyV1(VM27GICDeadlineSchedulerV1 *);
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDeadlineScheduleV1(
 void *,const VZKernelRunPendingRequestV14 *,bool,uint64_t);
// Permanent gate closure, dispatch cancellation handler and in-flight drain
// must all succeed before freeing an entry. Timeout returns BUSY and retains it.
__attribute__((visibility("hidden"))) VZKernelStatus VM27GICDeadlineDrainV1(
 void *,const VZKernelRunPendingRequestV14 *);
__attribute__((visibility("hidden"))) bool VM27GICDeadlineOutputDisjointV1(
 VM27GICDeadlineSchedulerV1 *,const void *,size_t);
#ifdef __cplusplus
}
#endif
#endif
