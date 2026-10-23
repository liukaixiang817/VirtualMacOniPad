#ifndef VM27_PRODUCTION_CROSS_WAKE_V23_H
#define VM27_PRODUCTION_CROSS_WAKE_V23_H
#include "modern_cpu_kernel_lifecycle.h"
/* An optional concrete-provider read. False leaves the generic caller's
 * original mapping/read path intact; the output is unchanged on rejection. */
__attribute__((visibility("hidden"))) bool VM27ProductionWakeVersionReadV23(
    const VZKernelLifecycleOps *,const void *,uint64_t *);
#endif
