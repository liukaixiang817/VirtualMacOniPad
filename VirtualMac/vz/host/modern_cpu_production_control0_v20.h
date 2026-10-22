#ifndef VM27_PRODUCTION_CONTROL0_V20_H
#define VM27_PRODUCTION_CONTROL0_V20_H
#include "modern_cpu_kernel_initialization.h"
typedef struct { bool handled; VZKernelInitReceipt receipt; } VM27Control0ResultV20;
/* Private concrete-owner transaction. Refusal performs no writes and selects
 * the original callback engine. The result reports actual engine operations. */
__attribute__((visibility("hidden"))) VM27Control0ResultV20
VM27ProductionControl0V20(uintptr_t, uint32_t, uint64_t);
#endif
