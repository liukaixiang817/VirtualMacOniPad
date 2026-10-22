#ifndef VM27_PRODUCTION_PAC_SERVICE_V16_H
#define VM27_PRODUCTION_PAC_SERVICE_V16_H
#include "modern_cpu_production_pac_batch_v14.h"
typedef struct { unsigned handled,ok,attempted,completed,syncNeeded; uint8_t policy; } VM27PACServiceResultV16;
/* Private, concrete Production owner only. An unready bank performs no writes
 * and returns unhandled so the existing real native8 synchronization runs. */
__attribute__((visibility("hidden"))) VM27PACServiceResultV16
VM27ProductionPACServiceV16(uintptr_t,uint32_t,uint32_t);
#endif
