#ifndef VM27_PRODUCTION_PAC_SERVICE_V15_H
#define VM27_PRODUCTION_PAC_SERVICE_V15_H
#include "modern_cpu_production_pac_batch_v14.h"
typedef struct { unsigned handled,ok,attempted,completed; uint8_t policy; } VM27PACServiceResultV15;
/* Private, concrete Production owner only. An unready bank performs no writes
 * and returns unhandled so the existing real native8 synchronization runs. */
__attribute__((visibility("hidden"))) VM27PACServiceResultV15
VM27ProductionPACServiceV15(uintptr_t,uint32_t,uint32_t);
#endif
