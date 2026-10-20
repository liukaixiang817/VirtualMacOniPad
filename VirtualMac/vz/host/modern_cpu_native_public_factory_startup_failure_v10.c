/* Factory9 implementation whole; only its public vtimer wrapper is observed. */
#include "modern_cpu_native_public_factory_v22.h"
__attribute__((visibility("hidden"))) __typeof__(hv_vcpu_set_vtimer_offset) VM27InheritedSetVtimerOffsetV10;
#define hv_vcpu_set_vtimer_offset VM27InheritedSetVtimerOffsetV10
#include "modern_cpu_native_public_factory_startup_failure_v9.c"
#undef hv_vcpu_set_vtimer_offset
#include "modern_cpu_native_public_factory_vtimer_public_v11.inc"
