#include "modern_cpu_native_public_factory_v20.h"
/* Include the frozen owner registry exactly once. Only the old public
 * feature getter is renamed; no second registry or fabricated context. */
#define hv_vcpu_config_get_feature_reg VM27CPUInheritedFeatureGetterV19
#include "modern_cpu_native_public_factory_v19.c"
#undef hv_vcpu_config_get_feature_reg
#include "modern_cpu_native_public_factory_features_v20.inc"
