// Keep the real entire Factory24 path; only observe its returned failures.
#define _hv_vcpu_get_control_field VM27InheritedGetControlFailureV1
#define _hv_vcpu_set_control_field VM27InheritedSetControlFailureV1
#define hv_vcpu_get_sys_reg VM27InheritedGetSYSFailureV1
#define hv_vcpu_set_sys_reg VM27InheritedSetSYSFailureV1
#include "modern_cpu_native_public_factory_v24.c"
#undef _hv_vcpu_get_control_field
#undef _hv_vcpu_set_control_field
#undef hv_vcpu_get_sys_reg
#undef hv_vcpu_set_sys_reg
#include "modern_cpu_public_failure_diagnostic_v1.inc"
