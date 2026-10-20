#ifndef VM27_CPU_CONFIG_PRIVATE_ABI_V1_H
#define VM27_CPU_CONFIG_PRIVATE_ABI_V1_H
#include "modern_cpu_hv_public_abi_v2.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Original27 private setters receive the real hv_vcpu_config_t pointer and
 * an ABI-canonical bool in W1. They accept only the own registered OS object.
 * Configuration acceptance does not claim FGT/TLBI Run handling. */
hv_return_t _hv_vcpu_config_set_tlbi_workaround_enabled(hv_vcpu_config_t, bool);
hv_return_t _hv_vcpu_config_set_fgt_enabled(hv_vcpu_config_t, bool);
#ifdef __cplusplus
}
#endif
#endif
