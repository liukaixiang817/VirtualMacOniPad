#ifndef VM27_MODERN_CPU_OPTIONAL_ABI_V1_H
#define VM27_MODERN_CPU_OPTIONAL_ABI_V1_H
#include "modern_cpu_hv_public_abi_v2.h"
#if __has_include(<Hypervisor/hv_sme_config.h>)
#include <Hypervisor/hv_sme_config.h>
#else
typedef struct { bool streaming_sve_mode_enabled; bool za_storage_enabled; } hv_vcpu_sme_state_t;
typedef uint32_t hv_sme_z_reg_t, hv_sme_p_reg_t;
typedef uint8_t hv_sme_zt0_uchar64_t __attribute__((ext_vector_type(64)));
#ifdef __cplusplus
extern "C" {
#endif
hv_return_t hv_sme_config_get_max_svl_bytes(size_t *);
hv_return_t hv_vcpu_get_sme_state(hv_vcpu_t,hv_vcpu_sme_state_t *);
hv_return_t hv_vcpu_set_sme_state(hv_vcpu_t,const hv_vcpu_sme_state_t *);
hv_return_t hv_vcpu_get_sme_z_reg(hv_vcpu_t,hv_sme_z_reg_t,uint8_t *,size_t);
hv_return_t hv_vcpu_set_sme_z_reg(hv_vcpu_t,hv_sme_z_reg_t,const uint8_t *,size_t);
hv_return_t hv_vcpu_get_sme_p_reg(hv_vcpu_t,hv_sme_p_reg_t,uint8_t *,size_t);
hv_return_t hv_vcpu_set_sme_p_reg(hv_vcpu_t,hv_sme_p_reg_t,const uint8_t *,size_t);
hv_return_t hv_vcpu_get_sme_za_reg(hv_vcpu_t,uint8_t *,size_t);
hv_return_t hv_vcpu_set_sme_za_reg(hv_vcpu_t,const uint8_t *,size_t);
hv_return_t hv_vcpu_get_sme_zt0_reg(hv_vcpu_t,hv_sme_zt0_uchar64_t *);
hv_return_t hv_vcpu_set_sme_zt0_reg(hv_vcpu_t,const hv_sme_zt0_uchar64_t *);
#ifdef __cplusplus
}
#endif
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Private ABI shapes captured from the original macOS27 wrappers and callers. */
hv_return_t _hv_capability(uint32_t,uint64_t *);
hv_return_t _hv_vcpu_amx_prepare(hv_vcpu_t);
hv_return_t _hv_vcpu_amx_query_active_context(hv_vcpu_t,bool *);
hv_return_t _hv_vcpu_get_amx_state_t_el1(hv_vcpu_t,uint64_t *);
hv_return_t _hv_vcpu_set_amx_state_t_el1(hv_vcpu_t,uint64_t);
hv_return_t _hv_vcpu_get_amx_x_space(hv_vcpu_t,void *);
hv_return_t _hv_vcpu_set_amx_x_space(hv_vcpu_t,const void *);
hv_return_t _hv_vcpu_get_amx_y_space(hv_vcpu_t,void *);
hv_return_t _hv_vcpu_set_amx_y_space(hv_vcpu_t,const void *);
hv_return_t _hv_vcpu_get_amx_z_space(hv_vcpu_t,void *);
hv_return_t _hv_vcpu_set_amx_z_space(hv_vcpu_t,const void *);
void *_hv_vcpu_get_context(hv_vcpu_t);
/* Hidden, defined inside the one Factory translation unit, never a second registry. */
__attribute__((visibility("hidden"))) hv_return_t VM27CPUFactoryRefuseOptionalFeatureV1(hv_vcpu_t);
#ifdef __cplusplus
}
#endif
#endif
