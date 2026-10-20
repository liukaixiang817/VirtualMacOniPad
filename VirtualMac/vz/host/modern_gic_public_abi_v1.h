#ifndef VM27_MODERN_GIC_PUBLIC_ABI_V1_H
#define VM27_MODERN_GIC_PUBLIC_ABI_V1_H
#include "modern_cpu_hv_public_abi_v3.h"
#if __has_include(<Hypervisor/hv_gic.h>)
#include <Hypervisor/hv_gic.h>
#include <Hypervisor/hv_gic_config.h>
#include <Hypervisor/hv_gic_parameters.h>
#include <Hypervisor/hv_gic_state.h>
#else
typedef struct vm27_own_gic_config_opaque *hv_gic_config_t;
typedef struct vm27_own_gic_state_opaque *hv_gic_state_t;
typedef uint16_t hv_gic_intid_t,hv_gic_distributor_reg_t,hv_gic_icc_reg_t;
typedef uint16_t hv_gic_ich_reg_t,hv_gic_icv_reg_t,hv_gic_msi_reg_t;
typedef uint32_t hv_gic_redistributor_reg_t;
#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V4_H
typedef uint64_t hv_ipa_t;
#endif
#ifdef __cplusplus
extern "C" {
#endif
hv_gic_config_t hv_gic_config_create(void);
hv_return_t hv_gic_config_set_distributor_base(hv_gic_config_t,hv_ipa_t);
hv_return_t hv_gic_config_set_redistributor_base(hv_gic_config_t,hv_ipa_t);
hv_return_t hv_gic_config_set_msi_region_base(hv_gic_config_t,hv_ipa_t);
hv_return_t hv_gic_config_set_msi_interrupt_range(hv_gic_config_t,uint32_t,uint32_t);
hv_return_t hv_gic_create(hv_gic_config_t);
hv_return_t hv_gic_set_spi(uint32_t,bool);
hv_return_t hv_gic_send_msi(hv_ipa_t,uint32_t);
hv_return_t hv_gic_get_distributor_reg(hv_gic_distributor_reg_t,uint64_t *);
hv_return_t hv_gic_set_distributor_reg(hv_gic_distributor_reg_t,uint64_t);
hv_return_t hv_gic_get_redistributor_base(hv_vcpu_t,hv_ipa_t *);
hv_return_t hv_gic_get_redistributor_reg(hv_vcpu_t,hv_gic_redistributor_reg_t,uint64_t *);
hv_return_t hv_gic_set_redistributor_reg(hv_vcpu_t,hv_gic_redistributor_reg_t,uint64_t);
hv_return_t hv_gic_get_icc_reg(hv_vcpu_t,hv_gic_icc_reg_t,uint64_t *);
hv_return_t hv_gic_set_icc_reg(hv_vcpu_t,hv_gic_icc_reg_t,uint64_t);
hv_return_t hv_gic_get_ich_reg(hv_vcpu_t,hv_gic_ich_reg_t,uint64_t *);
hv_return_t hv_gic_set_ich_reg(hv_vcpu_t,hv_gic_ich_reg_t,uint64_t);
hv_return_t hv_gic_get_icv_reg(hv_vcpu_t,hv_gic_icv_reg_t,uint64_t *);
hv_return_t hv_gic_set_icv_reg(hv_vcpu_t,hv_gic_icv_reg_t,uint64_t);
hv_return_t hv_gic_get_msi_reg(hv_gic_msi_reg_t,uint64_t *);
hv_return_t hv_gic_set_msi_reg(hv_gic_msi_reg_t,uint64_t);
hv_return_t hv_gic_get_distributor_size(size_t *);
hv_return_t hv_gic_get_distributor_base_alignment(size_t *);
hv_return_t hv_gic_get_redistributor_region_size(size_t *);
hv_return_t hv_gic_get_redistributor_size(size_t *);
hv_return_t hv_gic_get_redistributor_base_alignment(size_t *);
hv_return_t hv_gic_get_msi_region_size(size_t *);
hv_return_t hv_gic_get_msi_region_base_alignment(size_t *);
hv_return_t hv_gic_get_spi_interrupt_range(uint32_t *,uint32_t *);
hv_return_t hv_gic_get_intid(hv_gic_intid_t,uint32_t *);
hv_return_t hv_gic_reset(void);
hv_return_t hv_gic_set_state(const void *,size_t);
hv_gic_state_t hv_gic_state_create(void);
hv_return_t hv_gic_state_get_size(hv_gic_state_t,size_t *);
hv_return_t hv_gic_state_get_data(hv_gic_state_t,void *);
#ifdef __cplusplus
}
#endif
#endif
#ifdef __cplusplus
static_assert(sizeof(hv_gic_intid_t)==2 && sizeof(hv_gic_icc_reg_t)==2 &&
#else
_Static_assert(sizeof(hv_gic_intid_t)==2 && sizeof(hv_gic_icc_reg_t)==2 &&
#endif
 sizeof(hv_gic_distributor_reg_t)==2 && sizeof(hv_gic_redistributor_reg_t)==4,"SDK GIC selector widths");
#endif
