#ifndef VM27_MODERN_CPU_HV_PUBLIC_ABI_V2_H
#define VM27_MODERN_CPU_HV_PUBLIC_ABI_V2_H
// Prevent inherited Factory6 headers from reintroducing the old C++ fallback.
#define VM27_MODERN_CPU_HV_PUBLIC_ABI_V1_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#if __has_include(<Hypervisor/hv_vcpu.h>)
#include <Hypervisor/hv_vcpu.h>
#include <Hypervisor/hv_vcpu_config.h>
#else
typedef int32_t hv_return_t;
typedef uint64_t hv_vcpu_t;
typedef uint32_t hv_reg_t,hv_simd_fp_reg_t;
typedef uint16_t hv_sys_reg_t;
typedef unsigned char hv_simd_fp_uchar16_t __attribute__((ext_vector_type(16)));
typedef struct vm27_own_config_opaque *hv_vcpu_config_t;
typedef struct {uint32_t reason,reserved;struct{uint64_t syndrome,virtual_address,physical_address;}exception;}hv_vcpu_exit_t;
typedef uint32_t hv_feature_reg_t;
#ifdef __cplusplus
extern "C" {
#endif
hv_vcpu_config_t hv_vcpu_config_create(void);
hv_return_t hv_vcpu_create(hv_vcpu_t *,hv_vcpu_exit_t **,hv_vcpu_config_t);
hv_return_t hv_vcpu_destroy(hv_vcpu_t);
hv_return_t hv_vcpu_set_reg(hv_vcpu_t,hv_reg_t,uint64_t);
hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t,hv_simd_fp_reg_t,hv_simd_fp_uchar16_t);
hv_return_t hv_vcpu_get_reg(hv_vcpu_t,hv_reg_t,uint64_t *);
hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t,hv_simd_fp_reg_t,hv_simd_fp_uchar16_t *);
hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t,hv_sys_reg_t,uint64_t *);
hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t,hv_sys_reg_t,uint64_t);
hv_return_t hv_vcpu_config_get_feature_reg(hv_vcpu_config_t,hv_feature_reg_t,uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
#endif
