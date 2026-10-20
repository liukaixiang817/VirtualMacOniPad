#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V4_H
#define VM27_HV_PUBLIC_VM_BOOTSTRAP_V4_H
#include "modern_cpu_native_public_factory_v9.h"
#include "modern_cpu_config_capability_acquisition_v2.h"
#ifdef __cplusplus
extern "C" {
#endif
#if __has_include(<Hypervisor/hv_vm.h>)
#include <Hypervisor/hv_vm.h>
#include <Hypervisor/hv_vm_config.h>
#else
typedef struct vm27_own_vm_config_opaque *hv_vm_config_t;
typedef uint32_t hv_ipa_granule_t;
typedef uint64_t hv_ipa_t,hv_memory_flags_t;
hv_vm_config_t hv_vm_config_create(void);
hv_return_t hv_vm_config_get_max_ipa_size(uint32_t *);
hv_return_t hv_vm_config_get_default_ipa_size(uint32_t *);
hv_return_t hv_vm_config_set_ipa_size(hv_vm_config_t,uint32_t);
hv_return_t hv_vm_config_get_ipa_size(hv_vm_config_t,uint32_t *);
hv_return_t hv_vm_config_set_ipa_granule(hv_vm_config_t,hv_ipa_granule_t);
hv_return_t hv_vm_config_set_el2_enabled(hv_vm_config_t,bool);
hv_return_t hv_vm_create(hv_vm_config_t);
hv_return_t hv_vm_destroy(void);
hv_return_t hv_vm_map(void *,hv_ipa_t,size_t,hv_memory_flags_t);
hv_return_t hv_vm_unmap(hv_ipa_t,size_t);
hv_return_t hv_vm_protect(hv_ipa_t,size_t,hv_memory_flags_t);
#endif
// Actual Mach-O symbols are __hv_vm_config_set_* (two underscores). C source
// names have one. Earlier v1/v2 triple-underscore candidates remain inert and
// cannot resolve the original VMM's two private imports.
hv_return_t _hv_vm_config_set_isa(hv_vm_config_t,uint32_t);
hv_return_t _hv_vm_config_set_vhe_enabled(hv_vm_config_t,bool);
hv_return_t VM27HVVMInstallNativeOpsV1(const VZKernelLifecycleOps *,const VZKernelInitWriter *);
hv_return_t VM27HVVMUninstallNativeOpsV1(void);
// Owner-only borrowed handle; lifecycle remains exclusively hv_vm_destroy.
hv_return_t VM27HVVMGetOwnedVMV1(VM27CPUFactoryVMV2 **);
__attribute__((visibility("hidden")))
bool VM27HVVMOutputRangeDisjointV1(const void *,size_t);
__attribute__((visibility("hidden")))
bool VM27CPUFactoryVMOutputGuardLinkedV7(void);
#if VM27_HV_VM_TESTING
void VM27HVVMTestConfigCountsV1(uint64_t *,uint64_t *);
#endif
// Native ISA1/ISA2 use the validated lower context profiles. Default remains1.
// Default-space whole writable caller-owned16KiB ranges/36bitIPA/flags0..7.
// Caller must retain host backing through successful unmap after any failed
// native change. Mapping changes require no CPU handles. Partial ranges and
// complete original public Run semantics remain unimplemented in this profile.
#ifdef __cplusplus
}
#endif
#endif
