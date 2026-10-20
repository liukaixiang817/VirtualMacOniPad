#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V1_H
#define VM27_HV_PUBLIC_VM_BOOTSTRAP_V1_H
#include "modern_cpu_native_public_factory_v7.h"
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
hv_vm_config_t hv_vm_config_create(void);
hv_return_t hv_vm_config_get_max_ipa_size(uint32_t *);
hv_return_t hv_vm_config_get_default_ipa_size(uint32_t *);
hv_return_t hv_vm_config_set_ipa_size(hv_vm_config_t, uint32_t);
hv_return_t hv_vm_config_get_ipa_size(hv_vm_config_t, uint32_t *);
hv_return_t hv_vm_config_set_ipa_granule(hv_vm_config_t, hv_ipa_granule_t);
hv_return_t hv_vm_config_set_el2_enabled(hv_vm_config_t, bool);
hv_return_t hv_vm_create(hv_vm_config_t);
hv_return_t hv_vm_destroy(void);
#endif
// Real original private two-argument ABI; native ISA namespace, not serialized ISA.
hv_return_t __hv_vm_config_set_isa(hv_vm_config_t, uint32_t);
hv_return_t __hv_vm_config_set_vhe_enabled(hv_vm_config_t, bool);
// Strongly link reciprocal guard support in NEW Factory7. NativeOps/context
// must remain alive until explicit uninstall; no copied foreign HV pointers.
hv_return_t VM27HVVMInstallNativeOpsV1(const VZKernelLifecycleOps *, const VZKernelInitWriter *);
hv_return_t VM27HVVMUninstallNativeOpsV1(void);
// Guard lock order is Factory registry -> this registry. This helper takes
// only its own mutex and never invokes a callback or CPU/config guard.
__attribute__((visibility("hidden")))
bool VM27HVVMOutputRangeDisjointV1(const void *, size_t);
__attribute__((visibility("hidden")))
bool VM27CPUFactoryVMOutputGuardLinkedV7(void);
// Get a real own RAM VM handle for the separate app-owned allocation path;
// only the native VM owner may borrow it. This is not public hv_vm_map.
hv_return_t VM27HVVMGetOwnedVMV1(VM27CPUFactoryVMV2 **);
#if VM27_HV_VM_TESTING
void VM27HVVMTestConfigCountsV1(uint64_t *, uint64_t *);
#endif
#ifdef __cplusplus
}
#endif
#endif
