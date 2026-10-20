#ifndef VM27_HV_PUBLIC_VM_BOOTSTRAP_V2_H
#define VM27_HV_PUBLIC_VM_BOOTSTRAP_V2_H
#include "vm27_hv_public_vm_bootstrap_v1.h"
#include "modern_cpu_native_public_factory_v9.h"
#ifdef __cplusplus
extern "C" {
#endif
#if !__has_include(<Hypervisor/hv_vm.h>)
typedef uint64_t hv_ipa_t,hv_memory_flags_t;
hv_return_t hv_vm_map(void *,hv_ipa_t,size_t,hv_memory_flags_t);
hv_return_t hv_vm_unmap(hv_ipa_t,size_t);
hv_return_t hv_vm_protect(hv_ipa_t,size_t,hv_memory_flags_t);
#endif
// This source profile supports whole registered 16KiB ranges, default space,
// 36bitIPA, flags0..7 and actual writable self-task host memory. The caller
// retains host backing until successful unmap; partial ranges are refused.
// CPU handles must be destroyed before mapping changes. These restrictions
// are explicit and are not evidence of complete original VMM map behavior.
#ifdef __cplusplus
}
#endif
#endif
