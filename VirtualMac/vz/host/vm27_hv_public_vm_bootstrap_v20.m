// Preserve the complete Root19 backend, single registry, admission and owner.
// Only two public GIC base-alignment APIs replace hidden inherited definitions.
#include "vm27_hv_public_vm_bootstrap_v14.h"
#include "modern_gic_v3_engine_v2.h"
__attribute__((visibility("hidden"))) hv_return_t VM27GICInheritedRedistributorSetterV20(hv_gic_config_t,hv_ipa_t);
__attribute__((visibility("hidden"))) hv_return_t VM27GICInheritedRedistributorAlignmentV20(size_t *);
#define hv_gic_config_set_redistributor_base VM27GICInheritedRedistributorSetterV20
#define hv_gic_get_redistributor_base_alignment VM27GICInheritedRedistributorAlignmentV20
#include "vm27_hv_public_vm_bootstrap_v19.m"
#undef hv_gic_config_set_redistributor_base
#undef hv_gic_get_redistributor_base_alignment

hv_return_t hv_gic_config_set_redistributor_base(hv_gic_config_t object,hv_ipa_t value) {
 const uint64_t bytes=VM27_GIC_REDIST_BYTES_V1*VM27_GIC_CPUS_V1;
 const uint64_t alignment=VM27GICRedistributorBaseAlignmentV2();
 if((value&(alignment-1)) || value>(UINT64_C(1)<<36)-bytes)return Error(3);
 GICLockV9();GICConfigEntryV9 *e=GICFindConfigV9(object);
 hv_return_t status=!e?Error(3):e->inUse?Error(2):0;
 if(!status) {
  e->config.redistributorBase=value;e->fields|=2;
  e->config.msiConfigured=(e->fields&12)==12;GICCopyStorageV9(e);
 }
 GICUnlockV9();return status;
}
hv_return_t hv_gic_get_redistributor_base_alignment(size_t *out) {
 return GICSizeV9(out,VM27GICRedistributorBaseAlignmentV2());
}
