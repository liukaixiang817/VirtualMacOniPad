// Alternative translation unit: the frozen Root4 VM/RAM implementation is
// included unchanged and linked with Factory11/Lifecycle13 instead of9/11.
#include "vm27_hv_public_vm_bootstrap_v5.h"
#include "vm27_hv_public_vm_bootstrap_v4.m"
_Static_assert(sizeof(hv_return_t)==4 && sizeof(uint32_t)==4,"Actual max-vCPU SDK ABI");
hv_return_t hv_vm_get_max_vcpu_count(uint32_t *out) {
 // Original27 0x2d00..0x2d10: mov w8,64; str w8,[x0]; mov w0,0; ret.
 // The reciprocal exclusions additionally protect own VM/CPU/config/RAM and
 // actual native contexts. No capability query or native operation occurs.
 if(!OutputBeforeLock(out,sizeof(*out)) ||
  !VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)))return Error(3);
 Lock();hv_return_t status=OutputLocked(out,sizeof(*out))?0:Error(3);
 if(!status)*out=UINT32_C(64);
 Unlock();return status;
}
