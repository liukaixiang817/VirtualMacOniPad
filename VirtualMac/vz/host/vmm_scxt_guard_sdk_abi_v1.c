#include <Hypervisor/Hypervisor.h>
#include "modern_vmm_scxt_state_guard_v1.h"
_Static_assert(sizeof(hv_vcpu_t) == 8 && sizeof(hv_sys_reg_t) == 2 && sizeof(hv_return_t) == 4, "genuine LP64 public SYS ABI");
_Static_assert(HV_SYS_REG_SCXTNUM_EL0 == VM27_VMM_SCXT_EL0_V1 && HV_SYS_REG_SCXTNUM_EL1 == VM27_VMM_SCXT_EL1_V1, "genuine SDK SCXT names");
// Actual compiler assignments verify the callback types without casts.
VM27VMMGetSYSV1 VM27VMMSCXTSDKGetV1 = hv_vcpu_get_sys_reg;
VM27VMMSetSYSV1 VM27VMMSCXTSDKSetV1 = hv_vcpu_set_sys_reg;
hv_return_t VM27VMMSCXTSDKCallV1(hv_vcpu_t cpu, uint64_t value, uint64_t *out) {
    hv_return_t result = hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_SCXTNUM_EL0, out);
    return result ? result : hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_SCXTNUM_EL1, value);
}
