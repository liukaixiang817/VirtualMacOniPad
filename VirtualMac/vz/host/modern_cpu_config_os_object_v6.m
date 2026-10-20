#include "modern_cpu_config_private_abi_v1.h"
/* Alternative translation unit: the frozen OS5 registry is included exactly
 * once. Link this instead of OS5, never alongside it. */
#include "modern_cpu_config_os_object_v5.m"

hv_return_t _hv_vcpu_config_set_tlbi_workaround_enabled(hv_vcpu_config_t config,
    bool enabled) {
    return (hv_return_t)VM27CPUConfigSetTLBIObjectV3((const void *)config, enabled);
}
hv_return_t _hv_vcpu_config_set_fgt_enabled(hv_vcpu_config_t config, bool enabled) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V3;
    EntryV3 *entry = FindObjectLocked((const void *)config);
    VM27CPUConfigHandleV3 handle = {(const void *)config, entry ? entry->generation : 0};
    Leave();
    /* The caller owns a real CF reference throughout this lookup and write.
     * A foreign pointer is never dereferenced to synthesize a handle. */
    return (hv_return_t)VM27CPUConfigSetFGTV3(handle, enabled ? 1u : 0u);
}
