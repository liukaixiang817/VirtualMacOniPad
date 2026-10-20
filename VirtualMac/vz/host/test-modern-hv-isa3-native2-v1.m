#include "vm27_hv_public_vm_bootstrap_v24.m"
#include <assert.h>

int main(void) {
 OwnConfigStorage storage={0};ConfigEntry entry={0};
 entry.object=(id)&storage;entry.options=Defaults();Configs=&entry;
 hv_vm_config_t config=(hv_vm_config_t)(void *)&storage;
 assert(entry.options.nativeHVISA==1);
 assert(!_hv_vm_config_set_isa(config,3));
 assert(entry.options.nativeHVISA==2 && storage.options.nativeHVISA==2);
 assert(_hv_vm_config_set_isa(config,4)==Error(15));
 assert(entry.options.nativeHVISA==2 && storage.options.nativeHVISA==2);
 assert(!_hv_vm_config_set_isa(config,1) && entry.options.nativeHVISA==1);
 assert(!_hv_vm_config_set_isa(config,2) && entry.options.nativeHVISA==2);
 entry.inUse=true;
 assert(_hv_vm_config_set_isa(config,3)==Error(2));
 assert(entry.options.nativeHVISA==2);entry.inUse=false;
 assert(_hv_vm_config_set_isa((hv_vm_config_t)(uintptr_t)1,3)==Error(3));
 assert(_hv_vm_config_set_isa(config,0)==Error(15));
 assert(entry.options.ipaBits==36 && !entry.options.ipaGranule && !entry.options.el2Enabled && !entry.options.vheEnabled);
 Configs=NULL;
 puts("{\"actualInheritedConfigRegistrySetterExecuted\":true,\"modern3StoresNative2\":true,\"modern4UnsupportedUnchanged\":true,\"native1And2Preserved\":true,\"inUseAndForeignRegistryRefusalsPreserved\":true,\"otherConfigFieldsUnchanged\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");
 return 0;
}
