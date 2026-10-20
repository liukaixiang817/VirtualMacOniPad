#include "vm27_hv_public_vm_bootstrap_v14.h"
#include "modern_cpu_ram_host_input_v52.h"
#include "modern_cpu_ram_task_scope_v53.h"
#include "modern_cpu_ram_range_v54.h"
#include <errno.h>
#include <stdio.h>
__attribute__((visibility("hidden"))) __typeof__(hv_vm_map) VM27HVVMInheritedMapV25;
#define hv_vm_map VM27HVVMInheritedMapV25
__attribute__((visibility("hidden"))) __typeof__(hv_vm_unmap) VM27HVVMInheritedUnmapV27;
__attribute__((visibility("hidden"))) __typeof__(hv_vm_protect) VM27HVVMInheritedProtectV27;
#define hv_vm_unmap VM27HVVMInheritedUnmapV27
#define hv_vm_protect VM27HVVMInheritedProtectV27
#include "vm27_hv_public_vm_bootstrap_v24.m"
#undef hv_vm_unmap
#undef hv_vm_protect
#undef hv_vm_map

static _Atomic unsigned VM27MapFailureLogsV25;
static hv_return_t MapResultV25(const char *stage,const void *host,hv_ipa_t ipa,
 size_t bytes,hv_return_t result,bool nativeInvoked) {
 if(!result)return result;
 int savedErrno=errno;
 unsigned count=atomic_load_explicit(&VM27MapFailureLogsV25,memory_order_relaxed);
 while(count<8 && !atomic_compare_exchange_weak_explicit(&VM27MapFailureLogsV25,
  &count,count+1,memory_order_relaxed,memory_order_relaxed)){}
 if(count<8)dprintf(2,"[Independent27HV] failed stage=vm-map-%s ordinal=%u host=%p GPA=0x%llx bytes=0x%zx status=0x%08x nativeInvoked=%u\n",
  stage,count+1,host,(unsigned long long)ipa,bytes,(unsigned)result,nativeInvoked);
 errno=savedErrno;return result;
}
// Caller-owned host input is distinct from an output publication target.
// Preserve every Bootstrap control/config/MapEntry exclusion while allowing
// existing MapEntry host data to be re-used at another disjoint guest IPA.
bool VM27HVVMRAMHostInputRangeDisjointV26(const void *host,size_t bytes) {
 Lock();bool valid=host && bytes && bytes<=UINTPTR_MAX-(uintptr_t)host &&
  Disjoint(host,bytes,&Backend,sizeof(Backend)) && Disjoint(host,bytes,&Admission,sizeof(Admission)) &&
  Disjoint(host,bytes,&NextGeneration,sizeof(NextGeneration)) &&
  Disjoint(host,bytes,&Configs,sizeof(Configs)) && Disjoint(host,bytes,&Maps,sizeof(Maps)) &&
  Disjoint(host,bytes,&Mutex,sizeof(Mutex));
 for(ConfigEntry *entry=Configs;entry && valid;entry=entry->next)
  valid=Disjoint(host,bytes,entry,sizeof(*entry)) && Disjoint(host,bytes,entry->object,64);
 for(MapEntry *entry=Maps;entry && valid;entry=entry->next)
  valid=Disjoint(host,bytes,entry,sizeof(*entry));
 Unlock();return valid;
}
// Admission pins this installed backend through the real Factory/Kernel
// registry checks. VM/config lifecycle keeps its original creator owner.
static hv_return_t MapRAMTaskBeforeLockV27(VM27CPUFactoryVMV2 **out) {
 Lock();bool valid=Backend.installed && Backend.vm && !Backend.vmDestroyed &&
  atomic_load_explicit(&Admission,memory_order_relaxed) &&
  Backend.ops.schemaVersion==1 && Backend.ops.validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  Backend.ops.context && Backend.ops.nativeTrap && Backend.ops.currentThread && Backend.ops.readMemory &&
  Backend.writer.writeMemory && Backend.writer.context==Backend.ops.context;
 VM27CPUFactoryVMV2 *vm=valid?Backend.vm:NULL;Unlock();
 if(!valid)return Error(3);
 hv_return_t status=VM27CPUFactoryRAMTaskScopeV8(vm);if(!status)*out=vm;return status;
}
hv_return_t hv_vm_map(void *host,hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {
    if (!VM27CPUFactoryRAMHostInputRangeDisjointV7(host,bytes)) return MapResultV25("host-range",host,ipa,bytes,Error(3),false);
    VZKernelMemoryPacket packet;
    if (VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,VZKernelMemoryMap,
        (uintptr_t)host,ipa,bytes,flags,0,&packet)) return MapResultV25("packet",host,ipa,bytes,Error(3),false);
    if (!Begin()) return MapResultV25("admission",host,ipa,bytes,Error(2),false);
    VM27CPUFactoryVMV2 *vm = NULL; hv_return_t status = MapRAMTaskBeforeLockV27(&vm);
    if (status) { End(); return MapResultV25("vm-owner",host,ipa,bytes,status,false); }
    MapEntry *entry = calloc(1,sizeof(*entry));
    if (!entry) { End(); return MapResultV25("allocation",host,ipa,bytes,Error(5),false); }
    entry->host = host; entry->guestAddress = ipa; entry->bytes = bytes;
    VZKernelRAMResultV9 receipt = {0};
    status = VM27CPUFactoryRAMAdoptHostV9(vm,host,bytes,&entry->ram,&receipt);
    if (status) { free(entry); End(); return MapResultV25("adopt",host,ipa,bytes,status,receipt.nativeInvoked); }
    Lock(); entry->next = Maps; Maps = entry; Unlock();
    status = VM27CPUFactoryRAMMapV5(entry->ram,ipa,flags,&receipt);
    if (status && !receipt.nativeInvoked) {
        // Validation failure cannot have mapped guest RAM. Free only the own
        // handle; the caller retains its original host allocation throughout.
        entry->cleanupOnly = true;
        if (!VM27CPUFactoryRAMFreeV5(entry->ram)) RemoveMap(entry);
    }
    // Once native3 was invoked, even a failing return keeps the exact IPA
    // and caller-host lease until successful native4 and own-handle release.
    End(); return MapResultV25("map",host,ipa,bytes,status,receipt.nativeInvoked);
}

// The actual original VMM logs unmap errors and may then try a fresh map.
// Record only the first eight true range failures. Preserve errno and the
// actual public/native result; the interval transaction owns range semantics.
static _Atomic unsigned VM27DestructiveFailureLogsV27;
static hv_return_t DestructiveResultV27(const char *stage,hv_ipa_t ipa,size_t bytes,
 hv_return_t status,bool nativeInvoked,int32_t nativeReturn) {
 if(!status)return status;
 int savedErrno=errno;
 unsigned count=atomic_load_explicit(&VM27DestructiveFailureLogsV27,memory_order_relaxed);
 while(count<8 && !atomic_compare_exchange_weak_explicit(&VM27DestructiveFailureLogsV27,
  &count,count+1,memory_order_relaxed,memory_order_relaxed)){}
 if(count<8)dprintf(2,"[Independent27HV] failed stage=%s ordinal=%u GPA=0x%llx bytes=0x%zx status=0x%08x nativeInvoked=%u nativeReturn=%d\n",
  stage,count+1,(unsigned long long)ipa,bytes,(unsigned)status,nativeInvoked,nativeReturn);
 errno=savedErrno;return status;
}
// Native4/5 operate on exact caller ranges. The kernel interval ledger is
// authoritative; these MapEntry objects keep only caller-HVA/root ownership.
// A successful unmap never frees a caller allocation or a live reader root.
static hv_return_t RAMRangeChangeV28(VZKernelMemoryOperation operation,hv_ipa_t ipa,
 size_t bytes,hv_memory_flags_t flags) {
 const bool unmap=operation==VZKernelMemoryUnmap;const char *name=unmap?"vm-unmap":"vm-protect";
 VZKernelMemoryPacket packet;
 if(VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,operation,0,ipa,bytes,flags,0,&packet))
  return DestructiveResultV27(unmap?"vm-unmap-packet":"vm-protect-packet",ipa,bytes,Error(3),false,0);
 if(!Begin())return DestructiveResultV27(unmap?"vm-unmap-admission":"vm-protect-admission",ipa,bytes,Error(2),false,0);
 VM27CPUFactoryVMV2 *vm=NULL;hv_return_t status=MapRAMTaskBeforeLockV27(&vm);
 VZKernelRAMResultV9 receipt={0};
 if(!status)status=VM27CPUFactoryRAMRangeChangeV9(vm,operation,ipa,bytes,flags,&receipt);
 End();return DestructiveResultV27(name,ipa,bytes,status,receipt.nativeInvoked,receipt.nativeReturn);
}
hv_return_t hv_vm_unmap(hv_ipa_t ipa,size_t bytes) {
 return RAMRangeChangeV28(VZKernelMemoryUnmap,ipa,bytes,0);
}
hv_return_t hv_vm_protect(hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {
 return RAMRangeChangeV28(VZKernelMemoryProtect,ipa,bytes,flags);
}
