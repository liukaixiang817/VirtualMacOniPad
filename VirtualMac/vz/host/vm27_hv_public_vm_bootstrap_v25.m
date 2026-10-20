#include "vm27_hv_public_vm_bootstrap_v14.h"
#include <errno.h>
#include <stdio.h>
__attribute__((visibility("hidden"))) __typeof__(hv_vm_map) VM27HVVMInheritedMapV25;
#define hv_vm_map VM27HVVMInheritedMapV25
#include "vm27_hv_public_vm_bootstrap_v24.m"
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
hv_return_t hv_vm_map(void *host,hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {
    if (!OutputBeforeLock(host,bytes)) return MapResultV25("host-range",host,ipa,bytes,Error(3),false);
    VZKernelMemoryPacket packet;
    if (VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,VZKernelMemoryMap,
        (uintptr_t)host,ipa,bytes,flags,0,&packet)) return MapResultV25("packet",host,ipa,bytes,Error(3),false);
    if (!Begin()) return MapResultV25("admission",host,ipa,bytes,Error(2),false);
    VM27CPUFactoryVMV2 *vm = NULL; hv_return_t status = MapVMBeforeLock(&vm);
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
