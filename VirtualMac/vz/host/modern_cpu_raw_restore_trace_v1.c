/* Observe only existing calls from the original owned VMM raw-HV thunk.
 * The exact same -5 trap runs once in the original process/thread. No packet
 * content, guest memory, key data, permissions or kernel configuration changes. */
#include "modern_cpu_optional_abi_v1.h"
__attribute__((visibility("hidden"))) __typeof__(_hv_capability) VM27InheritedCapabilityRawTraceV1;
#define _hv_capability VM27InheritedCapabilityRawTraceV1
#include "modern_cpu_optional_abi_v1.c"
#undef _hv_capability
#include "vm27_actual_executable_image_v1.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <ptrauth.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
static const char RawMainPathV1[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static pthread_once_t RawOnceV1=PTHREAD_ONCE_INIT;
static uintptr_t RawBaseV1;
static _Atomic unsigned RawLogsV1[32];
static void RawIdentityV1(void) {
 static const uint8_t uuid[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
 VM27ActualExecutableImageV1 image={0};
 if(getuid()==501 && !VM27ActualExecutableImageFindV1(RawMainPathV1,&image) &&
  !memcmp(image.uuid,uuid,16))RawBaseV1=(uintptr_t)image.header;
}
static bool RawCallerV1(uintptr_t caller) {
 pthread_once(&RawOnceV1,RawIdentityV1);
 if(!RawBaseV1 || caller<RawBaseV1+0x2154 || caller>=RawBaseV1+0x410524 ||
  !VM27CPUSelfMappedRangeV1((void *)(caller-4),4,false,NULL))return false;
 uint32_t instruction;memcpy(&instruction,(void *)(caller-4),4);
 if((instruction&UINT32_C(0xfc000000))!=UINT32_C(0x94000000))return false;
 int64_t displacement=(int64_t)(int32_t)(instruction<<6)>>4;
 return caller-4+displacement==RawBaseV1+0x3a59a4;
}
__attribute__((visibility("hidden"))) hv_return_t VM27OwnedRawHVPassV1(uint32_t,void *);
hv_return_t _hv_capability(uint32_t selector,uint64_t *packet) {
 int incomingErrno=errno;
 uintptr_t caller=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
 bool rawCaller=RawCallerV1(caller);errno=incomingErrno;
 if(!rawCaller)return VM27InheritedCapabilityRawTraceV1(selector,packet);
 hv_return_t status=VM27OwnedRawHVPassV1(selector,packet);
 if(status) {
  int saved=errno;_Atomic unsigned *budget=&RawLogsV1[selector<32?selector:31];
  unsigned count=atomic_load_explicit(budget,memory_order_relaxed);
  while(count<2 && !atomic_compare_exchange_weak_explicit(budget,&count,count+1,memory_order_relaxed,memory_order_relaxed)){}
  if(count<2)dprintf(2,"[VM27RawRestoreTraceV1] pid=%d op=%u callerRVA=0x%lx status=0x%08x originalTrapOnce=1 packetRead=0\n",
   getpid(),selector,(unsigned long)(caller-RawBaseV1),(unsigned)status);
  errno=saved;
 }
 return status;
}
