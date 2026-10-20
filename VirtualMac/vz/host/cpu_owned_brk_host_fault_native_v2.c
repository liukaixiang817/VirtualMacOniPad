// Mac-only end-to-end fault injection for the inert BRK executable source.
// Every native operation and capability is mocked. This file is never linked
// into the iOS candidate and cannot establish an instruction or device result.
#include "vm27_hv_public_vm_bootstrap_v4.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static unsigned char *Context;
static bool VM,CPU,Mapped;
static unsigned Calls[10];
static void *Host;
static uint64_t Owner;
static const char *Mode(void){const char *m=getenv("VM27_BRK_HOST_MODE");return m?m:"brk";}
static bool Is(const char *value){return !strcmp(Mode(),value);}
static void Need(bool value,const char *meaning){if(!value){fprintf(stderr,"HOST_FAULT_ASSERT %s\n",meaning);abort();}}
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *out){*out=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *out){*out=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out){*out=(VM27CPUTLBICapabilityValueV1){0};}
int32_t VM27OwnedBRKNativeTrapV1(uint64_t operation,void *arguments){
 uint64_t thread=0;Need(!pthread_threadid_np(NULL,&thread),"actual thread");
 if(!Owner)Owner=thread;Need(thread==Owner,"one owner");
 Need(operation>=1&&operation<=9&&operation!=5&&Calls[operation]++==0,"no operation retry");
 if(operation==1){VZKernelNativeVMConfig *q=arguments;Need(!VM&&q&&q->ipaLimit==(UINT64_C(1)<<36)&&q->nativeHVISA==2,"true ISA2 packet");VM=true;return 0;}
 if(operation==3||operation==4){VZKernelMemoryPacket *q=arguments;Need(VM&&!CPU&&q&&q->guestAddress==0x40000000&&q->bytes==0x4000&&!q->spaceWord,"true default memory packet");
  if(operation==3){Need(q->hostAddress&&q->flags==5,"caller host flags5");Host=(void *)(uintptr_t)q->hostAddress;if(Is("map-failure"))return -17;Mapped=true;}
  else {Need(!q->hostAddress&&!q->flags,"unmap zero packet");if(Is("unmap-failure"))return -17;Mapped=false;}return 0;}
 if(operation==6){Need(VM&&Mapped&&!CPU&&arguments&&!((uint64_t *)arguments)[0]&&!((uint64_t *)arguments)[1],"native6 exact zero packet");
  Context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);Need(Context!=MAP_FAILED,"own self-task context mock");
  uint64_t version=Is("version-failure")?0:VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(Context+0x4000,&version,8);
  uint64_t marker=UINT64_C(0x1234000000000000);memcpy(Context+0x748,&marker,8);
  ((uint64_t *)arguments)[1]=(uintptr_t)Context;CPU=true;return 0;}
 if(operation==8){Need(CPU&&!arguments,"native8 NULL on own CPU");if(Is("sync-failure"))return -17;
  uint64_t ready=1;memcpy(Context+0x4100,&ready,8);
  if(Is("stale-sync-brk")){uint32_t reason=1,syndrome=0xf2000000;uint64_t address=0x40000000;
   memcpy(Context+0x4008,&reason,4);memcpy(Context+0x400c,&syndrome,4);
   memcpy(Context+0x4018,&address,8);memcpy(Context+0x4020,&address,8);}
  return 0;}
 if(operation==9){Need(CPU&&Mapped&&!arguments,"one native9 NULL");uint64_t pc=0,sctlr=0;uint32_t cpsr=0;
  memcpy(&pc,Context+0x108,8);memcpy(&sctlr,Context+0x400,8);memcpy(&cpsr,Context+0x110,4);
  Need(pc==0x40000000&&sctlr==0x30800180&&cpsr==0x3c5,"typed native states actually committed");
  for(size_t i=0;i<0x4000/4;++i)Need(((uint32_t *)Host)[i]==0xd4200000,"real own leased page unchanged");
  if(Is("run-failure"))return -17;
  uint32_t reason=Is("raw11")?11:Is("unknown")?0:1,syndrome=Is("wrong-syndrome")?0:0xf2000000;
  memcpy(Context+0x4008,&reason,4);memcpy(Context+0x400c,&syndrome,4);
  uint64_t va=0x40000000,ipa=0x40000000;memcpy(Context+0x4018,&va,8);memcpy(Context+0x4020,&ipa,8);return 0;}
 if(operation==7){Need(CPU&&!arguments,"owner native7 NULL");if(Is("cpu-destroy-failure"))return -17;
  Need(!munmap(Context,0x8000),"free native mock only after7 success");Context=NULL;CPU=false;return 0;}
 if(operation==2){Need(VM&&!CPU&&!Mapped&&!arguments,"native2 after cleanup");if(Is("vm-destroy-failure"))return -17;VM=false;return 0;}
 abort();
}
