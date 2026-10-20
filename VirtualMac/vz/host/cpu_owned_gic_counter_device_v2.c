// A finite instruction/GIC/counter diagnostic. No kernel writes, disk image,
// guest OS, device installation or trust cache operation occurs in this file.
#include "vm27_hv_public_vm_bootstrap_v10.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include <CoreFoundation/CoreFoundation.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27OwnedBRKNativeTrapV1(uint64_t,void *);
extern const unsigned char VM27OwnedGICGuestStartV1[],VM27OwnedGICGuestBRKV1[],VM27OwnedGICGuestEndV1[];
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
extern void VM27HVVMTestConfigCountsV1(uint64_t *,uint64_t *);

#define PAGE_BYTES UINT64_C(0x4000)
#define GUEST_IPA UINT64_C(0x40000000)
#define DIST_IPA UINT64_C(0x10000000)
#define REDIST_IPA UINT64_C(0x20000000)
#define BRK_WORD UINT32_C(0xd4200000)
#define BRK_ESR UINT32_C(0xf2000000)
#define NATIVE_LIMIT 24u
#define FAIL ((int32_t)UINT32_C(0xfae94003))
typedef struct {
 void *context,*allocation,*host;
 size_t allocationBytes,guestBytes;
 uint64_t owner,returnedSlot;
 unsigned calls[10],reads,writes;
 atomic_uint wakes;
 bool vmExists,cpuExists,mapped,runArmed,writeFailed;
} ProbeGICV2;

static uint64_t OwnerThread(void *unused) {
 (void)unused;uint64_t value=0;
 return pthread_threadid_np(NULL,&value)?0:value;
}
static bool Profile(const char *name,const char *expected) {
 char value[128]={0};size_t bytes=sizeof(value);
 return !sysctlbyname(name,value,&bytes,NULL,0) && bytes && bytes<=sizeof(value) &&
  value[bytes-1]==0 && !strcmp(value,expected);
}
static bool OwnedRange(ProbeGICV2 *p,const void *address,size_t bytes) {
 uintptr_t base=(uintptr_t)p->context,value=(uintptr_t)address;
 // Native6 returns this exact user mapping, with length0x8000. Validate the
 // current mapping as well as the CPU/owner identity before every access.
 return p->cpuExists && base && OwnerThread(NULL)==p->owner && bytes && value>=base &&
  value-base<0x8000 && bytes<=0x8000-(value-base) &&
  VM27CPUSelfMappedRangeV1(address,bytes,false,NULL);
}
static bool Read(void *opaque,const void *address,size_t bytes,void *out) {
 ProbeGICV2 *p=opaque;
 if(!out || p->reads>=32768 || !OwnedRange(p,address,bytes))return false;
 ++p->reads;vm_size_t copied=0;
 return vm_read_overwrite(mach_task_self(),(vm_address_t)address,bytes,(vm_address_t)out,&copied)==0 && copied==bytes;
}
static bool Write(void *opaque,void *address,size_t bytes,const void *value) {
 ProbeGICV2 *p=opaque;
 if(!value || p->writeFailed || p->writes>=512 || !OwnedRange(p,address,bytes))return false;
 size_t offset=(uintptr_t)address-(uintptr_t)p->context;
 bool xreg=bytes==8 && offset>=8 && offset<=8+8*8 && !((offset-8)&7);
 bool allowed=xreg || (bytes==8 && (offset==0x108 || offset==0x400 || offset==0x3f0 ||
  offset==0x438 || offset==0x688 || offset==0x670 || offset==0x678 || offset==0x6a0 ||
  offset==0x6d0 || offset==0x6d8 || offset==0x6e0 || offset==0x6e8 || offset==0x748)) ||
  (bytes==4 && offset==0x110);
 if(!allowed)return false;
 uint64_t version=0;
 if(!Read(p,(unsigned char *)p->context+0x4000,8,&version) || version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION)return false;
 ++p->writes;kern_return_t status=vm_write(mach_task_self(),(vm_address_t)address,(vm_offset_t)value,(mach_msg_type_number_t)bytes);
 unsigned char copied[8];bool exact=!status && Read(p,address,bytes,copied) && !memcmp(copied,value,bytes);
 if(!exact)p->writeFailed=true;
 printf("{\"kind\":\"write\",\"offset\":%zu,\"bytes\":%zu,\"machStatus\":%d,\"readback\":%s}\n",offset,bytes,status,exact?"true":"false");
 return exact;
}
static bool CodeExact(ProbeGICV2 *p) {
 if(!p->host || !p->guestBytes || p->guestBytes>PAGE_BYTES || p->guestBytes%4)return false;
 if(memcmp(p->host,VM27OwnedGICGuestStartV1,p->guestBytes))return false;
 const uint32_t *words=p->host;
 for(size_t i=p->guestBytes/4;i<PAGE_BYTES/4;++i)if(words[i]!=BRK_WORD)return false;
 return true;
}
static int32_t Native(void *opaque,uint64_t op,void *arguments) {
 ProbeGICV2 *p=opaque;
 // A true scheduler wake may execute on its own thread. Lower Wake17 verifies
 // the actual retained CPU/VM/slot before entering this exact-mask boundary.
 if(op==10) {
  if(p->returnedSlot>=64 || (uintptr_t)arguments!=(UINT64_C(1)<<p->returnedSlot))return FAIL;
  unsigned n=atomic_load_explicit(&p->wakes,memory_order_relaxed);
  do {
   if(n>=NATIVE_LIMIT)return FAIL;
  }while(!atomic_compare_exchange_weak_explicit(&p->wakes,&n,n+1,
                                              memory_order_relaxed,memory_order_relaxed));
  unsigned ordinal=n+1;
  uint64_t actualThread=OwnerThread(NULL);
  printf("{\"kind\":\"nativeBegin\",\"operation\":10,\"ordinal\":%u,\"owner\":%llu,\"actualThread\":%llu,\"mask\":%llu}\n",ordinal,(unsigned long long)p->owner,(unsigned long long)actualThread,(unsigned long long)(uintptr_t)arguments);
  int32_t status=VM27OwnedBRKNativeTrapV1(op,arguments);
  printf("{\"kind\":\"nativeEnd\",\"operation\":10,\"ordinal\":%u,\"returnBits\":%u}\n",ordinal,(uint32_t)status);
  return status;
 }
 if(op<1 || op>9 || op==5 || OwnerThread(NULL)!=p->owner)return FAIL;
 if((op==8 || op==9)?p->calls[op]>=NATIVE_LIMIT:p->calls[op]!=0)return FAIL;
 if(op==1) {
  const VZKernelNativeVMConfig *q=arguments;
  if(p->vmExists || !q || q->reserved || q->ipaLimit!=(UINT64_C(1)<<36) || q->ipaGranule ||
   q->reserved20 || q->nativeHVISA!=2 || q->reserved28)return FAIL;
 }else if(op==3 || op==4) {
  const VZKernelMemoryPacket *q=arguments;
  if(!p->vmExists || p->cpuExists || !q || q->hostAddress!=(op==3?(uintptr_t)p->host:0) ||
   q->guestAddress!=GUEST_IPA || q->bytes!=PAGE_BYTES || q->spaceWord || q->flags!=(op==3?5u:0u) ||
   (op==3 && !CodeExact(p)))return FAIL;
 }else if(op==6) {
  if(!p->vmExists || !p->mapped || p->cpuExists || !arguments ||
   ((uint64_t *)arguments)[0] || ((uint64_t *)arguments)[1])return FAIL;
 }else if(op==8 || op==9) {
  if(arguments || !p->cpuExists || !p->mapped || p->writeFailed || !CodeExact(p) || (op==9 && !p->runArmed))return FAIL;
 }else if(op==7) {
  if(arguments || !p->cpuExists)return FAIL;
 }else if(op==2) {
  if(arguments || !p->vmExists || p->cpuExists || p->mapped)return FAIL;
 }else return FAIL;
 if(op==9) {
  // Re-check immediately after any real Native8 synchronization. A stale BRK
  // must never be accepted as fresh execution by another Native9 entry.
  uint32_t priorESR=0;
  bool known=Read(p,(unsigned char *)p->context+0x400c,4,&priorESR);
  bool fresh=known && priorESR!=BRK_ESR;
  printf("{\"kind\":\"armFreshAtNative9\",\"ordinal\":%u,\"known\":%s,\"priorESR\":%u,\"fresh\":%s}\n",p->calls[9]+1,known?"true":"false",priorESR,fresh?"true":"false");
  if(!fresh)return FAIL;
 }
 ++p->calls[op];
 printf("{\"kind\":\"nativeBegin\",\"operation\":%llu,\"ordinal\":%u,\"owner\":%llu}\n",(unsigned long long)op,p->calls[op],(unsigned long long)p->owner);
 int32_t status=VM27OwnedBRKNativeTrapV1(op,arguments);
 if(!status) {
  if(op==1)p->vmExists=true;
  else if(op==3)p->mapped=true;
  else if(op==4)p->mapped=false;
  else if(op==6){p->context=(void *)(uintptr_t)((uint64_t *)arguments)[1];p->returnedSlot=((uint64_t *)arguments)[0];p->cpuExists=true;}
  else if(op==7){p->context=NULL;p->cpuExists=false;}
  else if(op==2)p->vmExists=false;
 }
 if(op==9 && !status) {
  uint32_t reason=0,esr=0;uint64_t pc=0,cnthctl=0,ready=0,active=0;
  bool known=Read(p,(unsigned char *)p->context+0x4008,4,&reason) &&
   Read(p,(unsigned char *)p->context+0x400c,4,&esr) && Read(p,(unsigned char *)p->context+0x108,8,&pc) &&
   Read(p,(unsigned char *)p->context+0x4088,8,&cnthctl) && Read(p,(unsigned char *)p->context+0x4100,8,&ready) &&
   Read(p,(unsigned char *)p->context+0x4110,8,&active);
  printf("{\"kind\":\"actualNativeExit\",\"known\":%s,\"rawReason\":%u,\"ESR\":%u,\"PC\":%llu,\"effectiveCNTHCTL\":%llu,\"ready\":%llu,\"activeBanks\":%llu}\n",known?"true":"false",reason,esr,(unsigned long long)pc,(unsigned long long)cnthctl,(unsigned long long)ready,(unsigned long long)active);
 }
 printf("{\"kind\":\"nativeEnd\",\"operation\":%llu,\"returnBits\":%u}\n",(unsigned long long)op,(uint32_t)status);
 return status;
}
static void Status(const char *stage,hv_return_t status) {
 printf("{\"kind\":\"status\",\"stage\":\"%s\",\"returnBits\":%u}\n",stage,(uint32_t)status);
}
static bool AllocatePage(ProbeGICV2 *p) {
 uintptr_t start=(uintptr_t)VM27OwnedGICGuestStartV1,end=(uintptr_t)VM27OwnedGICGuestEndV1;
 if(end<=start || end-start>PAGE_BYTES || (end-start)%4)return false;
 p->guestBytes=end-start;p->allocationBytes=5*PAGE_BYTES;
 p->allocation=mmap(NULL,p->allocationBytes,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(p->allocation==MAP_FAILED){p->allocation=NULL;return false;}
 p->host=(void *)(((uintptr_t)p->allocation+PAGE_BYTES*2-1)&~(PAGE_BYTES-1));
 if(mprotect(p->host,PAGE_BYTES,PROT_READ|PROT_WRITE))return false;
 uint32_t *words=p->host;for(size_t i=0;i<PAGE_BYTES/4;++i)words[i]=BRK_WORD;
 memcpy(p->host,VM27OwnedGICGuestStartV1,p->guestBytes);sys_icache_invalidate(p->host,PAGE_BYTES);
 return CodeExact(p);
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IOLBF,0);
 if(argc!=2 || strcmp(argv[1],"--owned-gic-counter-no-cpu-rlimit-v2"))return 64;
 struct rlimit cpu={0},core={0};
 if(!Profile("hw.machine","iPad14,6") || !Profile("kern.osrelease","22.1.0") || !Profile("kern.osversion","20B101") ||
  getrlimit(RLIMIT_CPU,&cpu) || getrlimit(RLIMIT_CORE,&core) || cpu.rlim_cur!=RLIM_INFINITY || cpu.rlim_max!=RLIM_INFINITY || core.rlim_cur)return 71;
 puts("{\"kind\":\"scope\",\"singleCPU\":true,\"guestPageBytes\":16384,\"native9Maximum\":24,\"publicRunMaximum\":1,\"full27Backend\":false}");
 ProbeGICV2 p={0};atomic_init(&p.wakes,0);p.owner=OwnerThread(NULL);if(!p.owner)return 72;
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&p,Native,OwnerThread,Read};
 VZKernelInitWriter writer={&p,Write};
 hv_vm_config_t vmConfig=NULL;hv_vcpu_config_t cpuConfig=NULL;hv_gic_config_t gicConfig=NULL;
 VM27CPUFactoryVMV2 *vm=NULL;VM27CPUFactoryBorrowV2 *borrow=NULL;
 hv_vcpu_t id=0;hv_vcpu_exit_t *exit=NULL;
 bool installed=false,vmCreated=false,mapAttempted=false,oracle=false,released=false;
 hv_return_t run=FAIL,cleanup=FAIL,unmap=FAIL,destroy=FAIL,uninstall=FAIL,borrowRelease=0;
 uint64_t offset=0,expectedType=0,post[9]={0},postPC=0;
 VZKernelCounterDomainSampleV19 before={0},after={0};
 if(!AllocatePage(&p))goto done;
 hv_return_t s=VM27HVVMInstallNativeOpsV1(&ops,&writer);Status("install",s);if(s)goto done;installed=true;
 vmConfig=hv_vm_config_create();cpuConfig=hv_vcpu_config_create();
 if(!vmConfig || !cpuConfig || _hv_vm_config_set_isa(vmConfig,2))goto done;
 s=hv_vm_create(vmConfig);Status("createVM",s);if(s)goto done;vmCreated=true;
 if(VM27HVVMGetOwnedVMV1(&vm) || !vm)goto done;
 gicConfig=hv_gic_config_create();
 if(!gicConfig || hv_gic_config_set_distributor_base(gicConfig,DIST_IPA) ||
  hv_gic_config_set_redistributor_base(gicConfig,REDIST_IPA))goto done;
 s=hv_gic_create(gicConfig);Status("createGIC",s);if(s)goto done;
 if(hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)4,&expectedType))goto done;
 mapAttempted=true;s=hv_vm_map(p.host,GUEST_IPA,PAGE_BYTES,5);Status("map",s);if(s)goto done;
 s=hv_vcpu_create(&id,&exit,cpuConfig);Status("createCPU",s);if(s || !id || !exit || !p.cpuExists)goto done;
 // Use the original fresh-boot source of the nonzero public offset.
 offset=mach_absolute_time();
 if(!offset || !VZKernelReadCounterDomainSampleV19(&p,&before) ||
  VZKernelValidateCounterDomainV19(&before)!=VZ_COUNTER_DOMAIN_VALID_V19)goto done;
 printf("{\"kind\":\"clockDomainBefore\",\"publicOffset\":%llu,\"physicalBefore\":%llu,\"physicalAfter\":%llu,\"machAbsolute\":%llu,\"MachBias\":%llu,\"frequency\":%llu}\n",(unsigned long long)offset,(unsigned long long)before.physicalBefore,(unsigned long long)before.physicalAfter,(unsigned long long)before.machAbsolute,(unsigned long long)before.commpageBaseBefore,(unsigned long long)before.counterFrequency);
 if(hv_vcpu_set_vtimer_offset(id,offset) || hv_vcpu_set_vtimer_mask(id,false) ||
  hv_vcpu_set_sys_reg(id,(hv_sys_reg_t)0xc080,UINT64_C(0x30800180)) ||
  hv_vcpu_set_reg(id,(hv_reg_t)34,UINT64_C(0x3c5)) || hv_vcpu_set_reg(id,(hv_reg_t)31,GUEST_IPA))goto done;
 if(VM27CPUFactoryBorrowAcquireV2(id,&borrow))goto done;
 uint64_t debug=0;VZKernelInitReceipt receipt={0};
 if(!Read(&p,(unsigned char *)p.context+0x688,8,&debug))goto done;
 s=VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_CONTROL,2,debug|UINT64_C(0x100),0,&writer,&receipt,NULL);
 if(!s)s=VM27CPUFactoryBorrowApplyV2(borrow,VZ_KERNEL_INIT_CONTROL,16,0,0,&writer,&receipt,NULL);
 Status("configureDebugAndRequestedCounterTrap",s);
 borrowRelease=VM27CPUFactoryBorrowReleaseV2(borrow);Status("releaseSetupBorrow",borrowRelease);
 if(!borrowRelease)borrow=NULL;if(s || borrowRelease)goto done;
 uint32_t initialESR=0;
 if(!Read(&p,(unsigned char *)p.context+0x400c,4,&initialESR) || initialESR==BRK_ESR || !CodeExact(&p))goto done;
 p.runArmed=true;run=hv_vcpu_run(id);p.runArmed=false;Status("publicRun",run);
 if(run || !VZKernelReadCounterDomainSampleV19(&p,&after) ||
  VZKernelValidateCounterDomainV19(&after)!=VZ_COUNTER_DOMAIN_VALID_V19)goto done;
 for(unsigned i=0;i<9;++i)if(hv_vcpu_get_reg(id,(hv_reg_t)i,&post[i]))goto done;
 if(hv_vcpu_get_reg(id,(hv_reg_t)31,&postPC))goto done;
 uint64_t brkOffset=(uintptr_t)VM27OwnedGICGuestBRKV1-(uintptr_t)VM27OwnedGICGuestStartV1;
 oracle=exit->reason==1 && exit->exception.syndrome==BRK_ESR && postPC==GUEST_IPA+brkOffset &&
  after.machAbsolute>=offset && post[0]>=before.machAbsolute-offset && post[0]<=after.machAbsolute-offset &&
  post[1]==before.counterFrequency && post[3]==255 && post[4]==248 && post[5]==DIST_IPA &&
  post[6]==expectedType && post[7]==1023 && !(post[8]&3) && p.calls[9]>1 && CodeExact(&p);
 printf("{\"kind\":\"guestOracle\",\"passed\":%s,\"publicReason\":%u,\"ESR\":%llu,\"PC\":%llu,\"X0LogicalCounter\":%llu,\"X1Frequency\":%llu,\"X4PMR\":%llu,\"X6DistributorType\":%llu,\"X7IAR\":%llu,\"X8TimerControl\":%llu,\"expectedDistributorType\":%llu,\"afterMachAbsolute\":%llu,\"publicOffset\":%llu}\n",oracle?"true":"false",exit->reason,(unsigned long long)exit->exception.syndrome,(unsigned long long)postPC,(unsigned long long)post[0],(unsigned long long)post[1],(unsigned long long)post[4],(unsigned long long)post[6],(unsigned long long)post[7],(unsigned long long)post[8],(unsigned long long)expectedType,(unsigned long long)after.machAbsolute,(unsigned long long)offset);
done:
 if(borrow){borrowRelease=VM27CPUFactoryBorrowReleaseV2(borrow);if(!borrowRelease)borrow=NULL;}
 hv_return_t drain=VM27CPUFactoryPublicDrainBorrowV6();Status("drainPublicBorrow",drain);
 hv_return_t gicDrain=VM27HVDrainGICBorrowV9();Status("drainGICBorrow",gicDrain);
 if(vm && p.cpuExists && !borrow){cleanup=VM27CPUFactoryOwnerCleanupV2(vm,NULL);Status("ownerCPUCleanup",cleanup);}
 if(mapAttempted && p.mapped && !p.cpuExists && !borrow){unmap=hv_vm_unmap(GUEST_IPA,PAGE_BYTES);Status("unmap",unmap);}
 if(vmCreated && !p.cpuExists && !p.mapped && !borrow){destroy=hv_vm_destroy();Status("destroyVM",destroy);}
 if(gicConfig)CFRelease((CFTypeRef)gicConfig);
 if(cpuConfig)CFRelease((CFTypeRef)cpuConfig);
 if(vmConfig)CFRelease((CFTypeRef)vmConfig);
 if(installed){uninstall=VM27HVVMUninstallNativeOpsV1();Status("uninstall",uninstall);}
 if(p.allocation && !p.cpuExists && !p.mapped && !borrow){released=!munmap(p.allocation,p.allocationBytes);if(released){p.allocation=NULL;p.host=NULL;}}
 uint64_t cpuMade=0,cpuFreed=0,vmMade=0,vmFreed=0;
 VM27CPUConfigTestCountsV3(&cpuMade,&cpuFreed);VM27HVVMTestConfigCountsV1(&vmMade,&vmFreed);
 bool clean=!cleanup && !unmap && !destroy && !uninstall && !drain && !gicDrain && !borrow && released &&
  !p.cpuExists && !p.vmExists && !p.mapped && p.calls[1]==1 && p.calls[2]==1 && p.calls[3]==1 &&
  p.calls[4]==1 && p.calls[6]==1 && p.calls[7]==1 && cpuMade==1 && cpuFreed==1 && vmMade==1 && vmFreed==1;
 printf("{\"kind\":\"result\",\"instructionGICCounterOracle\":%s,\"cleanupComplete\":%s,\"passed\":%s,\"native8\":%u,\"native9\":%u,\"native10\":%u,\"writes\":%u,\"reads\":%u,\"guestBooted\":false,\"full27Backend\":false}\n",oracle?"true":"false",clean?"true":"false",oracle&&clean?"true":"false",p.calls[8],p.calls[9],atomic_load_explicit(&p.wakes,memory_order_relaxed),p.writes,p.reads);
 return oracle && clean?0:74;
}
