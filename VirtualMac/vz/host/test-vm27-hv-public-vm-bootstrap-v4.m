#include "vm27_hv_public_vm_bootstrap_v4.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {++Checks;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);abort();}}while(0)
#define BAD ((hv_return_t)UINT32_C(0xfae94003))
#define BUSY ((hv_return_t)UINT32_C(0xfae94002))
#define UNSUP ((hv_return_t)UINT32_C(0xfae9400f))
static unsigned Checks,RawCalls;
static VM27CPURawIPAPairV2 Pair={true,40,42};
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *out){++RawCalls;*out=Pair;}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *out){*out=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out){*out=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {unsigned char *memory,*host;unsigned calls[10],failMapOp,nativeISA;uint64_t flags;bool failCreate,failDestroy,reenter;hv_vm_config_t config;} Mock;
static uint64_t Thread(void *context){(void)context;uint64_t out=0;CHECK(!pthread_threadid_np(NULL,&out));return out;}
static int32_t Trap(void *context,uint64_t op,void *arg){Mock *m=context;CHECK(op>=1&&op<=8);++m->calls[op];
 if(m->reenter){CHECK(hv_vm_create(m->config)==BUSY);CHECK(hv_vm_destroy()==BUSY);CHECK(VM27HVVMUninstallNativeOpsV1()==BUSY);
  if(op==1){CHECK(hv_vm_config_set_ipa_size(m->config,36)==BUSY);uint32_t v=55;CHECK(hv_vm_config_get_ipa_size(m->config,&v)==BUSY&&v==55);}}
 if(op==1){VZKernelNativeVMConfig *p=arg;CHECK(p&&p->reserved==0&&p->ipaLimit==(UINT64_C(1)<<36)&&p->nativeHVISA==m->nativeISA&&p->ipaGranule==0);return m->failCreate?-1:0;}
 if(op==2){CHECK(!arg);return m->failDestroy?-1:0;}
 if(op==6){CHECK(arg&&!((uint64_t *)arg)[0]&&!((uint64_t *)arg)[1]);((uint64_t *)arg)[1]=(uintptr_t)m->memory;uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->memory+0x4000,&magic,8);return 0;}
 if(op==3||op==4||op==5){VZKernelMemoryPacket *p=arg;CHECK(p&&p->hostAddress==(op==3?(uintptr_t)m->host:0)&&p->guestAddress==0x40000000&&p->bytes==0x4000&&p->flags==(op==4?0:m->flags)&&!p->spaceWord);
  if(m->reenter){CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY);CHECK(hv_vm_protect(0x40000000,0x4000,3)==BUSY);}return m->failMapOp==op?-17:0;}
 CHECK(!arg);return 0;
}
static bool Read(void *context,const void *p,size_t n,void *out){Mock *m=context;uintptr_t off=(uintptr_t)p-(uintptr_t)m->memory;CHECK(off<0x8000&&n<=0x8000-off);return VM27CPUSelfReadV1(NULL,p,n,out);}
static bool Write(void *context,void *p,size_t n,const void *in){Mock *m=context;uintptr_t off=(uintptr_t)p-(uintptr_t)m->memory;CHECK(off<0x8000&&n<=0x8000-off);return VM27CPUSelfWriteV1(NULL,p,n,in);}
static void *Foreign(void *context){Mock *m=context;VM27CPUFactoryVMV2 *out=(void *)1;CHECK(hv_vm_create(m->config)==BAD);CHECK(hv_vm_destroy()==BAD);CHECK(VM27HVVMGetOwnedVMV1(&out)==BAD&&out==(void *)1);CHECK(VM27HVVMUninstallNativeOpsV1()==BUSY);return NULL;}
int main(void){
 puts("MAIN combined true Factory7 guard and public VM/CPU source; all native traps/acquisition mocked");
 _Static_assert(sizeof(hv_vm_config_t)==8&&sizeof(hv_ipa_granule_t)==4,"real SDK public VM ABI");
 CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());
 Mock m={.nativeISA=2};m.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(VM27HVVMInstallNativeOpsV1(NULL,&writer)==BAD);CHECK(VM27HVVMInstallNativeOpsV1(&ops,NULL)==BAD);
 uint32_t bits=55;CHECK(hv_vm_config_get_max_ipa_size(&bits)==BAD&&bits==55&&RawCalls==0);
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));CHECK(VM27HVVMInstallNativeOpsV1(&ops,&writer)==BUSY);
 m.config=hv_vm_config_create();CHECK(m.config);hv_vm_config_t other=hv_vm_config_create();CHECK(other);
 CHECK(!hv_vm_config_get_default_ipa_size(&bits)&&bits==36);CHECK(!hv_vm_config_get_ipa_size(m.config,&bits)&&bits==36);
 CHECK(!hv_vm_config_set_ipa_size(m.config,36));CHECK(hv_vm_config_set_ipa_size(m.config,40)==UNSUP);
 CHECK(!hv_vm_config_set_ipa_granule(m.config,(hv_ipa_granule_t)0));CHECK(hv_vm_config_set_ipa_granule(m.config,(hv_ipa_granule_t)1)==UNSUP);
 CHECK(!_hv_vm_config_set_isa(m.config,1));CHECK(!_hv_vm_config_set_isa(m.config,2));CHECK(_hv_vm_config_set_isa(m.config,3)==UNSUP);
 CHECK(!hv_vm_config_set_el2_enabled(m.config,false));CHECK(hv_vm_config_set_el2_enabled(m.config,true)==UNSUP);
 CHECK(!_hv_vm_config_set_vhe_enabled(m.config,false));CHECK(_hv_vm_config_set_vhe_enabled(m.config,true)==UNSUP);
 CHECK(hv_vm_config_get_ipa_size((hv_vm_config_t)(void *)1,&bits)==BAD&&bits==36);
 CHECK(hv_vm_config_get_ipa_size(m.config,(uint32_t *)(void *)m.config)==BAD);
 CHECK(hv_vm_config_get_ipa_size(m.config,(uint32_t *)(void *)other)==BAD);
 CHECK(hv_vm_config_get_default_ipa_size((uint32_t *)(void *)m.config)==BAD);
 CHECK(hv_vm_config_get_max_ipa_size((uint32_t *)(void *)m.config)==BAD&&RawCalls==0);
 CHECK(!hv_vm_config_get_max_ipa_size(&bits)&&bits==36);
 Pair.known=false;bits=55;CHECK(hv_vm_config_get_max_ipa_size(&bits)==UNSUP&&bits==55);
 Pair=(VM27CPURawIPAPairV2){true,35,48};CHECK(hv_vm_config_get_max_ipa_size(&bits)==UNSUP&&bits==55);
 Pair=(VM27CPURawIPAPairV2){true,UINT64_C(1)<<32|40,42};CHECK(hv_vm_config_get_max_ipa_size(&bits)==UNSUP&&bits==55);
 Pair=(VM27CPURawIPAPairV2){true,40,UINT64_C(1)<<32|42};CHECK(hv_vm_config_get_max_ipa_size(&bits)==UNSUP&&bits==55);
 Pair=(VM27CPURawIPAPairV2){true,36,36};CHECK(!hv_vm_config_get_max_ipa_size(&bits)&&bits==36);
 hv_vcpu_config_t cpuConfig=hv_vcpu_config_create();CHECK(cpuConfig);
 CHECK(hv_vm_config_get_default_ipa_size((uint32_t *)(void *)cpuConfig)==BAD);
 uint64_t feature=55;CHECK(hv_vcpu_config_get_feature_reg(cpuConfig,(hv_feature_reg_t)0,(uint64_t *)(void *)m.config)==BAD);
 CHECK(hv_vcpu_config_get_feature_reg(cpuConfig,(hv_feature_reg_t)0,&feature)==UNSUP&&feature==55);
 CHECK(hv_vm_create((hv_vm_config_t)(void *)1)==BAD&&m.calls[1]==0);
 m.failCreate=true;CHECK(hv_vm_create(m.config)!=0&&m.calls[1]==1);CHECK(!hv_vm_config_set_ipa_size(m.config,36));m.failCreate=false;
 m.reenter=true;CHECK(!hv_vm_create(m.config));m.reenter=false;CHECK(hv_vm_create(m.config)==BUSY&&m.calls[1]==2);
 VM27CPUFactoryVMV2 *owned=NULL;CHECK(!VM27HVVMGetOwnedVMV1(&owned)&&owned);
 CHECK(VM27HVVMGetOwnedVMV1((VM27CPUFactoryVMV2 **)(void *)m.config)==BAD);
 CHECK(hv_vm_config_get_default_ipa_size((uint32_t *)(void *)owned)==BAD);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m.host!=MAP_FAILED&&!((uintptr_t)m.host&0x3fff));memset(m.host,0x66,0x8000);m.flags=7;
 CHECK(hv_vm_map((void *)m.config,0x40000000,0x4000,7)==BAD&&m.calls[3]==0);
 CHECK(hv_vm_map(m.host+1,0x40000000,0x4000,7)==BAD&&m.calls[3]==0);
 CHECK(hv_vm_map(m.host,0x40000000,0x4000,8)==BAD&&m.calls[3]==0);
 m.reenter=true;CHECK(!hv_vm_map(m.host,0x40000000,0x4000,7));m.reenter=false;CHECK(m.calls[3]==1);
 CHECK(hv_vm_map(m.host,0x40010000,0x4000,7)==BAD&&m.calls[3]==1);
 CHECK(hv_vm_map(m.host+0x4000,0x40000000,0x4000,7)==BUSY&&m.calls[3]==1);
 CHECK(hv_vm_unmap(0x40000000,0x2000)==UNSUP&&m.calls[4]==0);
 CHECK(hv_vm_destroy()==BUSY&&m.calls[2]==0);
 CHECK(hv_vm_config_get_default_ipa_size((uint32_t *)(void *)m.host)==BAD&&m.host[0]==0x66);
 pthread_t t;CHECK(!pthread_create(&t,NULL,Foreign,&m));CHECK(!pthread_join(t,NULL));
 hv_vcpu_t id=0;hv_vcpu_exit_t *exit=NULL;
 CHECK(hv_vcpu_create((hv_vcpu_t *)(void *)m.config,&exit,cpuConfig)==BAD&&m.calls[6]==0);
 CHECK(!hv_vcpu_create(&id,&exit,cpuConfig)&&id&&exit);
 CHECK(hv_vcpu_get_reg(id,HV_REG_X0,(uint64_t *)(void *)m.config)==BAD);
 CHECK(hv_vm_config_get_default_ipa_size((uint32_t *)(void *)exit)==BAD);
 CHECK(hv_vm_destroy()==BUSY&&m.calls[2]==0);CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY&&m.calls[4]==0);
 CHECK(hv_vm_protect(0x40000000,0x4000,3)==BUSY&&m.calls[5]==0);CHECK(!hv_vcpu_set_reg(id,HV_REG_X0,0x1234));uint64_t value=0;
 CHECK(!hv_vcpu_get_reg(id,HV_REG_X0,&value)&&value==0x1234);CHECK(!hv_vcpu_destroy(id));
 m.flags=1;CHECK(!hv_vm_protect(0x40000000,0x4000,1)&&m.calls[5]==1);
 m.flags=3;m.failMapOp=5;CHECK(hv_vm_protect(0x40000000,0x4000,3)!=0&&m.calls[5]==2);
 CHECK(hv_vm_destroy()==BUSY&&m.calls[2]==0);m.failMapOp=4;CHECK(hv_vm_unmap(0x40000000,0x4000)!=0&&m.calls[4]==1);
 CHECK(hv_vm_destroy()==BUSY&&m.calls[2]==0);m.failMapOp=0;CHECK(!hv_vm_unmap(0x40000000,0x4000)&&m.calls[4]==2);
 CHECK(VM27CPUSelfMappedRangeV1(m.host,0x8000,true,NULL)&&m.host[0]==0x66);
 m.flags=7;m.failMapOp=3;CHECK(hv_vm_map(m.host,0x40000000,0x4000,7)!=0&&m.calls[3]==2);
 CHECK(hv_vm_destroy()==BUSY&&m.calls[2]==0);m.failMapOp=0;CHECK(!hv_vm_unmap(0x40000000,0x4000)&&m.calls[4]==3);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==UNSUP&&m.calls[4]==3);CHECK(VM27CPUSelfMappedRangeV1(m.host,0x8000,true,NULL)&&m.host[0]==0x66);CHECK(!munmap(m.host,0x8000));
 m.failDestroy=true;CHECK(hv_vm_destroy()!=0&&m.calls[2]==1);CHECK(!VM27HVVMGetOwnedVMV1(&owned));m.failDestroy=false;
 m.reenter=true;CHECK(!hv_vm_destroy());m.reenter=false;CHECK(hv_vm_destroy()==BAD&&m.calls[2]==2);
 m.nativeISA=1;CHECK(!hv_vm_create(NULL));CHECK(!hv_vm_destroy());
 CFRelease((CFTypeRef)cpuConfig);CFRelease((CFTypeRef)other);hv_vm_config_t stale=m.config;CFRelease((CFTypeRef)m.config);
 bits=55;CHECK(hv_vm_config_get_ipa_size(stale,&bits)==BAD&&bits==55);CHECK(hv_vm_config_set_ipa_size(stale,36)==BAD);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(VM27HVVMUninstallNativeOpsV1()==BAD);CHECK(!munmap(m.memory,0x8000));
 uint64_t created=0,destroyed=0;VM27HVVMTestConfigCountsV1(&created,&destroyed);CHECK(created==2&&destroyed==2);
 printf("{\"checks\":%u,\"VMConfigCreated\":%llu,\"VMConfigDestroyed\":%llu,\"combinedStrongGuard\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks,(unsigned long long)created,(unsigned long long)destroyed);
}
