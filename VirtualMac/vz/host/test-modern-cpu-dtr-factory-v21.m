#include "modern_cpu_native_public_factory_v21.h"
#include "modern_vmm_dtr_v1.h"
#include "modern_cpu_native_public_factory_v20.h"
#include "modern_cpu_config_capability_acquisition_v2.h"
#include "modern_cpu_config_os_object_v3.h"
#pragma clang diagnostic ignored "-Wnonnull"
#define VM27CPUConfigAcquireRawIPAPairV2 FixtureRawIPAPairV20
#define VM27CPUConfigAcquireCapabilitiesV2 FixtureCapabilitiesV20
#define VM27CPUConfigAcquireTLBICapabilityV1 FixtureTLBICapabilitiesV20
#define main FrozenRoot8FeatureFixtureV20
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
#undef VM27CPUConfigAcquireRawIPAPairV2
#undef VM27CPUConfigAcquireCapabilitiesV2
#undef VM27CPUConfigAcquireTLBICapabilityV1
#include <sys/wait.h>

static unsigned QueryCallsV20,SDKCallsV20,UnmapCallsV20;
static bool FailQueryV20,FailUnmapV20,HoldConfigReleaseV20;
static hv_vcpu_config_t QueryConfigV20;
static const unsigned char Native0ObservationV20[352]={
#include "native0-observed-v20.inc"
};
bool VM27CPUCapabilityTestProfileV2(void){return true;}
uint64_t VM27CPUCapabilityTestOwnerV2(void){return Thread(NULL);}
int VM27CPUCapabilityTestSysctlV2(const char *name,void *out,size_t *n,void *newp,size_t newn) {
 CHECK(!strcmp(name,"kern.hv_vmm_present") && *n==sizeof(int) && !newp && !newn);
 *(int *)out=0;return 0;
}
int VM27CPUCapabilityTestUnmapV2(void *p,size_t n) {
 ++UnmapCallsV20;CHECK(!munmap(p,n));return FailUnmapV20?-1:0;
}
bool VM27CPUCapabilityTestSDKV2(uint64_t token) {
 ++SDKCallsV20;CHECK(token==VZ_KERNEL_FEATURE_SEED_SDK_TOKEN);return false;
}
int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t selector,void *out) {
 ++QueryCallsV20;CHECK(!selector && out && !((uintptr_t)out&31));
 uint64_t untouched=77;
 CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)12,&untouched)==BUSY && untouched==77);
 if(FailQueryV20)return -11;
 memcpy(out,Native0ObservationV20,sizeof(Native0ObservationV20));return 0;
}
extern VM27CPUConfigStatusV3 VM27CPUProfileActualConfigReleaseV20(VM27CPUConfigBorrowV3 *);
VM27CPUConfigStatusV3 VM27CPUConfigReleaseBorrowV3(VM27CPUConfigBorrowV3 *b) {
 return HoldConfigReleaseV20?VM27_CPU_CONFIG_BUSY_V3:VM27CPUProfileActualConfigReleaseV20(b);
}
static bool DTRHoldReleaseV21;
extern VZKernelStatus DTRActualReleaseV21(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *borrow) {
 return DTRHoldReleaseV21?VZ_KERNEL_BUSY:DTRActualReleaseV21(borrow);
}
typedef struct {
 Mock m;bool active,reenter,ownerFails;
 unsigned versionReads,failVersionOrdinal,failReadOrdinal;
} DTRMockV21;
static uint64_t DTRThreadV21(void *p) {
 DTRMockV21 *d=p;uint64_t owner=Thread(&d->m);
 return d->active && d->ownerFails && d->versionReads>=2?owner+1:owner;
}
static bool DTRReadV21(void *p,const void *at,size_t n,void *out) {
 DTRMockV21 *d=p;uintptr_t off=(uintptr_t)at-(uintptr_t)d->m.context;
 if(d->active && off==0x4000) {
  ++d->versionReads;
  if(d->reenter) {
   uint64_t unchanged=77;unsigned runs=d->m.calls[9],writes=d->m.writes;
   CHECK(VM27CPUFactoryAccessDTRV21(d->m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&unchanged)==BUSY && unchanged==77);
   CHECK(VM27CPUFactoryAccessDTRV21(d->m.cpu,VZ_KERNEL_DTR_WRITE_TX_V23,1,NULL)==BUSY);
   CHECK(hv_vcpu_destroy(d->m.cpu)==BUSY && hv_vm_destroy()==BUSY);
   CHECK(d->m.calls[9]==runs && d->m.writes==writes);
  }
  if(d->versionReads==d->failReadOrdinal)return false;
  if(d->versionReads==d->failVersionOrdinal) {uint64_t bad=VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000);memcpy(out,&bad,8);return true;}
 }
 return Read(&d->m,at,n,out);
}
static void DTRBeginV21(DTRMockV21 *d) {
 memset(d,0,sizeof(*d));Mock *m=&d->m;
 m->context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m->host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m->context!=MAP_FAILED && m->host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,d,Trap,DTRThreadV21,DTRReadV21};VZKernelInitWriter writer={d,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m->config=hv_vm_config_create();CHECK(m->config);
 CHECK(!_hv_vm_config_set_isa(m->config,2) && !hv_vm_create(m->config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m->vm) && !hv_vm_map(m->host,0x40000000,0x4000,7));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m->cpu,&exit,NULL) && m->cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->cpu,&m->retained));d->active=true;
}
static void DTREndV21(DTRMockV21 *d,bool poisoned) {
 Mock *m=&d->m;d->active=false;
 CHECK(!m->calls[8] && !m->calls[9]);CHECK(!VM27CPUFactoryBorrowReleaseV2(m->retained));m->retained=NULL;
 if(poisoned) {m->failCPU=true;CHECK(VM27CPUFactoryOwnerCleanupV2(m->vm,NULL)==ERROR);CHECK(!m->calls[4] && !m->calls[2]);m->failCPU=false;CHECK(!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL));}
 else CHECK(!hv_vcpu_destroy(m->cpu));
 CHECK(!hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());CFRelease((CFTypeRef)m->config);
 CHECK(!VM27HVVMUninstallNativeOpsV1() && !munmap(m->context,0x8000) && !munmap(m->host,0x8000));
}
static void DTRFailureV21(int32_t status) {(void)status;abort();}
static void *DTRForeignV21(void *p) {
 DTRMockV21 *d=p;uint64_t out=77;VZKernelDTRReceiptV23 receipt={0};
 CHECK(VM27CPUFactoryAccessDTRV21(d->m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==BAD && out==77);
 CHECK(VM27CPUFactoryBorrowAccessDTRV21(d->m.retained,VZ_KERNEL_DTR_WRITE_TX_V23,1,NULL,&receipt,NULL)==BAD);
 return NULL;
}
int main(void) {
 alarm(20);DTRMockV21 d;DTRBeginV21(&d);unsigned writes=d.m.writes;
 uint64_t out=77;CHECK(!VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out) && out==0);
 const uint64_t values[]={0,UINT64_MAX,UINT64_C(0xdeadbeef01234567),UINT64_C(1)<<63};
 for(unsigned i=0;i<4;++i) {
  VZKernelDTRReceiptV23 r={0};d.versionReads=0;d.reenter=true;
  CHECK(!VM27CPUFactoryBorrowAccessDTRV21(d.m.retained,VZ_KERNEL_DTR_WRITE_TX_V23,values[i],NULL,&r,NULL));d.reenter=false;
  CHECK(r.actualSoftwareWrites==1 && r.firstTXValue==values[i] && r.finalTXValue==values[i] && r.ownResetZeroPolicy && !r.mutationPoisoned);
  out=77;CHECK(!VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_PAIR_V23,0,&out) && out==(values[i]<<32));
  out=77;CHECK(!VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out) && out==0);
  d.versionReads=0;CHECK(!VM27CPUFactoryBorrowAccessDTRV21(d.m.retained,VZ_KERNEL_DTR_WRITE_PAIR_V23,values[i],NULL,&r,NULL));
  CHECK(d.versionReads==2 && r.actualSoftwareWrites==2 && r.firstTXValue==(uint32_t)values[i] && r.finalTXValue==values[i]>>32);
  out=77;CHECK(!VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_PAIR_V23,0,&out) && out==(values[i]&UINT64_C(0xffffffff00000000)));
 }
 VM27VMMWriteDTRV1(d.m.cpu,0x9820,UINT64_C(0xa5a5123487654321),DTRFailureV21);
 CHECK(VM27VMMReadDTRV1(d.m.cpu,0x9820,DTRFailureV21)==UINT64_C(0xa5a5123400000000));
 VM27VMMWriteDTRV1(d.m.cpu,0x9828,UINT64_MAX,DTRFailureV21);CHECK(!VM27VMMReadDTRV1(d.m.cpu,0x9828,DTRFailureV21));
 out=77;CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,(VZKernelDTRActionV23)0,0,&out)==BAD && out==77);
 CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,1,&out)==BAD && out==77);
 CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,(uint64_t *)d.m.context)==BAD);
 CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,(uint64_t *)d.m.host)==BAD);
 CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,(uint64_t *)(void *)d.m.retained)==BAD);
 VZKernelDTRReceiptV23 r={0};CHECK(VM27CPUFactoryBorrowAccessDTRV21(d.m.retained,VZ_KERNEL_DTR_READ_RX_V23,0,(uint64_t *)(void *)&r,&r,NULL)==BAD);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,DTRForeignV21,&d) && !pthread_join(foreign,NULL));
 d.failVersionOrdinal=1;d.versionReads=0;out=77;CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==ERROR && out==77);d.failVersionOrdinal=0;
 d.failReadOrdinal=1;d.versionReads=0;out=77;CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==ERROR && out==77);d.failReadOrdinal=0;
 DTRHoldReleaseV21=true;out=77;CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==BUSY && out==77);
 CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_WRITE_TX_V23,1,NULL)==BUSY);DTRHoldReleaseV21=false;
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());CHECK(d.m.writes==writes);hv_vcpu_t stale=d.m.cpu;DTREndV21(&d,false);
 DTRBeginV21(&d);CHECK(d.m.cpu!=stale);out=77;CHECK(VM27CPUFactoryAccessDTRV21(stale,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==BAD && out==77);
 CHECK(!VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_PAIR_V23,0,&out) && out==0);DTREndV21(&d,false);
 for(unsigned failure=0;failure<3;++failure) {
  DTRBeginV21(&d);d.failVersionOrdinal=failure==0?2:0;d.failReadOrdinal=failure==1?2:0;d.ownerFails=failure==2;d.versionReads=0;
  r=(VZKernelDTRReceiptV23){0};VM27CPUFactoryDiagnosticV2 diag={0};
  CHECK(VM27CPUFactoryBorrowAccessDTRV21(d.m.retained,VZ_KERNEL_DTR_WRITE_PAIR_V23,UINT64_C(0xdeadbeef12345678),NULL,&r,&diag)!=0);
  CHECK(r.actualSoftwareWrites==1 && r.firstTXValue==0x12345678 && r.finalTXValue==0x12345678 && r.mutationPoisoned && diag.vmEpoch && diag.cpuGeneration);
  out=77;CHECK(VM27CPUFactoryAccessDTRV21(d.m.cpu,VZ_KERNEL_DTR_READ_RX_V23,0,&out)==BAD && out==77);DTREndV21(&d,true);
 }
 printf("{\"checks\":%u,\"ownSoftwareDTRBank\":true,\"combinedSetterActualTXWrites\":2,\"RXNeverWrittenByTX\":true,\"ownerVersionEpoch\":true,\"partialWriteWithdraws\":true,\"releaseFailureRetained\":true,\"nativeOperations\":0,\"deviceOperations\":0}\n",Checks);return 0;
}
