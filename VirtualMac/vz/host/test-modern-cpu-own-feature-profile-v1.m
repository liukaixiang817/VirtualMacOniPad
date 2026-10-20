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
static void MissingSeedChildV20(bool failedQuery) {
 pid_t p=fork();CHECK(p>=0);
 if(!p) {
  FailQueryV20=failedQuery;FailUnmapV20=!failedQuery;
  QueryConfigV20=hv_vcpu_config_create();CHECK(QueryConfigV20);
  uint64_t out=77;
  CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)12,&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==77);
  CHECK(QueryCallsV20==1 && UnmapCallsV20==1 && SDKCallsV20==(failedQuery?0u:3u));
  CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)17,&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==77);
  CHECK(QueryCallsV20==1);CFRelease((CFTypeRef)QueryConfigV20);_exit(0);
 }
 int status=0;CHECK(waitpid(p,&status,0)==p && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void *ForeignFeatureWriteV20(void *p) {
 Mock *m=p;CHECK(hv_vcpu_set_sys_reg(m->cpu,(hv_sys_reg_t)0xc021,UINT64_C(1)<<24)==BAD);return NULL;
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());
 _Static_assert(sizeof(hv_feature_reg_t)==4,"True SDK enum");
 MissingSeedChildV20(true);MissingSeedChildV20(false);
 VZKernelCapabilitySeedInput input={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,
  Native0ObservationV20,VZ_KERNEL_CAPABILITY_CONSUMED_PREFIX_BYTES,{0,0,0}};
 VZKernelCapabilitySeed seed={0};VZKernelCapabilitySeedReceipt receipt={0};
 CHECK(VZKernelComputeNativeCapabilitySeed(&input,&seed,&receipt)==VZ_KERNEL_OK);
 CHECK((seed.featureWords[7]&0xff00)==0x1100 && ((seed.featureWords[7]>>32)&15)==0 && ((seed.featureWords[8]>>24)&15)==0);
 QueryConfigV20=hv_vcpu_config_create();CHECK(QueryConfigV20);
 /* Exact 16-query original constructor order, including each extra ID. */
 static const uint32_t order[]={11,0,1,2,3,14,4,5,6,16,17,7,8,15,12,13};
 for(unsigned i=0;i<sizeof(order)/sizeof(*order);++i) {
  uint32_t selector=order[i];uint64_t out=77,expected=88;
  CHECK(VM27CPUOwnProfileGetFeatureV1(&seed,selector,&expected)==VZ_KERNEL_OK);
  CHECK(!hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)selector,&out) && out==expected);
  if(selector<12) {
   uint64_t original=99;CHECK(VZKernelCapabilitySeedGetFeature(&seed,selector,&original)==VZ_KERNEL_OK);
   if(selector==7)CHECK(out==(original&~(UINT64_C(0xff00)|(UINT64_C(15)<<32))));
   else CHECK(out==original);
  } else CHECK(out==0);
 }
 CHECK(QueryCallsV20==1 && SDKCallsV20==3 && UnmapCallsV20==1);
 uint64_t out=77;CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)18,&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==77);
 CHECK(hv_vcpu_config_get_feature_reg((hv_vcpu_config_t)(void *)1,(hv_feature_reg_t)12,&out)==BAD && out==77);
 CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)12,NULL)==BAD);
 CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)12,(uint64_t *)(void *)QueryConfigV20)==BAD);
 /* A synthetic bit-rich seed checks withheld architecture and output preservation. */
 VZKernelCapabilitySeed all=seed;all.featureWords[7]=all.featureWords[8]=all.featureWords[5]=all.featureWords[6]=UINT64_MAX;
 CHECK(VM27CPUOwnProfileGetFeatureV1(&all,7,&out)==VZ_KERNEL_OK && !(out&(UINT64_C(0xff00)|(UINT64_C(15)<<32))));
 CHECK(VM27CPUOwnProfileGetFeatureV1(&all,8,&out)==VZ_KERNEL_OK && out==0xf0);
 CHECK(VM27CPUOwnProfileGetFeatureV1(&all,5,&out)==VZ_KERNEL_OK && !(out&(UINT64_C(15)<<8)));
 CHECK(VM27CPUOwnProfileGetFeatureV1(&all,6,&out)==VZ_KERNEL_OK && !(out&(UINT64_C(15)<<24)));
 out=77;CHECK(VM27CPUOwnProfileGetFeatureV1(&all,18,&out)==VZ_KERNEL_UNSUPPORTED && out==77);
 CHECK(VM27CPUOwnProfileGetFeatureV1(NULL,12,&out)==VZ_KERNEL_BAD_ARGUMENT && out==77);
 CHECK(VM27CPUOwnProfileGetFeatureV1(&all,12,NULL)==VZ_KERNEL_BAD_ARGUMENT);
 HoldConfigReleaseV20=true;out=77;
 CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)12,&out)==BUSY && out==77);
 CHECK(hv_vcpu_config_get_feature_reg(QueryConfigV20,(hv_feature_reg_t)13,&out)==BUSY && out==77);
 uint64_t created=0,destroyed=0,after=0;VM27CPUConfigTestCountsV3(&created,&destroyed);
 CFRelease((CFTypeRef)QueryConfigV20);QueryConfigV20=NULL;
 VM27CPUConfigTestCountsV3(&created,&after);CHECK(after==destroyed);
 HoldConfigReleaseV20=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 VM27CPUConfigTestCountsV3(&created,&after);CHECK(after==destroyed+1);

 Mock m={0};m.context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.context!=MAP_FAILED && m.host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m.config=hv_vm_config_create();CHECK(m.config);
 CHECK(hv_vm_config_set_el2_enabled(m.config,true)==(hv_return_t)UINT32_C(0xfae9400f));
 CHECK(!_hv_vm_config_set_isa(m.config,2) && !hv_vm_create(m.config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m.vm) && !hv_vm_map(m.host,0x40000000,0x4000,7));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.cpu,&exit,NULL) && m.cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.cpu,&m.retained));unsigned writes=m.writes;
 static const uint32_t ids[]={0xc020,0xc021,0xc039,0xc03a};
 static const uint64_t forbidden[]={UINT64_C(1)<<8,UINT64_C(1)<<24,UINT64_C(1)<<8,UINT64_C(1)<<24};
 static const uint32_t feature[]={7,8,5,6};
 for(unsigned i=0;i<4;++i) {
  uint64_t value=0;CHECK(VM27CPUOwnProfileGetFeatureV1(&seed,feature[i],&value)==VZ_KERNEL_OK);
  CHECK(!hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)ids[i],value));out=77;
  CHECK(!hv_vcpu_get_sys_reg(m.cpu,(hv_sys_reg_t)ids[i],&out) && out==value);
  CHECK(hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)ids[i],value|forbidden[i])==(hv_return_t)UINT32_C(0xfae9400f));
  VZKernelSysReceipt sys={0};VM27CPUFactoryDiagnosticV2 diagnostic={0};
  CHECK(VM27CPUFactoryBorrowAccessSystemV4(m.retained,VZ_KERNEL_SYS_WRITE,ids[i],value|forbidden[i],NULL,&sys,&diagnostic)==(hv_return_t)UINT32_C(0xfae9400f));
  CHECK(!sys.privateFeatureWrites && !sys.attemptedNativeWrites && !sys.mutationPoisoned && diagnostic.vmEpoch);
  out=77;CHECK(!hv_vcpu_get_sys_reg(m.cpu,(hv_sys_reg_t)ids[i],&out) && out==value);
 }
 CHECK(hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc020,UINT64_C(1)<<32)==(hv_return_t)UINT32_C(0xfae9400f));
 CHECK(hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc020,UINT64_C(1)<<12)==(hv_return_t)UINT32_C(0xfae9400f));
 CHECK(hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc021,UINT64_C(1)<<60)==(hv_return_t)UINT32_C(0xfae9400f));
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,ForeignFeatureWriteV20,&m));CHECK(!pthread_join(thread,NULL));
 Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000));
 CHECK(hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc021,UINT64_C(1)<<24)==ERROR);
 Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 CHECK(m.writes==writes && !m.calls[8] && !m.calls[9]);
 CHECK(!VM27CPUFactoryBorrowReleaseV2(m.retained));m.retained=NULL;
 CHECK(!hv_vcpu_destroy(m.cpu) && !hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());
 CFRelease((CFTypeRef)m.config);CHECK(!VM27HVVMUninstallNativeOpsV1());
 CHECK(!munmap(m.host,0x8000) && !munmap(m.context,0x8000));
 printf("{\"checks\":%u,\"originalCtorQueries\":16,\"mockNative0Queries\":%u,\"nativeSeedProvenancePreserved\":true,\"ownExtensionIDs\":6,\"coherentEL2OffProfile\":true,\"actualBorrowedSYSGuard\":true,\"failedConfigReleaseRetained\":true,\"nativeKernelOperations\":0,\"deviceOperations\":0}\n",Checks,QueryCallsV20);
 return 0;
}
