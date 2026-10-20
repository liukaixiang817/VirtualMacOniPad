#include "modern_cpu_native_public_factory_v18.h"
#define main FrozenRoot8ControlFixtureMainV18
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
static bool ControlHoldReleaseV18;
extern VZKernelStatus ControlActualReleaseV18(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *b) {
 if(ControlHoldReleaseV18)return VZ_KERNEL_BUSY;
 return ControlActualReleaseV18(b);
}
typedef struct {
 Mock m;
 bool active,reentry,failRead,versionAfterWrite,ownerAfterWrite;
 unsigned writeOrdinal,failWriteOrdinal;
 uint32_t offsets[4];
} ControlMockV18;
static uint64_t ControlThreadV18(void *p) {
 ControlMockV18 *c=p;uint64_t owner=Thread(&c->m);
 return c->active && c->ownerAfterWrite && c->writeOrdinal?owner+1:owner;
}
static bool ControlReadV18(void *p,const void *a,size_t n,void *out) {
 ControlMockV18 *c=p;uintptr_t offset=(uintptr_t)a-(uintptr_t)c->m.context;
 if(c->active && c->failRead && (offset==0x688 || offset==0x6e0 || offset==0x6e8))return false;
 return Read(&c->m,a,n,out);
}
static bool ControlWriteV18(void *p,void *a,size_t n,const void *value) {
 ControlMockV18 *c=p;uintptr_t offset=(uintptr_t)a-(uintptr_t)c->m.context;
 if(c->active) {
  CHECK(c->writeOrdinal<4);c->offsets[c->writeOrdinal++]=(uint32_t)offset;
  if(c->reentry) {
   unsigned destroys=c->m.calls[2],maps=c->m.calls[3],unmaps=c->m.calls[4];uint64_t unchanged=77;
   CHECK(_hv_vcpu_get_control_field(c->m.cpu,2,&unchanged)==BUSY && unchanged==77);
   CHECK(_hv_vcpu_set_control_field(c->m.cpu,7,1)==BUSY);
   CHECK(hv_vm_destroy()==BUSY && hv_vm_unmap(0x40000000,0x4000)==BUSY);
   CHECK(c->m.calls[2]==destroys && c->m.calls[3]==maps && c->m.calls[4]==unmaps);
  }
 }
 bool written=Write(&c->m,a,n,value);
 if(c->active && c->versionAfterWrite && c->writeOrdinal)Put(&c->m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000));
 return written && !(c->active && c->failWriteOrdinal==c->writeOrdinal);
}
static void ControlBeginV18(ControlMockV18 *c) {
 memset(c,0,sizeof(*c));Mock *m=&c->m;
 m->context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m->host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m->context!=MAP_FAILED && m->host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,c,Trap,ControlThreadV18,ControlReadV18};
 VZKernelInitWriter writer={c,ControlWriteV18};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m->config=hv_vm_config_create();CHECK(m->config);
 CHECK(!_hv_vm_config_set_isa(m->config,2));CHECK(!hv_vm_create(m->config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m->vm));CHECK(!hv_vm_map(m->host,0x40000000,0x4000,7));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m->cpu,&exit,NULL) && m->cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->cpu,&m->retained));
 Put(m,0x678,UINT64_C(0x23456789abcdef00));Put(m,0x670,UINT64_C(0xabcdef0120000000));Put(m,0x748,UINT64_C(0x8000000000000080));
 c->active=true;
}
static void ControlEndV18(ControlMockV18 *c,bool poisoned) {
 Mock *m=&c->m;c->active=false;Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 CHECK(!m->calls[8] && !m->calls[9]);CHECK(!VM27CPUFactoryBorrowReleaseV2(m->retained));m->retained=NULL;
 if(poisoned) {
  m->failCPU=true;CHECK(VM27CPUFactoryOwnerCleanupV2(m->vm,NULL)==ERROR);
  CHECK(m->calls[4]==0 && m->calls[2]==0);m->failCPU=false;
  CHECK(!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL));
 } else CHECK(!hv_vcpu_destroy(m->cpu));
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy());CFRelease((CFTypeRef)m->config);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m->context,0x8000) && !munmap(m->host,0x8000));
}
static void *ControlForeignV18(void *p) {
 ControlMockV18 *c=p;uint64_t out=77;
 CHECK(_hv_vcpu_get_control_field(c->m.cpu,2,&out)==BAD && out==77);
 CHECK(_hv_vcpu_set_control_field(c->m.cpu,7,1)==BAD);return NULL;
}
int main(void) {
 alarm(20);const uint32_t selectors[]={2,7,8},offsets[]={0x688,0x6e0,0x6e8};
 const uint64_t values[]={0,UINT64_MAX,UINT64_C(0xdeadbeef01234567),UINT64_C(1)<<63};
 ControlMockV18 c;ControlBeginV18(&c);
 for(unsigned s=0;s<3;++s)for(unsigned v=0;v<4;++v) {
  Put(&c.m,offsets[s],values[v]);uint64_t out=77;
  CHECK(!_hv_vcpu_get_control_field(c.m.cpu,selectors[s],&out) && out==values[v]);
  uint64_t fresh=~values[v],sync678=Word(&c.m,0x678),sync670=Word(&c.m,0x670),dirty=Word(&c.m,0x748);
  c.writeOrdinal=0;c.reentry=true;CHECK(!_hv_vcpu_set_control_field(c.m.cpu,selectors[s],fresh));c.reentry=false;
  CHECK(c.writeOrdinal==4 && c.offsets[0]==offsets[s] && c.offsets[1]==0x678 && c.offsets[2]==0x670 && c.offsets[3]==0x748);
  CHECK(Word(&c.m,offsets[s])==fresh && Word(&c.m,0x678)==(sync678|(UINT64_C(1)<<56)) &&
   Word(&c.m,0x670)==(sync670|(UINT64_C(1)<<18)) && Word(&c.m,0x748)==(dirty|4));
 }
 uint64_t out=77;CHECK(_hv_vcpu_get_control_field(c.m.cpu,4,&out)==BAD && out==77);
 CHECK(_hv_vcpu_get_control_field(c.m.cpu,0,&out)==(int32_t)UINT32_C(0xfae9400f) && out==77);
 CHECK(_hv_vcpu_get_control_field(c.m.cpu,2,(uint64_t *)(c.m.context+0x688))==BAD);
 CHECK(_hv_vcpu_get_control_field(c.m.cpu,2,(uint64_t *)c.m.host)==BAD);
 c.failRead=true;CHECK(_hv_vcpu_get_control_field(c.m.cpu,2,&out)==ERROR && out==77);c.failRead=false;
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,ControlForeignV18,&c));CHECK(!pthread_join(foreign,NULL));
 ControlHoldReleaseV18=true;CHECK(_hv_vcpu_get_control_field(c.m.cpu,2,&out)==BUSY && out==77);
 CHECK(_hv_vcpu_set_control_field(c.m.cpu,7,2)==BUSY);ControlHoldReleaseV18=false;
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());CHECK(!_hv_vcpu_get_control_field(c.m.cpu,2,&out));
 ControlEndV18(&c,false);
 for(unsigned fail=1;fail<=4;++fail) {
  ControlBeginV18(&c);c.failWriteOrdinal=fail;c.writeOrdinal=0;
  VZKernelInitReceipt receipt={0};VM27CPUFactoryDiagnosticV2 diagnostic={0};
  CHECK(VM27CPUFactoryBorrowAccessControlV18(c.m.retained,VZ_KERNEL_CONTROL_WRITE_V22,8,77,NULL,&receipt,&diagnostic)==ERROR);
  CHECK(receipt.mutationPoisoned && receipt.attemptedWrites==fail && receipt.completedWrites==fail-1 && diagnostic.cpuGeneration && diagnostic.vmEpoch);
  out=88;CHECK(_hv_vcpu_get_control_field(c.m.cpu,8,&out)==BAD && out==88);ControlEndV18(&c,true);
 }
 for(unsigned boundary=0;boundary<2;++boundary) {
  ControlBeginV18(&c);c.versionAfterWrite=!boundary;c.ownerAfterWrite=boundary;c.writeOrdinal=0;
  VZKernelInitReceipt receipt={0};
  CHECK(VM27CPUFactoryBorrowAccessControlV18(c.m.retained,VZ_KERNEL_CONTROL_WRITE_V22,2,77,NULL,&receipt,NULL)!=0);
  CHECK(receipt.mutationPoisoned && receipt.attemptedWrites==1);ControlEndV18(&c,true);
 }
 printf("{\"checks\":%u,\"actualControl2_7_8\":true,\"exactOldFourWrites\":true,\"actualRootOwner\":true,\"partialWriteWithdraws\":true,\"releaseFailurePreservesOutput\":true,\"nativeOperations\":0,\"deviceOperations\":0}\n",Checks);
 return 0;
}
