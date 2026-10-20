#include "modern_cpu_optional_abi_v1.h"
#include "modern_cpu_native_public_factory_v18.h"
#pragma clang diagnostic ignored "-Wnonnull"
#define main FrozenRoot8OptionalFixtureMainV1
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

#include <sys/wait.h>
#include <sys/resource.h>
#define UNSUPPORTED ((hv_return_t)UINT32_C(0xfae9400f))
static void *OptionalForeignV1(void *p) {
 ControlMockV18 *c=p;bool out=true;
 CHECK(_hv_vcpu_amx_query_active_context(c->m.cpu,&out)==BAD && out);
 return NULL;
}
int main(void) {
 alarm(20);
 /* Pointer ABI refusal is tested in a separate actual registry, not a fabricated ID. */
 pid_t child=fork();CHECK(child>=0);
 if(!child) {
  struct rlimit limit={0,0};if(setrlimit(RLIMIT_CORE,&limit))_exit(2);
  ControlMockV18 childCPU;ControlBeginV18(&childCPU);
  (void)_hv_vcpu_get_context(childCPU.m.cpu);_exit(3);
 }
 int signal=0;CHECK(waitpid(child,&signal,0)==child);
 CHECK(WIFSIGNALED(signal) && (WTERMSIG(signal)==SIGILL || WTERMSIG(signal)==SIGTRAP));
 ControlMockV18 c;ControlBeginV18(&c);unsigned writes=c.m.writes;
 uint8_t bytes[4096],before[4096];memset(bytes,0xa5,sizeof(bytes));memcpy(before,bytes,sizeof(bytes));
 hv_vcpu_sme_state_t state={true,true};hv_sme_zt0_uchar64_t vector;memset(&vector,0xa5,sizeof(vector));
 bool active=true;uint64_t word=UINT64_C(0xdeadbeef01234567);size_t size=77;
 CHECK(hv_sme_config_get_max_svl_bytes(&size)==UNSUPPORTED && size==77);
 CHECK(hv_sme_config_get_max_svl_bytes((size_t *)(uintptr_t)0)==BAD);
 CHECK(hv_vcpu_get_sme_state(c.m.cpu,&state)==UNSUPPORTED && state.streaming_sve_mode_enabled && state.za_storage_enabled);
 CHECK(hv_vcpu_set_sme_state(c.m.cpu,&state)==UNSUPPORTED);
 for(unsigned i=0;i<32;++i) {
  CHECK(hv_vcpu_get_sme_z_reg(c.m.cpu,(hv_sme_z_reg_t)i,bytes,64)==UNSUPPORTED);
  CHECK(hv_vcpu_set_sme_z_reg(c.m.cpu,(hv_sme_z_reg_t)i,bytes,64)==UNSUPPORTED);
 }
 for(unsigned i=0;i<16;++i) {
  CHECK(hv_vcpu_get_sme_p_reg(c.m.cpu,(hv_sme_p_reg_t)i,bytes,8)==UNSUPPORTED);
  CHECK(hv_vcpu_set_sme_p_reg(c.m.cpu,(hv_sme_p_reg_t)i,bytes,8)==UNSUPPORTED);
 }
 CHECK(hv_vcpu_get_sme_za_reg(c.m.cpu,bytes,sizeof(bytes))==UNSUPPORTED);
 CHECK(hv_vcpu_set_sme_za_reg(c.m.cpu,bytes,sizeof(bytes))==UNSUPPORTED);
 CHECK(hv_vcpu_get_sme_zt0_reg(c.m.cpu,&vector)==UNSUPPORTED);
 CHECK(hv_vcpu_set_sme_zt0_reg(c.m.cpu,&vector)==UNSUPPORTED);
 CHECK(_hv_vcpu_amx_prepare(c.m.cpu)==UNSUPPORTED);
 CHECK(_hv_vcpu_amx_query_active_context(c.m.cpu,&active)==UNSUPPORTED && active);
 CHECK(_hv_vcpu_get_amx_state_t_el1(c.m.cpu,&word)==UNSUPPORTED && word==UINT64_C(0xdeadbeef01234567));
 CHECK(_hv_vcpu_set_amx_state_t_el1(c.m.cpu,word)==UNSUPPORTED);
 CHECK(_hv_vcpu_get_amx_x_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(_hv_vcpu_set_amx_x_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(_hv_vcpu_get_amx_y_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(_hv_vcpu_set_amx_y_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(_hv_vcpu_get_amx_z_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(_hv_vcpu_set_amx_z_space(c.m.cpu,bytes)==UNSUPPORTED);
 CHECK(!memcmp(bytes,before,sizeof(bytes)) && ((uint8_t *)&vector)[0]==0xa5 && ((uint8_t *)&vector)[63]==0xa5);
 for(uint32_t selector=0;selector<25;++selector) {
  bool supported=selector==2 || selector==3 || selector==4 || selector==7 || selector==9 || selector==12 ||
   (selector>=14 && selector<=19) || selector==22 || selector==23;
  CHECK(_hv_capability(selector,&word)==(supported?UNSUPPORTED:BAD) && word==UINT64_C(0xdeadbeef01234567));
 }
 CHECK(_hv_capability(9,NULL)==BAD);
 CHECK(hv_vcpu_get_sme_state(0,&state)==BAD && state.streaming_sve_mode_enabled);
 CHECK(hv_vcpu_get_sme_state(c.m.cpu,(hv_vcpu_sme_state_t *)(uintptr_t)0)==BAD);
 CHECK(hv_vcpu_get_sme_z_reg(c.m.cpu,(hv_sme_z_reg_t)32,bytes,64)==BAD);
 CHECK(hv_vcpu_get_sme_p_reg(c.m.cpu,(hv_sme_p_reg_t)16,bytes,8)==BAD);
 CHECK(hv_vcpu_get_sme_za_reg(c.m.cpu,bytes,0)==BAD);
 CHECK(_hv_vcpu_get_context(0)==NULL);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,ControlForeignV18,&c));CHECK(!pthread_join(foreign,NULL));CHECK(!pthread_create(&foreign,NULL,OptionalForeignV1,&c));CHECK(!pthread_join(foreign,NULL));
 ControlHoldReleaseV18=true;
 CHECK(_hv_vcpu_amx_query_active_context(c.m.cpu,&active)==BUSY && active);
 CHECK(_hv_vcpu_amx_prepare(c.m.cpu)==BUSY && hv_vcpu_destroy(c.m.cpu)==BUSY);
 CHECK(hv_vm_destroy()==BUSY && !c.m.calls[2] && !c.m.calls[7]);
 ControlHoldReleaseV18=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 CHECK(_hv_vcpu_amx_prepare(c.m.cpu)==UNSUPPORTED);
 CHECK(c.m.writes==writes && !c.m.calls[8] && !c.m.calls[9]);ControlEndV18(&c,false);
 printf("{\"checks\":%u,\"actualRegistryBorrow\":true,\"releaseFailureRetained\":true,\"outputsUnchanged\":true,\"validGetContextTraps\":true,\"nativeOperations\":0,\"deviceOperations\":0,\"optionalFeaturesImplemented\":false}\n",Checks);
 return 0;
}
