#include "vm27_hv_public_vm_bootstrap_v11.h"
#define main UnusedFrozenRoot8ScalarProofV1
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
static Mock ScalarMockV1;
static bool ScalarReadFailureV1,ScalarWriteFailureV1;
static bool ScalarReadCallbackV1(void *context,const void *source,size_t bytes,void *out) {
 uintptr_t off=(uintptr_t)source-(uintptr_t)ScalarMockV1.context;
 if(ScalarReadFailureV1 && (off==0x3f8 || off==0x650))return false;
 return Read(context,source,bytes,out);
}
static bool ScalarWriteCallbackV1(void *context,void *target,size_t bytes,const void *value) {
 bool result=Write(context,target,bytes,value);
 return result && !ScalarWriteFailureV1;
}
hv_vcpu_t VM27ScalarFixtureBeginV1(void) {
 Mock *m=&ScalarMockV1;memset(m,0,sizeof(*m));ScalarReadFailureV1=ScalarWriteFailureV1=false;
 m->context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m->host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m->context!=MAP_FAILED && m->host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,ScalarReadCallbackV1};
 VZKernelInitWriter writer={m,ScalarWriteCallbackV1};CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));
 m->config=hv_vm_config_create();CHECK(m->config && !_hv_vm_config_set_isa(m->config,2));
 CHECK(!hv_vm_create(m->config));CHECK(!VM27HVVMGetOwnedVMV1(&m->vm));
 CHECK(!hv_vm_map(m->host,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m->cpu,&exit,NULL) && m->cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->cpu,&m->retained));
 Put(m,0x4100,UINT64_MAX);Put(m,0x748,0);m->context[0x668]=0x83;
 Put(m,0x3f8,UINT64_C(0xfedcba9876543210));return m->cpu;
}
void VM27ScalarFixtureSeedV1(uint32_t oldField,uint64_t value){Put(&ScalarMockV1,oldField,value);}
uint64_t VM27ScalarFixtureFieldV1(uint32_t oldField){return Word(&ScalarMockV1,oldField);}
void VM27ScalarFixtureFailV1(bool readFailure,bool writeFailure) {
 ScalarReadFailureV1=readFailure;ScalarWriteFailureV1=writeFailure;
}
void VM27ScalarFixtureEndV1(bool poisoned) {
 Mock *m=&ScalarMockV1;ScalarReadFailureV1=ScalarWriteFailureV1=false;
 CHECK(!m->calls[9] && !m->calls[8]);
 CHECK(!VM27CPUFactoryBorrowReleaseV2(m->retained));m->retained=NULL;
 if(poisoned)CHECK(!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL));else CHECK(!hv_vcpu_destroy(m->cpu));
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy());CFRelease((CFTypeRef)m->config);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m->context,0x8000) && !munmap(m->host,0x8000));
}
unsigned VM27ScalarFixtureChecksV1(void){return Checks;}
