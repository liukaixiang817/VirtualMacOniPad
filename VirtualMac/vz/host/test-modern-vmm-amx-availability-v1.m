#include "modern_vmm_amx_availability_v1.h"
#include "modern_cpu_optional_abi_v1.h"
#define main FrozenRoot8FixtureMainAMXV1
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
#define UNSUPPORTED ((hv_return_t)UINT32_C(0xfae9400f))
static bool ControlHoldReleaseV18;
extern VZKernelStatus ControlActualReleaseV18(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *b) {
    return ControlHoldReleaseV18 ? VZ_KERNEL_BUSY : ControlActualReleaseV18(b);
}
typedef struct {
    Mock m;
    bool active;
    bool failBankRead, changeActive, changeOwner, foreignOwner, reenter;
} AMXMockV1;
static uint64_t AMXThreadV1(void *p) {
    AMXMockV1 *m=p;return Thread(&m->m)+(m->foreignOwner?1:0);
}
static bool AMXReadV1(void *p,const void *a,size_t n,void *out) {
    AMXMockV1 *m=p;uintptr_t off=(uintptr_t)a-(uintptr_t)m->m.context;
    if(m->active && off==0x4108 && m->failBankRead)return false;
    bool result=Read(&m->m,a,n,out);
    if(m->active && off==0x4110) {
        if(m->reenter) {
            uint32_t untouched=99;
            CHECK(VM27VMMGetAMXAvailabilityV1(m->m.cpu,&untouched)==BUSY && untouched==99);
        }
        if(m->changeActive){Put(&m->m,0x4110,Word(&m->m,0x4110)^1);m->changeActive=false;}
        if(m->changeOwner){m->foreignOwner=true;m->changeOwner=false;}
    }
    return result;
}
static void AMXBeginV1(AMXMockV1 *c) {
    memset(c,0,sizeof(*c));Mock *m=&c->m;
    m->context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    m->host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(m->context!=MAP_FAILED && m->host!=MAP_FAILED);
    VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,c,Trap,AMXThreadV1,AMXReadV1};
    VZKernelInitWriter writer={c,Write};
    CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m->config=hv_vm_config_create();CHECK(m->config);
    CHECK(!_hv_vm_config_set_isa(m->config,2));CHECK(!hv_vm_create(m->config));
    CHECK(!VM27HVVMGetOwnedVMV1(&m->vm));CHECK(!hv_vm_map(m->host,0x40000000,0x4000,7));
    hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m->cpu,&exit,NULL) && m->cpu && exit);
    CHECK(!VM27CPUFactoryBorrowAcquireV2(m->cpu,&m->retained));
    Put(m,0x4108,UINT64_C(0x30fffffffffffffa));Put(m,0x4110,5);c->active=true;
}
static void *AMXForeignV1(void *p) {
    AMXMockV1 *m=p;uint32_t out=99;
    CHECK(VM27VMMGetAMXAvailabilityV1(m->m.cpu,&out)==BAD && out==99);return NULL;
}
int main(void) {
    alarm(20);AMXMockV1 c;AMXBeginV1(&c);Mock *m=&c.m;
    const unsigned writes=m->writes;uint32_t out=99;
    CHECK(!VM27VMMGetAMXAvailabilityV1(m->cpu,&out) && out==0);
    /* Run can replace inactive with ~active. It cannot upgrade guest ISA. */
    Put(m,0x4108,~UINT64_C(5));out=99;
    CHECK(!VM27VMMGetAMXAvailabilityV1(m->cpu,&out) && out==0);
    Put(m,0x4110,UINT64_C(1)<<57);out=99;
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==UNSUPPORTED && out==99);Put(m,0x4110,5);
    c.failBankRead=true;CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==ERROR && out==99);c.failBankRead=false;
    c.changeActive=true;CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==BUSY && out==99);Put(m,0x4110,5);
    Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION^UINT64_C(0x100000000));
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)!=0 && out==99);Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
    CHECK(VM27VMMGetAMXAvailabilityV1(0,&out)==BAD && out==99);
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,NULL)==BAD);
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,(uint32_t *)(m->context+0x4110))==BAD && Word(m,0x4110)==5);
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,(uint32_t *)(m->context+0x5000))==BAD && Word(m,0x5000)==0);
    pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,AMXForeignV1,&c));CHECK(!pthread_join(foreign,NULL));
    c.reenter=true;CHECK(!VM27VMMGetAMXAvailabilityV1(m->cpu,&out) && out==0);c.reenter=false;out=99;
    c.changeOwner=true;CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==BAD && out==99);
    c.foreignOwner=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
    ControlHoldReleaseV18=true;CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==BUSY && out==99);
    CHECK(VM27VMMGetAMXAvailabilityV1(m->cpu,&out)==BUSY && out==99);
    ControlHoldReleaseV18=false;CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
    CHECK(!VM27VMMGetAMXAvailabilityV1(m->cpu,&out) && out==0);
    bool actual=true;CHECK(_hv_vcpu_amx_query_active_context(m->cpu,&actual)==UNSUPPORTED && actual);
    CHECK(m->writes==writes && !m->calls[8] && !m->calls[9]);c.active=false;
    CHECK(!VM27CPUFactoryBorrowReleaseV2(m->retained));m->retained=NULL;
    CHECK(!hv_vcpu_destroy(m->cpu));CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy());
    CFRelease((CFTypeRef)m->config);CHECK(!VM27HVVMUninstallNativeOpsV1());
    CHECK(!munmap(m->context,0x8000) && !munmap(m->host,0x8000));
    printf("{\"checks\":%u,\"actualRegistryAndLifecycle\":true,\"profileAbsence\":true,\"noPromotionFromInactive\":true,\"ownerVersionReadAndReleaseFailuresDoNotPublish\":true,\"releaseFailureRetainedForExistingDrain\":true,\"nativeCallsAdded\":0,\"nativeWritesAdded\":0,\"deviceOperations\":0}\n",Checks);
    return 0;
}
