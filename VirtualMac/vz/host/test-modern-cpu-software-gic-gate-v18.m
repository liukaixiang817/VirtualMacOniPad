#include "vm27_hv_public_vm_bootstrap_v6.h"
#include "modern_cpu_kernel_software_gic_gate_v18.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do{++Checks;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
static unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *o){*o=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){*o=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){*o=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {
 unsigned char *native,*ram;unsigned calls[10];uint32_t failOffset;
 bool reenter,changeVersion;VZKernelCPU *cpu;VZKernelRunPendingRequestV14 identity;
} Model;
static void Put(Model *m,unsigned off,uint64_t v){memcpy(m->native+off,&v,8);}
static uint64_t Thread(void *p){(void)p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static int32_t Trap(void *p,uint64_t op,void *packet) {
 Model *m=p;CHECK(op>=1 && op<=9);++m->calls[op];
 if(op==1){CHECK(packet && ((VZKernelNativeVMConfig *)packet)->nativeHVISA==2);return 0;}
 if(op==2 || op==4){CHECK(op==2?!packet:packet!=NULL);return 0;}
 if(op==3){CHECK(packet);return 0;}
 if(op==6){((uint64_t *)packet)[0]=0;((uint64_t *)packet)[1]=(uintptr_t)m->native;
  Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);Put(m,0x6f8,0x1c00);Put(m,0x40b0,0x3c00);return 0;}
 CHECK(op==7 && !packet);return 0;
}
static bool Read(void *p,const void *src,size_t n,void *out) {
 Model *m=p;uintptr_t off=(uintptr_t)src-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 if(off==0x6f8 && m->reenter) {
  VZKernelSoftwareGICTrapReceiptV18 r={0};VZKernelLifecycleResult l={0};
  CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m->cpu,&m->identity,&r,&l)==VZ_KERNEL_BUSY);
 }
 if(off==m->failOffset)return false;
 bool ok=VM27CPUSelfReadV1(NULL,src,n,out);
 if(off==0x6f8 && m->changeVersion)Put(m,0x4000,0);
 return ok;
}
static bool Write(void *p,void *dst,size_t n,const void *v) {
 Model *m=p;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 return VM27CPUSelfWriteV1(NULL,dst,n,v);
}
static void *Foreign(void *p) {
 Model *m=p;VZKernelSoftwareGICTrapReceiptV18 r={0};VZKernelLifecycleResult l={0};
 CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m->cpu,&m->identity,&r,&l)==VZ_KERNEL_WRONG_THREAD);return NULL;
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());Model m={0};m.failOffset=UINT32_MAX;
 m.native=mmap(NULL,0x8000,3,MAP_PRIVATE|MAP_ANON,-1,0);m.ram=mmap(NULL,0x8000,3,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.native!=MAP_FAILED && m.ram!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));hv_vm_config_t cfg=hv_vm_config_create();CHECK(cfg);
 CHECK(!_hv_vm_config_set_isa(cfg,2) && !hv_vm_create(cfg));CHECK(!hv_vm_map(m.ram,0x40000000,0x4000,7));
 hv_vcpu_t id=0;hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&id,&exit,NULL));
 VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};CHECK(!VM27CPUFactoryBorrowAcquireV2(id,&b));
 CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));m.identity=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,v.vmEpoch,id,Thread(&m),v.cpuGeneration,0};
 CHECK(!VM27CPUFactoryBorrowReleaseV2(b));VZKernelCPUBorrowV5 *borrow=NULL;
 CHECK(!VZKernelCPUBorrowIdentityV5(id,&borrow) && !VZKernelCPUBorrowHandleV5(borrow,&m.cpu));
 VZKernelSoftwareGICTrapReceiptV18 r={0};VZKernelLifecycleResult l={0};
 m.reenter=true;CHECK(!VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l));m.reenter=false;
 CHECK(r.actualFieldsRead && r.commonAndBothGroupTrapsEnabled && r.nativeGICDisabled && r.attemptedReads==2);
 CHECK(r.requestedICHControl==0x1c00 && r.effectiveICHControl==0x3c00 && !r.actualSRETrapProved && !r.fullRunAllowed);
 CHECK(!r.actualPhysicalTimerTrapProved && !m.calls[8] && !m.calls[9]);
 uint64_t saved=0;memcpy(&saved,m.native+0x6f8,8);CHECK(saved==0x1c00);
 Put(&m,0x6f8,0x1c01);CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_UNSUPPORTED && !r.nativeGICDisabled);
 Put(&m,0x6f8,0x1c00);Put(&m,0x40b0,0x3c01);CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_UNSUPPORTED);
 Put(&m,0x40b0,0x2c00);CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_UNSUPPORTED && !r.commonAndBothGroupTrapsEnabled);
 Put(&m,0x40b0,0x3c00);Put(&m,0x6f8,0x1800);CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_UNSUPPORTED);
 Put(&m,0x6f8,0x1c00);m.failOffset=0x40b0;CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_CONTEXT_UNREADABLE && r.failedNativeOffset==0x40b0);
 m.failOffset=UINT32_MAX;m.changeVersion=true;
 CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l)==VZ_KERNEL_CONTEXT_VERSION_MISMATCH && !r.actualFieldsRead);
 m.changeVersion=false;Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);
 VZKernelRunPendingRequestV14 forged=m.identity;++forged.expectedCPUGeneration;
 CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&forged,&r,&l)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,(void *)(m.native+0x4000),&l)==VZ_KERNEL_BAD_ARGUMENT);
 pthread_t worker;CHECK(!pthread_create(&worker,NULL,Foreign,&m) && !pthread_join(worker,NULL));
 CHECK(!VZKernelCPUCheckSoftwareGICTrapV18(m.cpu,&m.identity,&r,&l));
 CHECK(!VZKernelCPUReleaseBorrowV5(borrow));CHECK(!hv_vcpu_destroy(id) && !hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());
 CFRelease((CFTypeRef)cfg);CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m.native,0x8000) && !munmap(m.ram,0x8000));
 printf("{\"checks\":%u,\"native8ModelCalls\":%u,\"native9ModelCalls\":%u,\"readOnly\":true,\"trueOwnerVersionGuard\":true,\"actualNativeCalls\":0,\"deviceOperations\":0}\n",Checks,m.calls[8],m.calls[9]);return 0;
}
