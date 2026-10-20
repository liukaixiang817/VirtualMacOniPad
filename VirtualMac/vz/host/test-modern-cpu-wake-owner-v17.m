#include "vm27_hv_public_vm_bootstrap_v6.h"
#include "modern_cpu_kernel_wake_owner_v17.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do{atomic_fetch_add(&Checks,1);if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
#define BUSY ((hv_return_t)UINT32_C(0xfae94002))
static _Atomic unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *o){*o=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){*o=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){*o=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {
 unsigned char *native,*ram;unsigned calls[11];uint64_t lastMask;
 bool readFail,wakeFail,wakeInsideRun,blockWake,trapEntered,trapRelease;
 pthread_mutex_t mutex;pthread_cond_t cond;
 hv_vcpu_t id;VM27CPUFactoryVMV2 *vm;VZKernelCPUWakeOwnerV17 *wake;
 VZKernelRunPendingRequestV14 identity;VZKernelCPUWakeReceiptV17 asyncReceipt;
 VZKernelStatus asyncResult;
} Model;
static void Put(Model *m,unsigned off,uint64_t v){memcpy(m->native+off,&v,8);}
static uint64_t Thread(void *p){(void)p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static int32_t Trap(void *p,uint64_t op,void *packet) {
 Model *m=p;CHECK(op>=1 && op<=10);++m->calls[op];
 if(op==1){CHECK(packet && ((VZKernelNativeVMConfig *)packet)->nativeHVISA==2);return 0;}
 if(op==2 || op==4){CHECK(op==2?!packet:packet!=NULL);return 0;}
 if(op==3){CHECK(packet);return 0;}
 if(op==6){((uint64_t *)packet)[0]=63;((uint64_t *)packet)[1]=(uintptr_t)m->native;
  Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);return 0;}
 if(op==7 || op==8){CHECK(!packet);return 0;}
 if(op==9){CHECK(!packet && m->wakeInsideRun);VZKernelCPUWakeReceiptV17 r={0};
  CHECK(!VZKernelCPUWakeOwnerSignalV17(m->wake,&m->identity,&r));
  CHECK(r.nativeInvoked && r.nativeSlotMask==UINT64_C(0x8000000000000000));
  uint32_t reason=1,esr=0xf2000000;memcpy(m->native+0x4008,&reason,4);memcpy(m->native+0x400c,&esr,4);return 0;}
 CHECK((uintptr_t)packet==UINT64_C(0x8000000000000000));m->lastMask=(uintptr_t)packet;
 VZKernelCPUWakeReceiptV17 nested={0};
 CHECK(VZKernelCPUWakeOwnerSignalV17(m->wake,&m->identity,&nested)==VZ_KERNEL_BUSY);
 CHECK(!pthread_mutex_lock(&m->mutex));
 if(m->blockWake){m->trapEntered=true;CHECK(!pthread_cond_signal(&m->cond));
  while(!m->trapRelease)CHECK(!pthread_cond_wait(&m->cond,&m->mutex));}
 CHECK(!pthread_mutex_unlock(&m->mutex));return m->wakeFail?-10:0;
}
static bool Read(void *p,const void *src,size_t n,void *out) {
 Model *m=p;uintptr_t off=(uintptr_t)src-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 return !m->readFail && VM27CPUSelfReadV1(NULL,src,n,out);
}
static bool Write(void *p,void *dst,size_t n,const void *v) {
 Model *m=p;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;CHECK(off<0x8000 && n<=0x8000-off);
 return VM27CPUSelfWriteV1(NULL,dst,n,v);
}
static void *Async(void *p) {
 Model *m=p;CHECK(VZKernelCPUWakeOwnerDrainV17(m->wake)==VZ_KERNEL_WRONG_THREAD);
 m->asyncResult=VZKernelCPUWakeOwnerSignalV17(m->wake,&m->identity,&m->asyncReceipt);return NULL;
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());Model m={0};
 CHECK(!pthread_mutex_init(&m.mutex,NULL) && !pthread_cond_init(&m.cond,NULL));
 m.native=mmap(NULL,0x8000,3,MAP_PRIVATE|MAP_ANON,-1,0);m.ram=mmap(NULL,0x8000,3,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.native!=MAP_FAILED && m.ram!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));hv_vm_config_t cfg=hv_vm_config_create();CHECK(cfg);
 CHECK(!_hv_vm_config_set_isa(cfg,2) && !hv_vm_create(cfg));CHECK(!VM27HVVMGetOwnedVMV1(&m.vm));
 CHECK(!hv_vm_map(m.ram,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.id,&exit,NULL));
 VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));
 CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));m.identity=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,
  v.vmEpoch,m.id,Thread(&m),v.cpuGeneration,63};CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 CHECK(!VZKernelCPUWakeOwnerCreateV17(&m.identity,&m.wake));CHECK(m.wake && hv_vm_destroy()==BUSY);
 VZKernelCPUWakeReceiptV17 r={0};VZKernelRunPendingRequestV14 forged=m.identity;++forged.expectedCPUGeneration;
 CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&forged,&r)==VZ_KERNEL_BAD_ARGUMENT && !r.nativeInvoked && !m.calls[10]);
 CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,(void *)(m.native+0x4000))==VZ_KERNEL_BAD_ARGUMENT);
 Put(&m,0x4000,0);CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,&r)==VZ_KERNEL_CONTEXT_VERSION_MISMATCH && !m.calls[10]);
 Put(&m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);m.readFail=true;
 CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,&r)==VZ_KERNEL_CONTEXT_UNREADABLE && !m.calls[10]);m.readFail=false;
 m.wakeFail=true;CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,&r)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(r.nativeInvoked && r.nativeReturn==-10 && r.versionVerified);m.wakeFail=false;
 CHECK(!VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,&r) && m.calls[10]==2);
 CHECK(r.nativeSlotMask==UINT64_C(0x8000000000000000));bool pending=true;
 CHECK(!hv_vcpu_get_pending_interrupt(m.id,HV_INTERRUPT_TYPE_IRQ,&pending) && !pending);
 m.wakeInsideRun=true;CHECK(!hv_vcpu_run(m.id) && m.calls[9]==1 && m.calls[10]==3);
 CHECK(exit->exception.syndrome==0xf2000000);
 // A genuine async callback remains pinned when owner teardown races it.
 m.blockWake=true;pthread_t worker;CHECK(!pthread_create(&worker,NULL,Async,&m));
 CHECK(!pthread_mutex_lock(&m.mutex));while(!m.trapEntered)CHECK(!pthread_cond_wait(&m.cond,&m.mutex));
 CHECK(!pthread_mutex_unlock(&m.mutex));CHECK(VZKernelCPUWakeOwnerDestroyV17(m.wake)==VZ_KERNEL_BUSY);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && !m.calls[7]);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY && hv_vm_destroy()==BUSY);
 CHECK(VZKernelCPUWakeOwnerSignalV17(m.wake,&m.identity,&r)==VZ_KERNEL_NOT_LIVE && r.callbackDraining);
 CHECK(!pthread_mutex_lock(&m.mutex));m.trapRelease=true;CHECK(!pthread_cond_signal(&m.cond));CHECK(!pthread_mutex_unlock(&m.mutex));
 // OwnerCleanup withdraws publication before noticing the live borrow. The
 // already-started wake remains safe, and its postcheck reports that change.
 CHECK(!pthread_join(worker,NULL) && m.asyncResult==VZ_KERNEL_NOT_LIVE && m.asyncReceipt.nativeInvoked);
 CHECK(!VZKernelCPUWakeOwnerDrainV17(m.wake));CHECK(!VZKernelCPUWakeOwnerDestroyV17(m.wake));m.wake=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL) && m.calls[7]==1);
 CHECK(!hv_vm_unmap(0x40000000,0x4000) && !hv_vm_destroy());CFRelease((CFTypeRef)cfg);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m.native,0x8000) && !munmap(m.ram,0x8000));
 CHECK(!pthread_mutex_destroy(&m.mutex) && !pthread_cond_destroy(&m.cond));
 printf("{\"checks\":%u,\"native10ModelCalls\":%u,\"native9ModelCalls\":%u,\"asyncCallbackDrainRetainsCPUVMRAM\":true,\"highestSlotMask\":\"0x8000000000000000\",\"wakeInsideRunVerified\":true,\"actualNativeCalls\":0,\"deviceOperations\":0}\n",atomic_load(&Checks),m.calls[10],m.calls[9]);return 0;
}
