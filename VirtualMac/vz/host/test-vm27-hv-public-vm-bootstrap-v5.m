#include "vm27_hv_public_vm_bootstrap_v5.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(v) do{++Checks;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);abort();}}while(0)
#define BAD ((hv_return_t)UINT32_C(0xfae94003))
#define BUSY ((hv_return_t)UINT32_C(0xfae94002))
#define ERROR ((hv_return_t)UINT32_C(0xfae94001))
static unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *out){*out=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *out){*out=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out){*out=(VM27CPUTLBICapabilityValueV1){0};}
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
typedef struct {
 unsigned char *context,*host;
 unsigned calls[10],writes,reentryChecks,failMapOp;
 bool reenter,failWrite,failDestroy;
 hv_vm_config_t config;
 hv_vcpu_t cpu;
 VM27CPUFactoryVMV2 *vm;
 VM27CPUFactoryBorrowV2 *retained;
} Mock;
static uint64_t Thread(void *p){(void)p;uint64_t id=0;CHECK(!pthread_threadid_np(NULL,&id));return id;}
static int32_t Trap(void *p,uint64_t op,void *arg) {
 Mock *m=p;CHECK(op>=1 && op<=7);++m->calls[op];
 if(op==1) {
  VZKernelNativeVMConfig *c=arg;
  CHECK(c && !c->reserved && c->ipaLimit==(UINT64_C(1)<<36) && !c->ipaGranule && c->nativeHVISA==2);return 0;
 }
 if(op==2){CHECK(!arg);return m->failDestroy?-19:0;}
 if(op==6) {
  CHECK(arg && !((uint64_t *)arg)[0] && !((uint64_t *)arg)[1]);
  ((uint64_t *)arg)[1]=(uintptr_t)m->context;
  uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->context+0x4000,&magic,8);return 0;
 }
 if(op==3 || op==4 || op==5) {
  VZKernelMemoryPacket *packet=arg;
  CHECK(packet && packet->guestAddress==0x40000000 && packet->bytes==0x4000 && !packet->spaceWord);
  CHECK(packet->hostAddress==(op==3?(uintptr_t)m->host:0));
  return m->failMapOp==op?-17:0;
 }
 CHECK(op==7 && !arg);return 0;
}
static bool Read(void *p,const void *source,size_t n,void *out) {
 Mock *m=p;uintptr_t off=(uintptr_t)source-(uintptr_t)m->context;
 CHECK(off<0x8000 && n<=0x8000-off);return VM27CPUSelfReadV1(NULL,source,n,out);
}
static void Reenter(Mock *m) {
 ++m->reentryChecks;unsigned map=m->calls[3],unmap=m->calls[4],protect=m->calls[5],destroy=m->calls[2];
 VM27CPUFactoryVMV2 *same=NULL;CHECK(!VM27HVVMGetOwnedVMV1(&same) && same==m->vm);
 CHECK(hv_vm_create(m->config)==BUSY);CHECK(hv_vm_destroy()==BUSY);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY);CHECK(hv_vm_protect(0x40000000,0x4000,1)==BUSY);
 CHECK(hv_vm_map(m->host+0x4000,0x40010000,0x4000,7)==BUSY);
 CHECK(VM27HVVMUninstallNativeOpsV1()==BUSY);
 CHECK(m->calls[3]==map && m->calls[4]==unmap && m->calls[5]==protect && m->calls[2]==destroy);
 uint32_t count=55;CHECK(!hv_vm_get_max_vcpu_count(&count) && count==64);
 CHECK(hv_vm_get_max_vcpu_count((uint32_t *)(void *)m->config)==BAD);
 CHECK(hv_vm_get_max_vcpu_count((uint32_t *)(void *)m->retained)==BAD);
 CHECK(hv_vm_get_max_vcpu_count((uint32_t *)(void *)(m->context+8))==BAD);
 CHECK(hv_vcpu_set_vtimer_offset(m->cpu,999)==BUSY);
 CHECK(hv_vcpu_set_trap_debug_exceptions(m->cpu,true)==BUSY);
 CHECK(hv_vcpu_set_trap_debug_reg_accesses(m->cpu,false)==BUSY);
}
static bool Write(void *p,void *target,size_t n,const void *value) {
 Mock *m=p;uintptr_t off=(uintptr_t)target-(uintptr_t)m->context;
 CHECK(off<0x8000 && n<=0x8000-off);++m->writes;
 if(m->reenter)Reenter(m);
 bool changed=VM27CPUSelfWriteV1(NULL,target,n,value);return changed && !m->failWrite;
}
static uint64_t Word(Mock *m,uint32_t off){uint64_t w=0;memcpy(&w,m->context+off,8);return w;}
static void Put(Mock *m,uint32_t off,uint64_t w){memcpy(m->context+off,&w,8);}
static void *Foreign(void *p) {
 Mock *m=p;VM27CPUFactoryVMV2 *out=(void *)1;
 CHECK(hv_vm_destroy()==BAD);CHECK(VM27HVVMGetOwnedVMV1(&out)==BAD && out==(void *)1);
 CHECK(hv_vm_unmap(0x40000000,0x4000)==BAD);
 CHECK(hv_vm_map(m->host+0x4000,0x40010000,0x4000,7)==BAD);
 CHECK(hv_vcpu_set_vtimer_offset(m->cpu,9)==BAD);
 CHECK(hv_vcpu_set_trap_debug_exceptions(m->cpu,true)==BAD);
 CHECK(hv_vcpu_set_trap_debug_reg_accesses(m->cpu,true)==BAD);return NULL;
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());
 _Static_assert(sizeof(hv_return_t)==4 && sizeof(hv_vcpu_t)==8 && sizeof(bool)==1,"actual public ABI");
 hv_return_t (*maxCaller)(uint32_t *)=hv_vm_get_max_vcpu_count;
 uint32_t canary[3]={UINT32_C(0xabcdef01),55,UINT32_C(0x12345678)};
 CHECK(!maxCaller(&canary[1]) && canary[1]==64 && canary[0]==UINT32_C(0xabcdef01) && canary[2]==UINT32_C(0x12345678));
 CHECK(maxCaller(NULL)==BAD);
 Mock m={0};m.context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.context!=MAP_FAILED && m.host!=MAP_FAILED && !((uintptr_t)m.host&0x3fff));memset(m.host,0x6b,0x8000);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m.config=hv_vm_config_create();CHECK(m.config);
 CHECK(maxCaller((uint32_t *)(void *)m.config)==BAD);CHECK(!_hv_vm_config_set_isa(m.config,2));
 CHECK(!hv_vm_create(m.config));CHECK(!VM27HVVMGetOwnedVMV1(&m.vm) && m.vm);
 CHECK(!hv_vm_map(m.host,0x40000000,0x4000,7));CHECK(m.calls[1]==1 && m.calls[3]==1);
 CHECK(maxCaller((uint32_t *)(void *)m.host)==BAD && m.host[0]==0x6b);
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.cpu,&exit,NULL) && m.cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.cpu,&m.retained));VM27CPUFactoryViewV2 view={0};
 CHECK(!VM27CPUFactoryBorrowViewV2(m.retained,&view));CHECK(view.identity==m.cpu && view.vmEpoch && view.cpuGeneration);
 CHECK(maxCaller((uint32_t *)(void *)exit)==BAD);CHECK(maxCaller((uint32_t *)(void *)(m.context+8))==BAD);
 Put(&m,0x688,UINT64_C(0xdeadbeef00000300));Put(&m,0x748,UINT64_C(0x8000000000000020));
 m.reenter=true;VZKernelInitReceipt receipt={0};VM27CPUFactoryDiagnosticV2 diag={0};
 CHECK(!VM27CPUFactoryBorrowSetVtimerOffsetV10(m.retained,UINT64_C(0x123456789abcdef0),&receipt,&diag));
 CHECK(receipt.completedWrites==2 && diag.vmEpoch==view.vmEpoch && diag.cpuGeneration==view.cpuGeneration);
 CHECK(Word(&m,0x6a0)==UINT64_C(0x123456789abcdef0) && Word(&m,0x748)==UINT64_C(0x8000000000000024));
 CHECK(!hv_vcpu_set_trap_debug_exceptions(m.cpu,false));CHECK(Word(&m,0x688)==UINT64_C(0xdeadbeef00000200));
 CHECK(!hv_vcpu_set_trap_debug_reg_accesses(m.cpu,true));CHECK(Word(&m,0x688)==UINT64_C(0xdeadbeef00000200));m.reenter=false;
 CHECK(m.reentryChecks==10 && m.calls[8]==0 && m.calls[9]==0);
 unsigned writes=m.writes;pthread_t t;CHECK(!pthread_create(&t,NULL,Foreign,&m));CHECK(!pthread_join(t,NULL));
 CHECK(m.writes==writes && m.calls[2]==0 && m.calls[4]==0 && m.calls[5]==0);
 // A false writer has already changed real mapped data. The permanent ID
 // withdrawal retains CPU, VM, RAM and caller backing through actual drain.
 m.failWrite=true;CHECK(hv_vcpu_set_vtimer_offset(m.cpu,UINT64_C(0xfedcba9876543210))==ERROR);
 CHECK(Word(&m,0x6a0)==UINT64_C(0xfedcba9876543210));m.failWrite=false;
 CHECK(hv_vcpu_set_trap_debug_exceptions(m.cpu,true)==BAD);
 CHECK(hv_vm_destroy()==BUSY && m.calls[2]==0);CHECK(hv_vm_unmap(0x40000000,0x4000)==BUSY && m.calls[4]==0);
 CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && m.calls[7]==0);
 CHECK(!VM27CPUFactoryBorrowReleaseV2(m.retained));m.retained=NULL;
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL) && m.calls[7]==1);
 CHECK(hv_vm_destroy()==BUSY && m.calls[2]==0);
 m.failMapOp=4;CHECK(hv_vm_unmap(0x40000000,0x4000)==ERROR);CHECK(hv_vm_destroy()==BUSY && m.calls[2]==0);
 CHECK(VM27CPUSelfMappedRangeV1(m.host,0x8000,true,NULL) && m.host[0]==0x6b);
 m.failMapOp=0;CHECK(!hv_vm_unmap(0x40000000,0x4000));
 m.failMapOp=3;CHECK(hv_vm_map(m.host,0x40000000,0x4000,7)==ERROR);
 CHECK(hv_vm_destroy()==BUSY && m.calls[2]==0);CHECK(maxCaller((uint32_t *)(void *)m.host)==BAD && m.host[0]==0x6b);
 m.failMapOp=0;CHECK(!hv_vm_unmap(0x40000000,0x4000));
 m.failDestroy=true;CHECK(hv_vm_destroy()==ERROR && m.calls[2]==1);
 VM27CPUFactoryVMV2 *retainedVM=NULL;CHECK(!VM27HVVMGetOwnedVMV1(&retainedVM) && retainedVM==m.vm);
 m.failDestroy=false;CHECK(!hv_vm_destroy() && m.calls[2]==2);
 CFRelease((CFTypeRef)m.config);CHECK(!VM27HVVMUninstallNativeOpsV1());
 CHECK(!munmap(m.context,0x8000) && !munmap(m.host,0x8000));
 uint64_t vmCreated=0,vmDestroyed=0,cpuCreated=0,cpuDestroyed=0;
 VM27HVVMTestConfigCountsV1(&vmCreated,&vmDestroyed);VM27CPUConfigTestCountsV3(&cpuCreated,&cpuDestroyed);
 CHECK(vmCreated==1 && vmDestroyed==1 && cpuCreated==1 && cpuDestroyed==1);
 printf("{\"checks\":%u,\"VMConfigCreated\":1,\"VMConfigDestroyed\":1,\"CPUConfigCreated\":1,\"CPUConfigDestroyed\":1,\"combinedStrongGuard\":true,\"sameOwnerAndVMEpoch\":true,\"writerReentries\":%u,\"native8\":0,\"native9\":0,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"maxVCPUFrameworkUpperBound\":64,\"maxOutputBytes\":4,\"full27Backend\":false}\n",Checks,m.reentryChecks);
 return 0;
}
