#define main FactoryGICParentFixtureV20
#include "test-modern-cpu-gic-factory-v15.m"
#undef main
#include "modern_cpu_kernel_vtimer_mask_v20.h"
static bool MaskWriteFailV20;
static unsigned MaskWritesV20;
static bool MaskWriteV20(void *context,void *dst,size_t bytes,const void *value) {
 Model *m=context;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;
 bool ok=Write(context,dst,bytes,value);
 if(off==0x6d8){++MaskWritesV20;CHECK(bytes==8);if(MaskWriteFailV20)return false;}
 return ok;
}
static void MaskNewV20(Model *m) {
 memset(m,0,sizeof(*m));m->now=100;MaskWriteFailV20=false;MaskWritesV20=0;
 m->native=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m->native!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,Read};
 VZKernelInitWriter writer={m,MaskWriteV20};VZKernelVMOptions options={36,0,2,false,false};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->vm,NULL));
 VM27CPUFactoryVMGICDescriptionV15 d={0};CHECK(!VM27CPUFactoryVMGICDescribeV15(m->vm,&d));
 VM27GICConfigV1 config={1,1,36,0,d.vmEpoch,0x10000,0x20000,0,0,0,false};
 VM27CPUFactoryGICSchedulerV15 scheduler={m,Schedule,Drain};
 CHECK(!VM27CPUFactoryVMGICInstallV15(m->vm,&config,&scheduler));
 CHECK(!hv_vcpu_create(&m->id,&m->exit,NULL));
}
typedef struct {
 VM27CPUFactoryBorrowV2 *factory;
 VZKernelCPUBorrowV5 *lower;
 VZKernelCPU *cpu;
 VZKernelRunPendingRequestV14 q;
 VZKernelInitWriter writer;
} MaskLeaseV20;
static MaskLeaseV20 MaskAcquireV20(Model *m) {
 MaskLeaseV20 lease={0};VM27CPUFactoryViewV2 view={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&lease.factory));
 CHECK(!VM27CPUFactoryBorrowViewV2(lease.factory,&view));
 CHECK(!VZKernelCPUBorrowIdentityV5(m->id,&lease.lower));CHECK(!VZKernelCPUBorrowHandleV5(lease.lower,&lease.cpu));
 lease.q=(VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,
  view.vmEpoch,m->id,Thread(m),view.cpuGeneration,0};
 lease.writer=(VZKernelInitWriter){m,MaskWriteV20};return lease;
}
static void MaskReleaseV20(MaskLeaseV20 *lease) {
 CHECK(!VZKernelCPUReleaseBorrowV5(lease->lower));CHECK(!VM27CPUFactoryBorrowReleaseV2(lease->factory));
}
static VZKernelStatus MaskAccessV20(MaskLeaseV20 *lease,bool write,bool mask,bool *out,VZKernelVtimerMaskReceiptV20 *receipt) {
 VZKernelLifecycleResult result={0};VZKernelStatus s=VZKernelCPUAccessVtimerMaskV20(lease->cpu,
  &lease->q,&lease->writer,write,mask,out,receipt,&result);
 CHECK(!result.nativeInvoked);return s;
}
static void MaskSuccessV20(void) {
 Model m;MaskNewV20(&m);MaskLeaseV20 lease=MaskAcquireV20(&m);
 const uint64_t preserved=UINT64_C(0xabc9876543210000);Put(&m,0x6d8,preserved);
 uint64_t ready=Word(&m,0x4100),dirty=Word(&m,0x748);unsigned traps[11];memcpy(traps,m.calls,sizeof(traps));
 bool out=true;VZKernelVtimerMaskReceiptV20 receipt={0};
 CHECK(!MaskAccessV20(&lease,false,false,&out,&receipt) && !out && receipt.attemptedReads==1 && !receipt.attemptedWrites);
 for(unsigned i=0;i<16;++i) {
  bool value=(i&1)==0;CHECK(!MaskAccessV20(&lease,true,value,NULL,&receipt));
  CHECK(Word(&m,0x6d8)==(preserved|(uint64_t)value) && receipt.completedWrites==1);
  CHECK(!MaskAccessV20(&lease,false,false,&out,&receipt) && out==value);
 }
 CHECK(MaskWritesV20==16 && ready==Word(&m,0x4100) && dirty==Word(&m,0x748));
 CHECK(!memcmp(traps,m.calls,sizeof(traps)));MaskReleaseV20(&lease);Clean(&m,false);
}
static void MaskFailuresV20(void) {
 Model m;MaskNewV20(&m);MaskLeaseV20 lease=MaskAcquireV20(&m);VZKernelVtimerMaskReceiptV20 receipt={0};
 bool out=false;uint64_t before=Word(&m,0x6d8);VZKernelRunPendingRequestV14 q=lease.q;
 ++lease.q.expectedCPUGeneration;CHECK(MaskAccessV20(&lease,true,true,NULL,&receipt)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!MaskWritesV20 && Word(&m,0x6d8)==before);lease.q=q;
 CHECK(MaskAccessV20(&lease,false,true,&out,&receipt)==VZ_KERNEL_BAD_ARGUMENT && !out);
 CHECK(MaskAccessV20(&lease,false,false,(bool *)(m.native+0x6d8),&receipt)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!MaskWritesV20);MaskWriteFailV20=true;
 CHECK(MaskAccessV20(&lease,true,true,NULL,&receipt)==VZ_KERNEL_CONTEXT_UNREADABLE);
 CHECK(receipt.mutationPoisoned && receipt.identityWithdrawn && receipt.attemptedWrites==1 && !receipt.completedWrites);
 CHECK((Word(&m,0x6d8)&1) && MaskWritesV20==1);MaskWriteFailV20=false;
 CHECK(!VM27CPUFactoryPoisonGICCPUV15(m.id,q.expectedVMEpoch,q.expectedCPUGeneration));
 CHECK(hv_vcpu_run(m.id)==BAD && !m.calls[9]);MaskReleaseV20(&lease);Clean(&m,true);
 // Callback invalidates the read output after initial range validation: no
 // read success is published and no write or poison is invented.
 MaskNewV20(&m);lease=MaskAcquireV20(&m);
 bool *page=mmap(NULL,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(page!=MAP_FAILED);*page=true;
 m.invalidatedOutput=page;m.invalidateOnVersion=true;
 CHECK(MaskAccessV20(&lease,false,false,page,&receipt)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!mprotect(page,0x4000,PROT_READ|PROT_WRITE) && *page);
 CHECK(!MaskWritesV20);MaskReleaseV20(&lease);CHECK(!munmap(page,0x4000));Clean(&m,false);
 // A failed final receipt/output check after a successful real write retains
 // the changed native field, poisons its real owner, and requires cleanup.
 MaskNewV20(&m);lease=MaskAcquireV20(&m);q=lease.q;
 page=mmap(NULL,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(page!=MAP_FAILED);*page=true;
 m.invalidatedOutput=page;m.invalidateOnVersion=true;
 CHECK(MaskAccessV20(&lease,true,true,page,&receipt)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!mprotect(page,0x4000,PROT_READ|PROT_WRITE) && *page && MaskWritesV20==1 && (Word(&m,0x6d8)&1));
 CHECK(!VM27CPUFactoryPoisonGICCPUV15(m.id,q.expectedVMEpoch,q.expectedCPUGeneration));
 MaskReleaseV20(&lease);CHECK(!munmap(page,0x4000));Clean(&m,true);
}
int main(void) {
 alarm(25);MaskSuccessV20();MaskFailuresV20();
 printf("{\"checks\":%u,\"actualFactoryAndKernelBorrow\":true,\"native6d8Full64Preserved\":true,\"dirtyReadyUnchanged\":true,\"partialWritesPoisonActualOwner\":true,\"native8And9And10Invoked\":false,\"rawExitClassified\":false,\"publicMaskAPIIntegrated\":false,\"allNativeCallsMocked\":true,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks);return 0;
}
