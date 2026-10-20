#include "modern_vmm_mandatory_field_v2.h"
#define main InheritedRoot8FieldFixtureMainV2
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
static bool FieldHoldReleaseV2,FieldTraceV2,FieldReadFailV2;
static unsigned FieldReadsV2,FieldWritesV2,FieldFailWriteV2,FieldReleaseAttemptsV2;
extern VM27CPUFactoryMachStatusV2 RealFactoryBorrowReleaseForFieldV2(VM27CPUFactoryBorrowV2 *);
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowReleaseV2(VM27CPUFactoryBorrowV2 *borrow) {
 ++FieldReleaseAttemptsV2;
 return FieldHoldReleaseV2?BUSY:RealFactoryBorrowReleaseForFieldV2(borrow);
}
static bool FieldReadV2(void *opaque,const void *source,size_t bytes,void *out) {
 Mock *m=opaque;uintptr_t off=(uintptr_t)source-(uintptr_t)m->context;
 if(FieldTraceV2 && (off==0x668 || off==0x3f8)) {
  CHECK(bytes==(off==0x668?1:8));++FieldReadsV2;if(FieldReadFailV2)return false;
 }
 return Read(opaque,source,bytes,out);
}
static bool FieldWriteV2(void *opaque,void *target,size_t bytes,const void *value) {
 Mock *m=opaque;uintptr_t off=(uintptr_t)target-(uintptr_t)m->context;
 if(FieldTraceV2) {
  CHECK((off==0x668 && bytes==1) || ((off==0x3f8 || off==0x748) && bytes==8));++FieldWritesV2;
  uint64_t output=77;
  CHECK(VM27VMMGetMandatoryFieldV2(m->cpu,0x410,&output)==BUSY && output==77);
  CHECK(VM27VMMSetMandatoryFieldV2(m->cpu,0x6a0,3)==BUSY);
  CHECK(VM27VMMDrainMandatoryFieldBorrowV2()==BUSY);
  CHECK(hv_vcpu_destroy(m->cpu)==BUSY && hv_vm_destroy()==BUSY && !m->calls[7] && !m->calls[2]);
 }
 bool changed=Write(opaque,target,bytes,value);
 return changed && !(FieldTraceV2 && FieldWritesV2==FieldFailWriteV2);
}
static void FieldCreateV2(Mock *m) {
 memset(m,0,sizeof(*m));FieldTraceV2=false;FieldReadFailV2=FieldHoldReleaseV2=false;
 FieldWritesV2=FieldReadsV2=FieldFailWriteV2=0;
 m->context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m->host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m->context!=MAP_FAILED && m->host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,FieldReadV2};
 VZKernelInitWriter writer={m,FieldWriteV2};CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));
 m->config=hv_vm_config_create();CHECK(m->config && !_hv_vm_config_set_isa(m->config,2));
 CHECK(!hv_vm_create(m->config));CHECK(!VM27HVVMGetOwnedVMV1(&m->vm));
 CHECK(!hv_vm_map(m->host,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m->cpu,&exit,NULL) && m->cpu && exit);
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->cpu,&m->retained));
 m->context[0x668]=0x83;Put(m,0x3f8,UINT64_C(0x83a4b5c607081902));
 Put(m,0x4100,3);Put(m,0x748,UINT64_C(0x8000000000000040));FieldTraceV2=true;
}
static void FieldCleanV2(Mock *m,bool poisoned) {
 FieldTraceV2=false;CHECK(!VM27CPUFactoryBorrowReleaseV2(m->retained));m->retained=NULL;
 if(poisoned)CHECK(!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL));else CHECK(!hv_vcpu_destroy(m->cpu));
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy());CFRelease((CFTypeRef)m->config);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!munmap(m->context,0x8000) && !munmap(m->host,0x8000));
}
static void *FieldForeignV2(void *opaque) {
 Mock *m=opaque;uint64_t out=77;
 CHECK(VM27VMMGetMandatoryFieldV2(m->cpu,0x410,&out)==BAD && out==77);
 CHECK(VM27VMMSetMandatoryFieldV2(m->cpu,0x6a0,3)==BAD);return NULL;
}
static void FieldSuccessV2(void) {
 Mock m;FieldCreateV2(&m);unsigned char frame[0x600];memset(frame,0xab,sizeof(frame));
 CHECK(!VM27VMMGetMandatoryFieldV2(m.cpu,0x6a0,frame+0x5d8));
 CHECK(frame[0x5d8]==0x83 && frame[0x5d9]==0xab && !FieldWritesV2);
 // Preserve the genuine interleaved call sequence: the new private adapter
 // performs one field, never reading ACTLR before the original MDCCINT call.
 CHECK(FieldReadsV2==1);CHECK(!VM27VMMGetMandatoryFieldV2(m.cpu,0x410,frame+0x5f8));
 uint64_t actlr=0;memcpy(&actlr,frame+0x5f8,8);CHECK(actlr==UINT64_C(0x83a4b5c607081902));
 for(unsigned i=0;i<sizeof(frame);++i)if(i!=0x5d8 && (i<0x5f8 || i>=0x600))CHECK(frame[i]==0xab);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x688,frame)==BAD);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,m.context+0x3f8)==BAD);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,m.host)==BAD);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,m.retained)==BAD);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,(void *)1)==BAD);
 CHECK(VM27VMMSetMandatoryFieldV2(m.cpu,0x6a0,0x100)==BAD && !FieldWritesV2);
 CHECK(!VM27VMMSetMandatoryFieldV2(m.cpu,0x6a0,0x44));
 CHECK(!VM27VMMSetMandatoryFieldV2(m.cpu,0x410,UINT64_C(0xf1e2d3c4b5a69782)));
 CHECK(m.context[0x668]==0x44 && Word(&m,0x3f8)==UINT64_C(0xf1e2d3c4b5a69782));
 CHECK(Word(&m,0x748)==UINT64_C(0x8000000000000043) && FieldWritesV2==4 && !m.calls[9]);
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,FieldForeignV2,&m));CHECK(!pthread_join(thread,NULL));
 FieldReadFailV2=true;uint64_t value=77;
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,&value)==ERROR && value==77);FieldReadFailV2=false;
 FieldHoldReleaseV2=true;unsigned releases=FieldReleaseAttemptsV2;
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x410,&value)==BUSY && value==77 && FieldReleaseAttemptsV2==releases+1);
 CHECK(VM27VMMGetMandatoryFieldV2(m.cpu,0x6a0,frame)==BUSY && frame[0]==0xab);
 CHECK(VM27VMMDrainMandatoryFieldBorrowV2()==BUSY && hv_vcpu_destroy(m.cpu)==BUSY);
 unsigned writes=FieldWritesV2;FieldHoldReleaseV2=false;
 CHECK(!VM27VMMDrainMandatoryFieldBorrowV2() && FieldWritesV2==writes);
 CHECK(!VM27VMMDrainMandatoryFieldBorrowV2());
 // The explicit public destroy above starts genuine draining even while a
 // release is held. Finish through the retained owner, never republish its ID.
 VM27CPUFactoryBorrowV2 *extra=NULL;
 CHECK(VM27CPUFactoryBorrowAcquireV2(m.cpu,&extra)==BAD && !extra);FieldCleanV2(&m,true);
}
static void FieldFailuresV2(void) {
 for(unsigned which=0;which<2;++which)for(unsigned fail=1;fail<=2;++fail) {
  Mock m;FieldCreateV2(&m);FieldFailWriteV2=fail;
  CHECK(VM27VMMSetMandatoryFieldV2(m.cpu,which?0x410:0x6a0,which?UINT64_MAX:0xff)==ERROR);
  CHECK(FieldWritesV2==fail && !m.calls[9]);VM27CPUFactoryBorrowV2 *extra=NULL;
  CHECK(VM27CPUFactoryBorrowAcquireV2(m.cpu,&extra)==BAD && !extra);
  CHECK(VM27CPUFactoryOwnerCleanupV2(m.vm,NULL)==BUSY && !m.calls[7]);
  CHECK(hv_vm_destroy()==BUSY && !m.calls[2] && VM27CPUSelfMappedRangeV1(m.host,0x8000,true,NULL));
  FieldCleanV2(&m,true);
 }
}
int main(void) {
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());FieldSuccessV2();FieldFailuresV2();
 printf("{\"checks\":%u,\"actualRoot9Factory15Life18\":true,\"actualProducedCPUIdentityAndBorrow\":true,\"singleFieldOriginalOrder\":true,\"claimByteAndACTLR64\":true,\"readAndReleaseFailurePreserveOutput\":true,\"partialWriteWithdrawsIdentityRetainsVMRAM\":true,\"releaseDrainDoesNotRepeatWrite\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks);return 0;
}
