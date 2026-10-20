#include "vm27_hv_public_vm_bootstrap_v11.h"
// Exact frozen Root10 fixture body, with only its outer main renamed.
#include "vm27_hv_public_vm_bootstrap_v10.h"
// Copied frozen Root9 fixture; only its outer entry name changes. Its own
// frozen Root8 include and every inherited check remain intact.
#include "vm27_hv_public_vm_bootstrap_v9.h"
// Exercise the complete frozen Root8 behavior against the new combined root
// before installing a controller. No old fixture is edited or skipped.
#define main FoundationMainV9
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
static unsigned GICWakesV9;
static int32_t GICTrapV9(void *opaque,uint64_t op,void *packet) {
 Mock *m=opaque;
 if(op==10){CHECK((uintptr_t)packet==1);++GICWakesV9;return 0;}
 int32_t status=Trap(opaque,op,packet);
 if(op==6 && !status){Put(m,0x4100,1);Put(m,0x6f8,0x1c00);Put(m,0x40b0,0x3c00);}
 return status;
}
typedef struct {hv_vcpu_t id;hv_return_t spi,icc;} GICForeignV9;
static void *GICForeignAccessV9(void *opaque) {
 GICForeignV9 *f=opaque;uint64_t value=55;
 f->spi=hv_gic_set_spi(40,true);f->icc=hv_gic_get_icc_reg(f->id,(hv_gic_icc_reg_t)0xc230,&value);
 CHECK(f->icc==BAD && value==55);return NULL;
}
static int FoundationMainV10(void) {
 CHECK(!FoundationMainV9());unsigned foundationChecks=Checks;
 alarm(20);Mock m={0};
 m.context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.context!=MAP_FAILED && m.host!=MAP_FAILED && !((uintptr_t)m.host&0x3fff));
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,GICTrapV9,Thread,Read};
 VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m.config=hv_vm_config_create();
 CHECK(!_hv_vm_config_set_isa(m.config,2));CHECK(!hv_vm_create(m.config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m.vm) && m.vm);
 hv_gic_config_t config=hv_gic_config_create();CHECK(config);
 size_t size=99;CHECK(!hv_gic_get_distributor_size(&size) && size==0x10000);
 CHECK(!hv_gic_get_redistributor_size(&size) && size==0x20000);
 CHECK(!hv_gic_get_redistributor_region_size(&size) && size==0x800000);
 CHECK(hv_gic_get_distributor_size((size_t *)(void *)config)==BAD);
 uint32_t first=77,count=88;CHECK(!hv_gic_get_spi_interrupt_range(&first,&count) && first==32 && count==988);
 CHECK(hv_gic_get_spi_interrupt_range(&first,&first)==BAD && first==32);
 uint32_t intid=88;CHECK(!hv_gic_get_intid((hv_gic_intid_t)30,&intid) && intid==30);
 CHECK(hv_gic_get_intid((hv_gic_intid_t)25,&intid)==(hv_return_t)UINT32_C(0xfae9400f) && intid==30);
 CHECK(hv_gic_config_set_distributor_base((hv_gic_config_t)(void *)1,0)==BAD);
 CHECK(hv_gic_config_set_distributor_base(config,1)==BAD);
 CHECK(hv_gic_create((hv_gic_config_t)(void *)1)==BAD);
 CHECK(hv_gic_create(config)==BAD);
 CHECK(!hv_gic_config_set_distributor_base(config,0x10000));
 CHECK(!hv_gic_config_set_redistributor_base(config,0));
 CHECK(hv_gic_create(config)==BAD); // Actual engine rejects overlapping regions.
 CHECK(!hv_gic_config_set_redistributor_base(config,0x200000));
 CHECK(hv_gic_config_set_msi_interrupt_range(config,31,1)==BAD);
 CHECK(hv_gic_config_set_msi_interrupt_range(config,1000,100)==BAD);
 CHECK(!hv_gic_config_set_msi_region_base(config,0x1000000));
 CHECK(!hv_gic_config_set_msi_interrupt_range(config,900,16));
 CHECK(!hv_gic_create(config));CHECK(hv_gic_create(config)==BUSY);
 uint64_t value=99;CHECK(!hv_gic_get_msi_reg((hv_gic_msi_reg_t)8,&value) && value==((900u<<16)|16));
 CHECK(hv_gic_get_msi_reg((hv_gic_msi_reg_t)0x40,&value)==BAD && value==((900u<<16)|16));
 CHECK(hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)4,(uint64_t *)(void *)config)==BAD);
 CHECK(!hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)4,&value) && (value&31)==31);
 CHECK(!hv_vm_map(m.host,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m.cpu,&exit,NULL));CHECK(m.cpu && exit);
 CHECK(!hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc005,0x80000001));
 hv_ipa_t base=99;CHECK(!hv_gic_get_redistributor_base(m.cpu,&base) && base==0x200000);
 CHECK(!hv_gic_get_redistributor_reg(m.cpu,(hv_gic_redistributor_reg_t)8,&value) && value>>32==1);
 CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,0xff));
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,&value) && value==0xf8);
 CHECK(hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,(uint64_t *)(void *)exit)==BAD);
 value=77;CHECK(hv_gic_get_ich_reg(m.cpu,(hv_gic_ich_reg_t)0xe658,&value)==(hv_return_t)UINT32_C(0xfae9400f) && value==77);
 CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc667,1));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0,2));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x84,1u<<8));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x104,1u<<8));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x6140,1));
 CHECK(!hv_gic_set_spi(40,true));CHECK(GICWakesV9>0);
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc660,&value) && value==40);
 CHECK(!hv_gic_set_spi(40,false));CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc661,40));
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc662,&value) && value==1023);
 GICForeignV9 foreign={m.cpu,ERROR,ERROR};pthread_t t;
 CHECK(!pthread_create(&t,NULL,GICForeignAccessV9,&foreign));CHECK(!pthread_join(t,NULL));CHECK(!foreign.spi);
 CHECK(!hv_gic_set_spi(40,false));CHECK(hv_gic_set_spi(900,true)==BAD);
 CHECK(hv_gic_send_msi(0x1000000,900)==BAD);CHECK(!hv_gic_send_msi(0x1000040,900));
 CHECK(hv_gic_set_msi_reg((hv_gic_msi_reg_t)0x40,UINT64_C(1)<<32)==BAD);
 CHECK(!hv_gic_set_msi_reg((hv_gic_msi_reg_t)0x40,900));
 CHECK(!hv_gic_reset());CHECK(!hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)0,&value) && !(value&3));
 CHECK(hv_vm_destroy()==BUSY && !m.calls[2]);
 CHECK(hv_gic_state_create()==NULL);size=99;
 CHECK(hv_gic_state_get_size((hv_gic_state_t)(void *)config,&size)==(hv_return_t)UINT32_C(0xfae9400f) && size==99);
 VM27CPUFactoryBorrowV2 *probe=NULL;hv_return_t acquired=VM27CPUFactoryBorrowAcquireV2(m.cpu,&probe);
 if(acquired)fprintf(stderr,"Root9 pre-destroy acquire=%08x\n",(uint32_t)acquired);
 CHECK(!acquired);
 if(probe)CHECK(!VM27CPUFactoryBorrowReleaseV2(probe));
 hv_return_t destroy=hv_vcpu_destroy(m.cpu);
 if(destroy)fprintf(stderr,"Root9 CPU destroy status=%08x native7=%u\n",(uint32_t)destroy,m.calls[7]);
 CHECK(!destroy && m.calls[7]==1);
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy() && m.calls[2]==1);
 CHECK(VM27HVVMUninstallNativeOpsV1()==BUSY);
 CFRelease((CFTypeRef)config);CFRelease((CFTypeRef)m.config);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!VM27HVDrainGICBorrowV9());
 CHECK(!munmap(m.context,0x8000) && !munmap(m.host,0x8000));
 printf("{\"checks\":%u,\"foundationChecks\":%u,\"actualRootGICFactoryRegistry\":true,\"actualCPUOwner\":true,\"hostMockNative10\":%u,\"nativeCallsExecuted\":0,\"deviceExecuted\":false,\"full27Backend\":false}\n",Checks,foundationChecks,GICWakesV9);
 return 0;
}

typedef struct { hv_vcpu_t cpu; hv_return_t status; bool result; } MaskForeignV10;
static void *MaskForeignAccessV10(void *opaque) {
 MaskForeignV10 *f=opaque;
 f->result=true;
 f->status=hv_vcpu_get_vtimer_mask(f->cpu,&f->result);
 return NULL;
}
static int InheritedRoot10MainV11(void) {
 CHECK(!FoundationMainV10());
 unsigned inherited=Checks;
 Mock m={0};
 m.context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.context!=MAP_FAILED && m.host!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};
 VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));
 m.config=hv_vm_config_create();CHECK(m.config);
 CHECK(!_hv_vm_config_set_isa(m.config,2));CHECK(!hv_vm_create(m.config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m.vm));
 CHECK(!hv_vm_map(m.host,0x40000000,0x4000,7));
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.cpu,&exit,NULL));
 uint64_t original=UINT64_C(0xaabbccdd12340000);Put(&m,0x6d8,original);
 uint64_t dirty=Word(&m,0x748),ready=Word(&m,0x4100);unsigned native8=m.calls[8];
 bool mask=true;CHECK(!hv_vcpu_get_vtimer_mask(m.cpu,&mask) && !mask);
 CHECK(!hv_vcpu_set_vtimer_mask(m.cpu,true));CHECK(Word(&m,0x6d8)==(original|1));
 CHECK(!hv_vcpu_get_vtimer_mask(m.cpu,&mask) && mask);
 CHECK(!hv_vcpu_set_vtimer_mask(m.cpu,false));CHECK(Word(&m,0x6d8)==original);
 CHECK(Word(&m,0x748)==dirty && Word(&m,0x4100)==ready && m.calls[8]==native8 && !m.calls[9]);
 CHECK(hv_vcpu_get_vtimer_mask(m.cpu,(bool *)(void *)exit)==BAD);
 MaskForeignV10 foreign={.cpu=m.cpu};pthread_t t;
 CHECK(!pthread_create(&t,NULL,MaskForeignAccessV10,&foreign));CHECK(!pthread_join(t,NULL));
 CHECK(foreign.status==BAD && foreign.result && Word(&m,0x6d8)==original);
 CHECK(!hv_vcpu_set_vtimer_mask(m.cpu,true));CHECK(!hv_vcpu_get_vtimer_mask(m.cpu,&mask) && mask);
 CHECK(!hv_vcpu_destroy(m.cpu) && m.calls[7]==1);
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy());
 CFRelease((CFTypeRef)m.config);CHECK(!VM27HVVMUninstallNativeOpsV1());
 CHECK(!munmap(m.context,0x8000) && !munmap(m.host,0x8000));
 printf("{\"checks\":%u,\"foundationChecks\":%u,\"actualRootGICFactoryRegistry\":true,\"actualVtimerMaskPreservesFull64\":true,\"nativeCallsExecuted\":0,\"deviceExecuted\":false,\"full27Backend\":false}\n",Checks,inherited);
 return 0;
}

// These changed-field cases preserve the frozen adapter fixture's physical
// writers, held-release failure injection, and owner cleanup assertions.
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
 CHECK(!InheritedRoot10MainV11());unsigned inherited=Checks;
 alarm(20);CHECK(VM27CPUFactoryVMOutputGuardLinkedV7());FieldSuccessV2();FieldFailuresV2();
 printf("{\"checks\":%u,\"inheritedRoot10Checks\":%u,\"actualRootGICFactoryRegistry\":true,\"actualRoot10Factory16Life20\":true,\"actualProducedCPUIdentityAndBorrow\":true,\"singleFieldOriginalOrder\":true,\"claimByteAndACTLR64\":true,\"readAndReleaseFailurePreserveOutput\":true,\"partialWriteWithdrawsIdentityRetainsVMRAM\":true,\"releaseDrainDoesNotRepeatWrite\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks,inherited);return 0;
}
