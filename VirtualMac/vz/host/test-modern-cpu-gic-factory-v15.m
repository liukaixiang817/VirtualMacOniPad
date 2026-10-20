#include "modern_cpu_native_public_factory_v15.h"
#include "modern_cpu_config_capability_acquisition_v2.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do{++Checks;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
#define BUSY ((hv_return_t)UINT32_C(0xfae94002))
#define BAD ((hv_return_t)UINT32_C(0xfae94003))
#define ERROR ((hv_return_t)UINT32_C(0xfae94001))
static unsigned Checks;
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *o){*o=(VM27CPURawIPAPairV2){true,40,42};}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){*o=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){*o=(VM27CPUTLBICapabilityValueV1){0};}
typedef struct {
 unsigned char *native;
 unsigned calls[11],step,writes,pcWrites,deadlines,drains,reentries;
 uint64_t now,deadline;
 VM27CPUFactoryVMV2 *vm;hv_vcpu_t id;hv_vcpu_exit_t *exit;
 bool armed,trace,reenter,drainFail,deadlineFail,writePCFail,wakeFail,cancelInRun,allRetry,readFail;
 unsigned cancelAtStep;
 void *invalidatedOutput;
 bool invalidateOnVersion;
 uint64_t expectedEpoch,expectedGeneration;
} Model;
extern VZKernelCPUGICOwnerV18 *FixtureActualGICOwnerV18(VZKernelCPU *);
static uint64_t Word(Model *m,unsigned off){uint64_t v;memcpy(&v,m->native+off,8);return v;}
static void Put(Model *m,unsigned off,uint64_t v){memcpy(m->native+off,&v,8);}
static uint64_t Thread(void *p){(void)p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t;}
static uint32_t SysESR(uint16_t reg,unsigned rt,bool read) {
 return (0x18u<<26)|(1u<<25)|((uint32_t)(reg>>14)<<20)|((uint32_t)(reg&7)<<17)|
  (((uint32_t)reg>>11)&7)<<14|(((uint32_t)reg>>7)&15)<<10|rt<<5|(((uint32_t)reg>>3)&15)<<1|(read?1:0);
}
static int32_t Trap(void *p,uint64_t op,void *packet) {
 Model *m=p;CHECK(op>=1 && op<=10);++m->calls[op];
 if(op==1){CHECK(packet && ((VZKernelNativeVMConfig *)packet)->nativeHVISA==2);return 0;}
 if(op==2){CHECK(!packet);return 0;}
 if(op==6){CHECK(packet);((uint64_t *)packet)[1]=(uintptr_t)m->native;
  Put(m,0x4000,VZ_KERNEL_NATIVE_CONTEXT_VERSION);Put(m,0x4100,1);Put(m,0x690,UINT64_C(0x80000000));return 0;}
 if(op==7 || op==8){CHECK(!packet);if(op==8)Put(m,0x4100,Word(m,0x4100)|1);return 0;}
 if(op==10){CHECK((uintptr_t)packet==1);return m->wakeFail?-10:0;}
 CHECK(op==9 && !packet);uint32_t reason=1,esr=0xf2000000;uint64_t ipa=0,va=0;
 if(m->cancelInRun && m->step==m->cancelAtStep) {
  CHECK(!hv_vcpus_exit(&m->id,1));reason=2;
 }else if(m->allRetry)reason=m->step&1?2:11;
 else switch(m->step) {
  case 0:reason=11;break;
  case 1:esr=SysESR(0xc230,2,false);break;
  case 2:esr=SysESR(0xc665,3,true);break;
  case 3:esr=(0x24u<<26)|(1u<<25)|(1u<<24)|(2u<<22)|(4u<<16)|4u;ipa=UINT64_C(0x10004);va=UINT64_C(0x10004);break;
  case 4:esr=SysESR(0xdf11,5,false);break;
  case 5:esr=SysESR(0xdf12,6,true);break;
  case 6:reason=2;break;
  default:break;
 }
 ++m->step;memcpy(m->native+0x4008,&reason,4);memcpy(m->native+0x400c,&esr,4);
 Put(m,0x4018,va);Put(m,0x4020,ipa);return 0;
}
static void Reenter(Model *m) {
 if(!m->trace || !m->reenter)return;++m->reentries;
 CHECK(hv_vcpu_set_sys_reg(m->id,(hv_sys_reg_t)0xc005,1)==BUSY);
 CHECK(hv_vcpu_destroy(m->id)==BUSY);
}
static bool Read(void *p,const void *src,size_t n,void *out) {
 Model *m=p;uintptr_t off=(uintptr_t)src-(uintptr_t)m->native;
 CHECK(off<0x8000 && n<=0x8000-off);Reenter(m);
 if(m->invalidateOnVersion && off==0x4000) {
  CHECK(!mprotect(m->invalidatedOutput,0x4000,PROT_NONE));m->invalidateOnVersion=false;
 }
 if(m->trace && m->readFail && off==0x108)return false;
 return VM27CPUSelfReadV1(NULL,src,n,out);
}
static bool Write(void *p,void *dst,size_t n,const void *v) {
 Model *m=p;uintptr_t off=(uintptr_t)dst-(uintptr_t)m->native;
 CHECK(off<0x8000 && n<=0x8000-off);++m->writes;Reenter(m);
 bool result=VM27CPUSelfWriteV1(NULL,dst,n,v);
 if(m->trace && off==0x108){++m->pcWrites;if(m->writePCFail)return false;}
 return result;
}
bool FixturePhysicalCounterV18(void *p,uint64_t *out){Model *m=p;Reenter(m);*out=m->now;return true;}
static VZKernelStatus Schedule(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline) {
 Model *m=p;CHECK(q->schemaVersion==1 && q->expectedPublicIdentity==m->id && q->expectedOwnerThread==Thread(m));
 ++m->deadlines;m->armed=arm;m->deadline=deadline;Reenter(m);return m->deadlineFail?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static VZKernelStatus Drain(void *p,const VZKernelRunPendingRequestV14 *q) {
 Model *m=p;CHECK(q->expectedPublicIdentity==m->id);++m->drains;
 if(m->drainFail)return VZ_KERNEL_NATIVE_ERROR;m->armed=false;return VZ_KERNEL_OK;
}
static void New(Model *m) {
 memset(m,0,sizeof(*m));m->now=100;
 m->native=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m->native!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,m,Trap,Thread,Read};
 VZKernelInitWriter writer={m,Write};VZKernelVMOptions options={36,0,2,false,false};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m->vm,NULL));
 VM27CPUFactoryVMGICDescriptionV15 describe={0};CHECK(!VM27CPUFactoryVMGICDescribeV15(m->vm,&describe));
 CHECK(describe.vmEpoch && describe.nativeHVISA==2 && describe.live && !describe.liveCPUCount && !describe.gicInstalled);
 VM27GICConfigV1 config={1,1,36,0,describe.vmEpoch,0x10000,0x20000,0,0,0,false};
 VM27CPUFactoryGICSchedulerV15 scheduler={m,Schedule,Drain};
 CHECK(!VM27CPUFactoryVMGICInstallV15(m->vm,&config,&scheduler));
 CHECK(VM27CPUFactoryVMGICInstallV15(m->vm,&config,&scheduler)==BUSY);
 CHECK(!hv_vcpu_create(&m->id,&m->exit,NULL));CHECK(m->id && m->exit);
 CHECK(!VM27CPUFactoryVMGICDescribeV15(m->vm,&describe) && describe.gicInstalled && describe.liveCPUCount==1);
 CHECK(VM27CPUFactoryVMGICTeardownV15(m->vm)==BUSY && m->calls[7]==0 && m->calls[2]==0);
 CHECK(!hv_vcpu_set_sys_reg(m->id,(hv_sys_reg_t)0xc005,UINT64_C(0x80000010)));
 uint64_t mpidr=0;CHECK(!hv_vcpu_get_sys_reg(m->id,(hv_sys_reg_t)0xc005,&mpidr) && mpidr==UINT64_C(0x80000010));
 Put(m,8+2*8,0xff);Put(m,8+5*8,3);Put(m,0x108,UINT64_C(0x40000000));Put(m,0x3f0,80);Put(m,0x438,3);
}
static void Clean(Model *m,bool poisoned) {
 m->trace=m->reenter=false;m->drainFail=false;m->deadlineFail=false;m->wakeFail=false;
 CHECK(poisoned?!VM27CPUFactoryOwnerCleanupV2(m->vm,NULL):!hv_vcpu_destroy(m->id));
 CHECK(m->calls[7]==1 && m->drains>=1 && !m->armed);
 CHECK(!VM27CPUFactoryVMDestroyV2(m->vm,NULL) && m->calls[2]==1);
 CHECK(!VM27CPUFactoryVMFreeV2(m->vm));CHECK(!munmap(m->native,0x8000));
}
static void EnableSPI(Model *m) {
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15,0,2,NULL));
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15,0x84,1,NULL));
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15,0x104,1,NULL));
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15,0x6100,0x10,NULL));
 VM27CPUFactoryBorrowV2 *b=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&b));
 CHECK(!VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_WRITE_V15,0xc230,0xff,NULL));
 CHECK(!VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_WRITE_V15,0xc667,1,NULL));
 CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_SPI_LEVEL_V15,32,1,NULL));
}
static void Success(void) {
 Model m;New(&m);m.trace=m.reenter=true;
 CHECK(!hv_vcpu_run(m.id));CHECK(m.calls[9]==8 && m.pcWrites==5 && m.reentries>0);
 CHECK(m.exit->reason==HV_EXIT_REASON_EXCEPTION && m.exit->exception.syndrome==0xf2000000);
 CHECK(Word(&m,0x108)==UINT64_C(0x40000014) && Word(&m,8+3*8)==7 && Word(&m,8+6*8)==80);
 CHECK(Word(&m,0x438)==3 && (Word(&m,0x748)&1));m.trace=m.reenter=false;
 // Restore of the unchanged real MPIDR preserves the frozen topology.
 CHECK(!hv_vcpu_set_sys_reg(m.id,(hv_sys_reg_t)0xc005,UINT64_C(0x80000010)));
 uint64_t out=99;CHECK(!hv_vcpu_get_sys_reg(m.id,(hv_sys_reg_t)0xdf11,&out) && out==7);
 CHECK(!hv_vcpu_set_sys_reg(m.id,(hv_sys_reg_t)0xdf12,200));CHECK(Word(&m,0x3f0)==200);
 CHECK(!hv_vcpu_set_sys_reg(m.id,(hv_sys_reg_t)0xdf11,1));CHECK(m.armed && m.deadline==200);
 CHECK(hv_vcpu_set_sys_reg(m.id,(hv_sys_reg_t)0xc005,3)==BUSY);
 // A successful actual native MPIDR write followed by frozen-topology refusal
 // poisons both real identity registries; no inconsistent CPU can run again.
 VM27CPUFactoryBorrowV2 *b=NULL;CHECK(VM27CPUFactoryBorrowAcquireV2(m.id,&b)==BAD && !b);
 Clean(&m,true);
}
static void Cancel(void) {
 Model m;New(&m);unsigned calls=m.calls[9],wakes=m.calls[10];
 CHECK(!hv_vcpus_exit(&m.id,1));CHECK(!hv_vcpu_run(m.id) && m.calls[9]==calls && m.calls[10]==wakes);
 CHECK(m.exit->reason==HV_EXIT_REASON_CANCELED && !m.exit->exception.syndrome && !m.exit->exception.physical_address);
 EnableSPI(&m);wakes=m.calls[10];
 m.cancelInRun=true;m.cancelAtStep=0;CHECK(!hv_vcpu_run(m.id));
 CHECK(m.calls[9]==calls+1 && m.calls[10]==wakes+1 && m.exit->reason==HV_EXIT_REASON_CANCELED);
 CHECK(!(Word(&m,0x670)&UINT64_C(0xc0)));
 m.cancelInRun=false;m.step=7;CHECK(!hv_vcpu_run(m.id) && m.exit->reason==HV_EXIT_REASON_EXCEPTION);
 Clean(&m,false);
}
static void Failures(void) {
 Model m;New(&m);m.trace=true;m.writePCFail=true;m.step=2;
 memset(m.exit,0x77,sizeof(*m.exit));hv_vcpu_exit_t before=*m.exit;
 CHECK(hv_vcpu_run(m.id)==ERROR && m.calls[9]==1 && m.pcWrites==1 && !memcmp(m.exit,&before,sizeof(before)));
 CHECK(hv_vcpu_run(m.id)==BAD);Clean(&m,true);
 New(&m);m.trace=true;m.readFail=true;m.step=2;CHECK(hv_vcpu_run(m.id)==ERROR && !m.pcWrites);
 m.readFail=false;m.step=7;CHECK(!hv_vcpu_run(m.id));Clean(&m,false);
 New(&m);m.trace=true;m.deadlineFail=true;m.step=4;
 CHECK(hv_vcpu_run(m.id)==ERROR && m.calls[9]==0);Clean(&m,true);
 New(&m);m.drainFail=true;CHECK(hv_vcpu_destroy(m.id)==ERROR && !m.calls[7]);
 CHECK(VM27CPUFactoryVMDestroyV2(m.vm,NULL)==BUSY && !m.calls[2]);m.drainFail=false;Clean(&m,false);
 New(&m);EnableSPI(&m);m.trace=true;m.step=1;m.wakeFail=true;
 CHECK(hv_vcpu_run(m.id)==ERROR && m.calls[9]==1 && !m.pcWrites);Clean(&m,true);
 New(&m);EnableSPI(&m);VM27CPUFactoryBorrowV2 *b=NULL;CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));
 m.wakeFail=true;CHECK(VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_WRITE_V15,0xc230,0xff,NULL)==ERROR);
 CHECK(hv_vcpu_run(m.id)==BAD);CHECK(!VM27CPUFactoryBorrowReleaseV2(b));Clean(&m,true);
}
static void Bounded(void) {
 Model m;New(&m);VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));
 VZKernelCPUBorrowV5 *lower=NULL;VZKernelCPU *cpu=NULL;CHECK(!VZKernelCPUBorrowIdentityV5(m.id,&lower));
 CHECK(!VZKernelCPUBorrowHandleV5(lower,&cpu));
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,v.vmEpoch,m.id,Thread(&m),v.cpuGeneration,0};
 VZKernelInitWriter writer={&m,Write};VZKernelRunPendingReceiptV14 receipt={0};m.allRetry=true;
 CHECK(VZKernelCPURunGICPendingBoundedV18(cpu,&q,&writer,3,&receipt)==VZ_KERNEL_BUSY && m.calls[9]==3);
 CHECK(!receipt.mutationPoisoned && !receipt.step.publicExceptionProduced);
 CHECK(!VZKernelCPUReleaseBorrowV5(lower));CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 m.allRetry=false;m.step=7;CHECK(!hv_vcpu_run(m.id));Clean(&m,false);
}
static void *ForeignGIC(void *p) {
 Model *m=p;uint64_t out=99;
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_DISTRIBUTOR_READ_V15,0,0,&out) && (out&2));
 CHECK(!VM27CPUFactoryVMGICAccessV15(m->vm,VM27_FACTORY_GIC_SPI_LEVEL_V15,32,1,NULL));
 VM27CPUFactoryVMGICDescriptionV15 d={0};
 CHECK(VM27CPUFactoryVMGICDescribeV15(m->vm,&d)==BAD && !d.vmEpoch);
 CHECK(VM27CPUFactoryVMGICTeardownV15(m->vm)==BAD);return NULL;
}
static void *ForeignICC(void *p) {
 Model *m=p;VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};uint64_t out=99;
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&b));CHECK(VM27CPUFactoryBorrowViewV2(b,&v)==BAD && !v.vmEpoch);
 CHECK(VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_READ_V15,0xc660,0,&out)==BAD && out==99);
 CHECK(VM27CPUFactoryPoisonGICCPUV15(m->id,m->expectedEpoch,m->expectedGeneration)==BAD);
 CHECK(!VM27CPUFactoryBorrowReleaseV2(b));return NULL;
}
static void Async(void) {
 Model m;New(&m);EnableSPI(&m);unsigned wakes=m.calls[10];pthread_t thread;
 CHECK(!pthread_create(&thread,NULL,ForeignGIC,&m));CHECK(!pthread_join(thread,NULL));
 CHECK(m.calls[10]==wakes+1 && !m.calls[9] && !m.calls[7]);
 VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 view={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&view));
 m.expectedEpoch=view.vmEpoch;m.expectedGeneration=view.cpuGeneration;CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 CHECK(!pthread_create(&thread,NULL,ForeignICC,&m));CHECK(!pthread_join(thread,NULL));
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));
 CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 m.step=7;CHECK(!hv_vcpu_run(m.id));Clean(&m,false);
}
static void ACKFailures(void) {
 Model m;New(&m);EnableSPI(&m);VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};
 CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));
 CHECK(VM27CPUFactoryPoisonGICCPUV15(m.id,v.vmEpoch+1,v.cpuGeneration)==BAD);
 CHECK(VM27CPUFactoryPoisonGICCPUV15(m.id,v.vmEpoch,v.cpuGeneration+1)==BAD);
 uint64_t ack=99;CHECK(!VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_READ_V15,0xc660,0,&ack) && ack==32);
 // A real Root producer has already committed ACK, then detects release/output
 // failure: the expected numbers identify the actual retained attachment.
 CHECK(!VM27CPUFactoryPoisonGICCPUV15(m.id,v.vmEpoch,v.cpuGeneration));
 CHECK(hv_vcpu_run(m.id)==BAD && !m.calls[9]);CHECK(!VM27CPUFactoryBorrowReleaseV2(b));Clean(&m,true);
 New(&m);EnableSPI(&m);CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));
 uint64_t *out=mmap(NULL,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(out!=MAP_FAILED);*out=99;
 m.invalidatedOutput=out;m.invalidateOnVersion=true;
 CHECK(VM27CPUFactoryBorrowGICAccessV15(b,VM27_FACTORY_GIC_ICC_READ_V15,0xc660,0,out)==BAD);
 CHECK(!mprotect(out,0x4000,PROT_READ|PROT_WRITE) && *out==99);
 CHECK(hv_vcpu_run(m.id)==BAD && !m.calls[9]);CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 CHECK(!munmap(out,0x4000));Clean(&m,true);
 New(&m);EnableSPI(&m);CHECK(!VM27CPUFactoryBorrowAcquireV2(m.id,&b));CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));
 VZKernelCPUBorrowV5 *lowerBorrow=NULL;VZKernelCPU *cpu=NULL;
 CHECK(!VZKernelCPUBorrowIdentityV5(m.id,&lowerBorrow));CHECK(!VZKernelCPUBorrowHandleV5(lowerBorrow,&cpu));
 VZKernelCPUGICOwnerV18 *owner=FixtureActualGICOwnerV18(cpu);CHECK(owner);
 bool poisoned=false;CHECK(!VZKernelCPUGICOwnerPoisonedV18(owner,&poisoned) && !poisoned);
 CHECK(VZKernelCPUGICOwnerPoisonedV18((void *)(uintptr_t)1,&poisoned)==VZ_KERNEL_BAD_ARGUMENT && !poisoned);
 out=mmap(NULL,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(out!=MAP_FAILED);*out=99;
 m.invalidatedOutput=out;m.invalidateOnVersion=true;
 CHECK(VZKernelCPUGICOwnerAccessV18(owner,1,0xc660,0,out,NULL)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(!mprotect(out,0x4000,PROT_READ|PROT_WRITE) && *out==99);
 CHECK(!VZKernelCPUGICOwnerPoisonedV18(owner,&poisoned) && poisoned);
 CHECK(!VM27CPUFactoryPoisonGICCPUV15(m.id,v.vmEpoch,v.cpuGeneration));
 CHECK(!VZKernelCPUReleaseBorrowV5(lowerBorrow));CHECK(!VM27CPUFactoryBorrowReleaseV2(b));
 CHECK(!munmap(out,0x4000));Clean(&m,true);
}
int main(void) {
 alarm(25);Success();Cancel();Failures();Bounded();Async();ACKFailures();
 printf("{\"checks\":%u,\"actualFactoryKernelBorrowGICJoined\":true,\"postTokenRealPCAndRegistersWritten\":true,\"publicRunHasNoFixedIterationLimit\":true,\"timerWakeSeparateFromCancel\":true,\"cancelBeforeRunInvokesNoNative9\":true,\"nativeCounterAndSchedulerInFixtureMocked\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"virtualTimerLaneImplemented\":false,\"fullPublicRunEquivalent\":false,\"full27Backend\":false}\n",Checks);return 0;
}
