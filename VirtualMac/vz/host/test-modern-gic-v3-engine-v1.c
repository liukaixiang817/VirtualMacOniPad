#include "modern_gic_v3_engine_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// These are local scheduler/CPU mocks, never device execution evidence.
static unsigned checks;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"GIC check %u failed at %d: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
typedef struct {unsigned retained,released,wakes,arms,cancels,drains;bool wakeFail,drainFail,releaseFail;uint64_t deadline;} Fixture;
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out) {
 Fixture *f=p;CHECK(q->expectedVMEpoch==17);uint64_t *v=malloc(sizeof(*v));CHECK(v!=NULL);
 *v=q->expectedPublicIdentity;*out=v;++f->retained;return VZ_KERNEL_OK;
}
static VZKernelStatus Release(void *p,void *v) {
 Fixture *f=p;if(f->releaseFail)return VZ_KERNEL_NATIVE_ERROR;
 CHECK(v!=NULL);free(v);++f->released;return VZ_KERNEL_OK;
}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q) {
 Fixture *f=p;CHECK(q->expectedVMEpoch==17);++f->wakes;
 return f->wakeFail?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static VZKernelStatus Deadline(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline) {
 Fixture *f=p;CHECK(q->expectedVMEpoch==17);if(arm){++f->arms;f->deadline=deadline;}else ++f->cancels;
 return VZ_KERNEL_OK;
}
static VZKernelStatus Drain(void *p,const VZKernelRunPendingRequestV14 *q) {
 Fixture *f=p;CHECK(q->expectedVMEpoch==17);++f->drains;
 return f->drainFail?VZ_KERNEL_NATIVE_ERROR:VZ_KERNEL_OK;
}
static VZKernelRunPendingRequestV14 Identity(unsigned n) {
 return (VZKernelRunPendingRequestV14){1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,81+n,9020+n,9+n,n};
}
static VM27GICLinesV1 LinesOf(VM27GICV3V1 *g,VZKernelRunPendingRequestV14 *q) {
 VM27GICLinesV1 r={0};CHECK(VM27GICGetLinesV1(g,q,&r)==VZ_KERNEL_OK);return r;
}
static void Dist(VM27GICV3V1 *g,uint16_t reg,uint64_t value) {
 CHECK(VM27GICDistributorRegV1(g,reg,true,value,NULL)==VZ_KERNEL_OK);
}
static void Redist(VM27GICV3V1 *g,VZKernelRunPendingRequestV14 *q,uint32_t reg,uint64_t value) {
 CHECK(VM27GICRedistributorRegV1(g,q,reg,true,value,NULL)==VZ_KERNEL_OK);
}
static void ICC(VM27GICV3V1 *g,VZKernelRunPendingRequestV14 *q,uint16_t reg,uint64_t value) {
 CHECK(VM27GICICCRegV1(g,q,reg,true,value,NULL)==VZ_KERNEL_OK);
}
static uint64_t ReadICC(VM27GICV3V1 *g,VZKernelRunPendingRequestV14 *q,uint16_t reg) {
 uint64_t value=UINT64_MAX;CHECK(VM27GICICCRegV1(g,q,reg,false,0,&value)==VZ_KERNEL_OK);return value;
}
static void EnableCPU(VM27GICV3V1 *g,VZKernelRunPendingRequestV14 *q) {
 Redist(g,q,0x10080,UINT64_C(0x40000003));Redist(g,q,0x10100,UINT64_C(0x40000003));
 ICC(g,q,0xc230,0xf8);ICC(g,q,0xc667,1);
}
static uint32_t AbortESR(bool write,unsigned sas,unsigned rt,bool sign,bool sf) {
 return (0x24u<<26)|(1u<<25)|(1u<<24)|(sas<<22)|(sign?1u<<21:0)|(rt<<16)|
  (sf?1u<<15:0)|(write?1u<<6:0)|6;
}
typedef struct {VM27GICV3V1 *g;VZKernelRunPendingRequestV14 q;VZKernelStatus status;} ThreadCheck;
static void *ForeignThread(void *p) {
 ThreadCheck *t=p;VM27GICLinesV1 r={0};t->status=VM27GICGetLinesV1(t->g,&t->q,&r);return NULL;
}
int main(void) {
 Fixture f={0};VM27GICBindingsV1 b={&f,Retain,Release,Wake,Deadline,Drain};
 VM27GICConfigV1 config={1,4,36,0,17,UINT64_C(0x10000000),UINT64_C(0x11000000),
  UINT64_C(0x12000000),64,16,true};
 VM27GICV3V1 *g=NULL;CHECK(VM27GICCreateV1(&config,&b,&g)==VZ_KERNEL_OK);
 VZKernelRunPendingRequestV14 q0=Identity(0),q1=Identity(1);
 CHECK(VM27GICAttachCPUV1(g,&q0,0)==VZ_KERNEL_OK);CHECK(VM27GICAttachCPUV1(g,&q1,1)==VZ_KERNEL_OK);
 CHECK(VM27GICAttachCPUV1(g,&q0,2)==VZ_KERNEL_BUSY);
 CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_BUSY);
 uint64_t value=0;CHECK(VM27GICRedistributorBaseV1(g,&q1,&value)==VZ_KERNEL_OK);
 CHECK(value==config.redistributorBase+VM27_GIC_REDIST_BYTES_V1);
 CHECK(VM27GICRedistributorRegV1(g,&q0,8,false,0,&value)==VZ_KERNEL_OK);CHECK(!(value&16));
 CHECK(VM27GICRedistributorRegV1(g,&q1,8,false,0,&value)==VZ_KERNEL_OK);CHECK(value&16);
 CHECK(VM27GICDistributorRegV1(g,0xffe8,false,0,&value)==VZ_KERNEL_OK);CHECK(value==0x30);
 CHECK(VM27GICMMIOV1(g,&q0,config.msiBase+8,4,false,0,&value)==VZ_KERNEL_OK);
 CHECK(value==(UINT64_C(64)<<16|16));
 Dist(g,0,3);bool aggregate=true;
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q0,true,&aggregate)==VZ_KERNEL_OK);CHECK(!aggregate);
 EnableCPU(g,&q0);EnableCPU(g,&q1);
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q0,true,&aggregate)==VZ_KERNEL_OK);CHECK(aggregate);
 CHECK(ReadICC(g,&q0,0xc660)==30);CHECK(!LinesOf(g,&q0).irq);CHECK(ReadICC(g,&q0,0xc65b)==0x80);
 CHECK(ReadICC(g,&q0,0xc648)==(UINT64_C(1)<<16));
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q0,false,&aggregate)==VZ_KERNEL_OK);CHECK(!aggregate);
 ICC(g,&q0,0xc661,30);CHECK(ReadICC(g,&q0,0xc65b)==255);CHECK(ReadICC(g,&q0,0xc648)==0);
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q0,true,&aggregate)==VZ_KERNEL_OK);CHECK(ReadICC(g,&q0,0xc660)==30);
 ICC(g,&q0,0xc661,30);CHECK(LinesOf(g,&q0).irq); // a high level re-pends on EOI
 CHECK(ReadICC(g,&q0,0xc660)==30);
 CHECK(VM27GICRoutePhysicalTimerV1(g,&q0,false,&aggregate)==VZ_KERNEL_OK);ICC(g,&q0,0xc661,30);
 CHECK(!LinesOf(g,&q0).irq);
 Dist(g,0x84,7);Dist(g,0x104,7); // SPIs 32..34
 Dist(g,0x420,UINT64_C(0x804080)); // priorities 32=80,33=40,34=80
 CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);CHECK(VM27GICSetSPIV1(g,33,true)==VZ_KERNEL_OK);
 CHECK(LinesOf(g,&q0).highestGroup1==33);CHECK(ReadICC(g,&q0,0xc660)==33);
 CHECK(!LinesOf(g,&q0).irq);CHECK(VM27GICSetSPIV1(g,33,false)==VZ_KERNEL_OK);
 ICC(g,&q0,0xc661,33);CHECK(LinesOf(g,&q0).highestGroup1==32);
 CHECK(ReadICC(g,&q0,0xc660)==32);CHECK(VM27GICSetSPIV1(g,32,false)==VZ_KERNEL_OK);ICC(g,&q0,0xc661,32);
 Dist(g,0xc08,2); // SPI32 is now edge-triggered
 CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);CHECK(ReadICC(g,&q0,0xc660)==32);
 ICC(g,&q0,0xc661,32);CHECK(!LinesOf(g,&q0).irq);
 CHECK(VM27GICSetSPIV1(g,32,false)==VZ_KERNEL_OK);CHECK(!LinesOf(g,&q0).irq);
 CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);CHECK(ReadICC(g,&q0,0xc660)==32);ICC(g,&q0,0xc661,32);
 Dist(g,0x6100,1);CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);
 CHECK(!LinesOf(g,&q0).irq);CHECK(LinesOf(g,&q1).highestGroup1==32);
 CHECK(ReadICC(g,&q1,0xc660)==32);ICC(g,&q1,0xc661,32);
 // Group1 SGI explicitly targets affinity0=1; true ACK/EOI consumes its latch.
 ICC(g,&q0,0xc65d,(UINT64_C(1)<<24)|2);CHECK(LinesOf(g,&q1).highestGroup1==1);
 CHECK(!LinesOf(g,&q0).irq);CHECK(ReadICC(g,&q1,0xc660)==1);ICC(g,&q1,0xc661,1);
 CHECK(!LinesOf(g,&q1).irq);
 Dist(g,0x88,1);Dist(g,0x108,1);Dist(g,0x6200,1);
 CHECK(VM27GICSetSPIV1(g,64,true)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27GICSendMSIV1(g,config.msiBase+0x44,64)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27GICSendMSIV1(g,config.msiBase+0x40,80)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27GICSendMSIV1(g,config.msiBase+0x40,64)==VZ_KERNEL_OK);
 CHECK(ReadICC(g,&q1,0xc660)==64);ICC(g,&q1,0xc661,64);CHECK(!LinesOf(g,&q1).irq);
 // Split EOI drops priority but leaves an active interrupt until DIR.
 ICC(g,&q1,0xc664,2);CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);
 CHECK(ReadICC(g,&q1,0xc660)==32);ICC(g,&q1,0xc661,32);
 CHECK(ReadICC(g,&q1,0xc65b)==255);CHECK(!LinesOf(g,&q1).irq);
 CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);CHECK(!LinesOf(g,&q1).irq);
 ICC(g,&q1,0xc659,32);CHECK(LinesOf(g,&q1).irq);CHECK(ReadICC(g,&q1,0xc660)==32);
 ICC(g,&q1,0xc661,32);ICC(g,&q1,0xc659,32);ICC(g,&q1,0xc664,0);
 CHECK(!LinesOf(g,&q1).irq);
 // Real EC18 ISS decode and narrow signed Data Abort transfer decode.
 VM27GICTrapResultV1 r={0};uint32_t pmrRead=(0x18u<<26)|(1u<<25)|(3u<<20)|(4u<<10)|(4u<<5)|(6u<<1)|1;
 CHECK(VM27GICHandleSystemV1(g,&q0,pmrRead,0,&r)==VZ_KERNEL_OK);
 CHECK(r.handled && !r.write && r.registerIndex==4 && r.readValue==0xf8 && !r.controllerStateCommitted);
 CHECK(VM27GICHandleAbortV1(g,&q0,AbortESR(false,0,3,true,true),config.distributorBase+0x420,0,&r)==VZ_KERNEL_OK);
 CHECK(r.handled && r.registerIndex==3 && r.bytes==1 && r.readValue==UINT64_C(0xffffffffffffff80));
 CHECK(VM27GICHandleAbortV1(g,&q0,AbortESR(true,2,3,false,true),config.distributorBase+0x184,1,&r)==VZ_KERNEL_OK);
 CHECK(r.handled && r.write && r.controllerStateCommitted);
 CHECK(VM27GICSetSPIV1(g,32,true)==VZ_KERNEL_OK);CHECK(!LinesOf(g,&q1).irq);
 Dist(g,0x104,1);CHECK(ReadICC(g,&q1,0xc660)==32);ICC(g,&q1,0xc661,32);
 VM27GICTrapResultV1 before=r;
 CHECK(VM27GICHandleAbortV1(g,&q0,AbortESR(false,2,3,false,true)|8,config.distributorBase,0,&r)==VZ_KERNEL_UNSUPPORTED);
 CHECK(memcmp(&r,&before,sizeof(r))==0);
 CHECK(VM27GICHandleAbortV1(g,&q0,AbortESR(false,2,3,false,true),config.distributorBase-4,0,&r)==VZ_KERNEL_UNSUPPORTED);
 CHECK(memcmp(&r,&before,sizeof(r))==0);
 CHECK(VM27GICHandleSystemV1(g,&q0,pmrRead,0,(void *)g)==VZ_KERNEL_BAD_ARGUMENT);
 VZKernelRunPendingRequestV14 bad=q0;bad.expectedCPUGeneration++;
 aggregate=true;CHECK(VM27GICRoutePhysicalTimerV1(g,&bad,true,&aggregate)==VZ_KERNEL_NOT_LIVE);CHECK(aggregate);
 bad=q0;bad.expectedReturnedSlotWord++;CHECK(VM27GICValidateTimerOwnerV1(g,&bad)==VZ_KERNEL_NOT_LIVE);
 bad=q0;bad.expectedVMEpoch++;CHECK(VM27GICValidateTimerOwnerV1(g,&bad)==VZ_KERNEL_NOT_LIVE);
 ThreadCheck t={g,q0,VZ_KERNEL_OK};pthread_t thread;CHECK(!pthread_create(&thread,NULL,ForeignThread,&t));
 CHECK(!pthread_join(thread,NULL));CHECK(t.status==VZ_KERNEL_NOT_LIVE);
 CHECK(VM27GICBeginRunV1(g,&q0)==VZ_KERNEL_OK);
 CHECK(VM27GICSetAffinityV1(g,&q0,0)==VZ_KERNEL_OK);
 CHECK(VM27GICSetAffinityV1(g,&q0,UINT64_C(0x80000000))==VZ_KERNEL_OK);
 CHECK(VM27GICBeginRunV1(g,&q0)==VZ_KERNEL_BUSY);
 CHECK(VM27GICResetV1(g)==VZ_KERNEL_BUSY);
 CHECK(VM27GICEndRunV1(g,&q0)==VZ_KERNEL_OK);
 CHECK(VM27GICSetAffinityV1(g,&q1,2)==VZ_KERNEL_BUSY);bad=Identity(2);
 CHECK(VM27GICAttachCPUV1(g,&bad,2)==VZ_KERNEL_BUSY);
 CHECK(VM27GICUpdatePhysicalDeadlineV1(g,&q0,true,1234)==VZ_KERNEL_OK);CHECK(f.arms==1 && f.deadline==1234);
 CHECK(VM27GICUpdatePhysicalDeadlineV1(g,&q0,false,0)==VZ_KERNEL_OK);CHECK(f.cancels==1);
 // A failed asynchronous wake is a committed controller mutation, so a Run
 // integration can poison and retain the CPU instead of replaying the store.
 f.wakeFail=true;r=(VM27GICTrapResultV1){0};
 CHECK(VM27GICHandleAbortV1(g,&q0,AbortESR(true,2,3,false,true),config.distributorBase+0x204,1,&r)==VZ_KERNEL_NATIVE_ERROR);
 CHECK(r.handled && r.write && r.controllerStateCommitted);f.wakeFail=false;
 CHECK(ReadICC(g,&q1,0xc660)==32);ICC(g,&q1,0xc661,32);
 CHECK(VM27GICResetV1(g)==VZ_KERNEL_OK);
 CHECK(!LinesOf(g,&q0).irq && !LinesOf(g,&q1).irq);
 CHECK(ReadICC(g,&q0,0xc230)==0);
 // Failed drain retains both attachment and the actual borrowed allocation.
 unsigned released=f.released;f.drainFail=true;
 CHECK(VM27GICDetachCPUV1(g,&q0)==VZ_KERNEL_NATIVE_ERROR);CHECK(f.released==released);
 CHECK(VM27GICValidateTimerOwnerV1(g,&q0)==VZ_KERNEL_NOT_LIVE);
 CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_BUSY);f.drainFail=false;
 f.releaseFail=true;CHECK(VM27GICDetachCPUV1(g,&q0)==VZ_KERNEL_NATIVE_ERROR);CHECK(f.released==released);
 f.releaseFail=false;CHECK(VM27GICDetachCPUV1(g,&q0)==VZ_KERNEL_OK);
 CHECK(VM27GICDetachCPUV1(g,&q1)==VZ_KERNEL_OK);CHECK(f.retained==f.released && f.retained==2);
 CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_OK);
 for(unsigned mode=0;mode<12;++mode) {
  VM27GICConfigV1 invalid=config;
  switch(mode) {
   case 0:invalid.schemaVersion=0;break;case 1:invalid.maxCPUs=0;break;
   case 2:invalid.maxCPUs=65;break;case 3:invalid.ipaBits=40;break;
   case 4:invalid.vmEpoch=0;break;case 5:invalid.distributorBase++;break;
   case 6:invalid.redistributorBase=invalid.distributorBase;break;
   case 7:invalid.msiFirst=16;break;case 8:invalid.msiFirst=1019;invalid.msiCount=2;break;
   case 9:invalid.msiBase=UINT64_C(1)<<36;break;case 10:invalid.msiConfigured=false;break;
   case 11:invalid.reserved=1;break;
  }
  g=(void *)(uintptr_t)0x1234;CHECK(VM27GICCreateV1(&invalid,&b,&g)==VZ_KERNEL_BAD_ARGUMENT);
  CHECK(g==(void *)(uintptr_t)0x1234);
 }
 printf("{\"checks\":%u,\"finiteGICModelPassed\":true,\"retained\":%u,\"released\":%u,\"wakes\":%u,\"arms\":%u,\"cancels\":%u,\"drains\":%u,\"deviceExecuted\":false,\"fullRun\":false}\n",
  checks,f.retained,f.released,f.wakes,f.arms,f.cancels,f.drains);return 0;
}
