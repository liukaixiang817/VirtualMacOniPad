#include "modern_gic_v3_engine_v5.h"
#include <stdio.h>
#include <stdlib.h>

// Small controller-only callback fixture adapted from the existing Engine1
// host test. These mocks do not claim native CPU or guest execution.
static unsigned checks;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"MSI check %u failed at %d: %s\n",checks,__LINE__,#x);exit(1);}}while(0)
typedef struct {unsigned retains,releases,wakes,drains;} Fixture;
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out) {
 CHECK(q->expectedVMEpoch==17);++((Fixture *)p)->retains;*out=p;return VZ_KERNEL_OK;
}
static VZKernelStatus Release(void *p,void *token) {
 CHECK(token==p);++((Fixture *)p)->releases;return VZ_KERNEL_OK;
}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q) {
 CHECK(q->expectedVMEpoch==17);++((Fixture *)p)->wakes;return VZ_KERNEL_OK;
}
static VZKernelStatus Deadline(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t when) {
 (void)p;(void)q;(void)arm;(void)when;return VZ_KERNEL_OK;
}
static VZKernelStatus Drain(void *p,const VZKernelRunPendingRequestV14 *q) {
 CHECK(q->expectedVMEpoch==17);++((Fixture *)p)->drains;return VZ_KERNEL_OK;
}
static void Case(bool apple) {
 Fixture f={0};VM27GICBindingsV1 bindings={&f,Retain,Release,Wake,Deadline,Drain};
 VM27GICConfigV1 config={.schemaVersion=1,.maxCPUs=1,.ipaBits=36,.vmEpoch=17,
  .distributorBase=apple?UINT64_C(0x10000000):UINT64_C(0x08000000),
  .redistributorBase=apple?UINT64_C(0x10010000):UINT64_C(0x08010000),
  .msiBase=apple?UINT64_C(0x1fff0000):UINT64_C(0x09ff0000),
  .msiFirst=96,.msiCount=37,.msiConfigured=true};
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,81,9020,9,0};
 VM27GICV3V1 *g=NULL;CHECK(VM27GICCreateV1(&config,&bindings,&g)==VZ_KERNEL_OK);
 CHECK(VM27GICAttachCPUV1(g,&q,0)==VZ_KERNEL_OK);
 uint64_t type=0;CHECK(VM27GICMMIOV1(g,&q,config.msiBase+8,4,false,0,&type)==VZ_KERNEL_OK);
 // Deliberately non-default MSI range: no hardcoded Child27 base/count.
 CHECK(type==(apple?UINT64_C(0x80600025):UINT64_C(0x00600025)));
 CHECK(((type>>16)&0x3ff)==96);CHECK((type&0x3ff)==37);
 CHECK((type&UINT64_C(0xfc000000))==(apple?UINT64_C(0x80000000):0));
 CHECK(VM27GICDistributorRegV1(g,0,true,3,NULL)==VZ_KERNEL_OK);
 CHECK(VM27GICDistributorRegV1(g,0x8c,true,1,NULL)==VZ_KERNEL_OK); // SPI96 group1.
 CHECK(VM27GICDistributorRegV1(g,0x10c,true,1,NULL)==VZ_KERNEL_OK);
 CHECK(VM27GICICCRegV1(g,&q,0xc230,true,0xf8,NULL)==VZ_KERNEL_OK);
 CHECK(VM27GICICCRegV1(g,&q,0xc667,true,1,NULL)==VZ_KERNEL_OK);
 VM27GICLinesV1 lines={0};CHECK(VM27GICGetLinesV1(g,&q,&lines)==VZ_KERNEL_OK);CHECK(!lines.irq);
 CHECK(VM27GICSendMSIV1(g,config.msiBase+0x44,96)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27GICSendMSIV1(g,config.msiBase+0x40,133)==VZ_KERNEL_BAD_ARGUMENT);
 unsigned before=f.wakes;
 CHECK(VM27GICMMIOV1(g,&q,config.msiBase+0x40,4,true,96,NULL)==VZ_KERNEL_OK);
 CHECK(f.wakes>before);
 CHECK(VM27GICGetLinesV1(g,&q,&lines)==VZ_KERNEL_OK);CHECK(lines.irq && lines.highestGroup1==96);
 uint64_t ack=0;CHECK(VM27GICICCRegV1(g,&q,0xc660,false,0,&ack)==VZ_KERNEL_OK);CHECK(ack==96);
 CHECK(VM27GICICCRegV1(g,&q,0xc661,true,96,NULL)==VZ_KERNEL_OK);
 CHECK(VM27GICGetLinesV1(g,&q,&lines)==VZ_KERNEL_OK);CHECK(!lines.irq);
 CHECK(VM27GICDetachCPUV1(g,&q)==VZ_KERNEL_OK);CHECK(f.retains==1 && f.releases==1 && f.drains==1);
 CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_OK);
}
int main(void) {
 Case(true);Case(false);
 printf("VMApple MSI type and doorbell: %u checks passed (HOST only).\n",checks);return 0;
}
