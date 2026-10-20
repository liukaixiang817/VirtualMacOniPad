#include "modern_gic_v3_engine_v2.h"
#include <stdio.h>
#include <stdlib.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"alignment check failed line=%d: %s\n",__LINE__,#x); return 1; } } while(0)
// HOST-only CPU/scheduler callbacks; no native CPU or device operation.
static VZKernelStatus Retain(void *c,const VZKernelRunPendingRequestV14 *q,void **out) {
 (void)c;(void)q;*out=malloc(1);return *out?VZ_KERNEL_OK:VZ_KERNEL_OUT_OF_MEMORY;
}
static VZKernelStatus Release(void *c,void *p) {(void)c;free(p);return VZ_KERNEL_OK;}
static VZKernelStatus Wake(void *c,const VZKernelRunPendingRequestV14 *q) {(void)c;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Schedule(void *c,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t t) {(void)c;(void)q;(void)arm;(void)t;return VZ_KERNEL_OK;}
static VZKernelStatus Drain(void *c,const VZKernelRunPendingRequestV14 *q) {(void)c;(void)q;return VZ_KERNEL_OK;}
int main(void) {
 CHECK(VM27GICRedistributorBaseAlignmentV2()==UINT64_C(0x10000));
 CHECK(VM27_GIC_REDIST_BYTES_V1==UINT64_C(0x20000));
 VM27GICBindingsV1 b={NULL,Retain,Release,Wake,Schedule,Drain};
 VM27GICConfigV1 c={.schemaVersion=1,.maxCPUs=4,.ipaBits=36,.vmEpoch=17,
  .distributorBase=UINT64_C(0x10000000),.redistributorBase=UINT64_C(0x10010000)};
 VM27GICV3V1 *g=NULL;
 CHECK(VM27GICCreateV1(&c,&b,&g)==VZ_KERNEL_OK);
 VZKernelRunPendingRequestV14 q0={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,81,9020,9,0};
 VZKernelRunPendingRequestV14 q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,2,0,17,82,9021,10,1};
 CHECK(VM27GICAttachCPUV1(g,&q0,0)==VZ_KERNEL_OK);
 CHECK(VM27GICAttachCPUV1(g,&q,1)==VZ_KERNEL_OK);
 uint64_t actual=0;CHECK(VM27GICRedistributorBaseV1(g,&q,&actual)==VZ_KERNEL_OK);
 CHECK(actual==UINT64_C(0x10030000)); // base64K plus unchanged CPU1 stride128K.
 CHECK(VM27GICDetachCPUV1(g,&q)==VZ_KERNEL_OK);
 CHECK(VM27GICDetachCPUV1(g,&q0)==VZ_KERNEL_OK);
 CHECK(VM27GICDestroyV1(g)==VZ_KERNEL_OK);g=NULL;
 c.redistributorBase=UINT64_C(0x10014000);
 CHECK(VM27GICCreateV1(&c,&b,&g)==VZ_KERNEL_BAD_ARGUMENT && g==NULL);
 c.redistributorBase=UINT64_C(0x10018000);
 CHECK(VM27GICCreateV1(&c,&b,&g)==VZ_KERNEL_BAD_ARGUMENT && g==NULL);
 c.redistributorBase=c.distributorBase;
 CHECK(VM27GICCreateV1(&c,&b,&g)==VZ_KERNEL_BAD_ARGUMENT && g==NULL);
 printf("GIC base alignment finite checks=%u passed\n",checks);return 0;
}
