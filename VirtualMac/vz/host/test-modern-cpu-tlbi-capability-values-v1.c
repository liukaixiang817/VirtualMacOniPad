#include "modern_cpu_tlbi_capability_values_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned Checks;
#define CHECK(v) do {++Checks;if(!(v)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#v);abort();}}while(0)
static void Refuse(VM27CPUTLBICapabilityInputV1 q) {
    VM27CPUTLBICapabilityValueV1 out={true,true},old=out;
    CHECK(!VM27CPUInterpretTLBICapabilityV1(&q,&out));CHECK(!memcmp(&old,&out,sizeof(out)));
}
int main(void) {
    VM27CPUTLBICapabilityInputV1 q={1,1,88,0,0,4,0,1,VM27_CPU_TLBI_HOST_MASK_V1};
    VM27CPUTLBICapabilityValueV1 out={false,false};
    CHECK(VM27CPUInterpretTLBICapabilityV1(&q,&out) && out.known && out.supported);
    q.vmmPresent=1;CHECK(VM27CPUInterpretTLBICapabilityV1(&q,&out) && out.known && !out.supported);
    q.vmmPresent=0;
    for(unsigned bit=0;bit<64;++bit) {
        q.hostContextWord40=VM27_CPU_TLBI_HOST_MASK_V1 ^ (UINT64_C(1)<<bit);
        CHECK(VM27CPUInterpretTLBICapabilityV1(&q,&out) && out.known);
        CHECK(out.supported==((VM27_CPU_TLBI_HOST_MASK_V1 & (UINT64_C(1)<<bit))==0));
    }
    q.hostContextWord40=UINT64_MAX;CHECK(VM27CPUInterpretTLBICapabilityV1(&q,&out) && out.supported);
    VM27CPUTLBICapabilityInputV1 bad=q;
    bad.schemaVersion=0;Refuse(bad);bad=q;bad.queryCalls=0;Refuse(bad);
    bad=q;bad.queryCalls=2;Refuse(bad);bad=q;bad.actualOwnerThread=0;Refuse(bad);
    bad=q;bad.nativeReturn=1;Refuse(bad);bad=q;bad.sysctlReturn=-1;Refuse(bad);
    bad=q;bad.sysctlOutputBytes=0;Refuse(bad);bad=q;bad.sysctlOutputBytes=8;Refuse(bad);
    bad=q;bad.vmmPresent=-1;Refuse(bad);bad=q;bad.vmmPresent=2;Refuse(bad);
    bad=q;bad.guardedContextKnown=0;Refuse(bad);bad=q;bad.guardedContextKnown=2;Refuse(bad);
    CHECK(!VM27CPUInterpretTLBICapabilityV1(NULL,&out));
    CHECK(!VM27CPUInterpretTLBICapabilityV1(&q,NULL));
    VM27CPUTLBICapabilityInputV1 prior=q;
    CHECK(!VM27CPUInterpretTLBICapabilityV1(&q,(VM27CPUTLBICapabilityValueV1 *)&q));
    CHECK(!memcmp(&q,&prior,sizeof(q)));
    printf("{\"checks\":%u,\"nativeCalls\":0,\"deviceOperations\":0,\"pureInterpretationOnly\":true}\n",Checks);
    return 0;
}
