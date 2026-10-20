#include "modern_cpu_tlbi_capability_values_v1.h"
#include <stddef.h>
#include <stdint.h>
static bool SpanOverlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x>UINTPTR_MAX-an || y>UINTPTR_MAX-bn || (x<y+bn && y<x+an);
}
bool VM27CPUInterpretTLBICapabilityV1(const VM27CPUTLBICapabilityInputV1 *q,
    VM27CPUTLBICapabilityValueV1 *out) {
    if(!q || !out || SpanOverlap(q,sizeof(*q),out,sizeof(*out)) ||
        q->schemaVersion!=1 || q->queryCalls!=1 || !q->actualOwnerThread ||
        q->nativeReturn!=0 || q->sysctlReturn!=0 || q->sysctlOutputBytes!=4 ||
        q->guardedContextKnown!=1 || (q->vmmPresent!=0 && q->vmmPresent!=1))
        return false;
    VM27CPUTLBICapabilityValueV1 value={true,q->vmmPresent==0 &&
        (q->hostContextWord40 & VM27_CPU_TLBI_HOST_MASK_V1)==VM27_CPU_TLBI_HOST_MASK_V1};
    *out=value;
    return true;
}
