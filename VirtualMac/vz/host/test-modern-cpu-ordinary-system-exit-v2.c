#include "modern_cpu_native_exit_reducer_v2.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checked;
static void accepted(VZCPUNativeExitValuesV1 q) {
    VZCPUNativeExitValuesV1 before=q;
    VZCPUExitReductionV1 r={0};
    assert(VZCPUReduceNativeExitV1(&q,&r)==VZ_CPU_EXIT_REDUCER_OK_V1);
    VZCPUDecodedPublicExceptionV1 expected={1,0,q.syndrome32,q.virtualAddress,q.physicalAddress};
    assert(r.schemaVersion==1 && r.kind==VZ_CPU_EXIT_DECODED_EXCEPTION_V1 &&
        r.hasPublicException==1 && r.rawReason==q.rawReason &&
        !memcmp(&r.exception,&expected,sizeof(expected)) && !memcmp(&q,&before,sizeof(q)));
    ++checked;
}
static void refused(VZCPUNativeExitValuesV1 q,VZCPUExitReducerStatusV1 status) {
    VZCPUExitReductionV1 r,before;memset(&r,0xa5,sizeof(r));before=r;
    assert(VZCPUReduceNativeExitV1(&q,&r)==status && !memcmp(&r,&before,sizeof(r)));++checked;
}
int main(void) {
    /* Exact Normal41 successful native9/identity-validated failing receipt. */
    VZCPUNativeExitValuesV1 q={.schemaVersion=1,
        .nativeContextVersion=VZ_CPU_EXIT_REDUCER_NATIVE_VERSION_V1,
        .knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1,.rawReason=8,.syndrome32=0x6230010f};
    accepted(q); /* genuine MRS c038 -> unchanged 32-byte public exception */
    q.virtualAddress=0x123456789abcdef0ULL;q.physicalAddress=0xfedcba9876543210ULL;
    q.rawReason=1;accepted(q);q.rawReason=6;accepted(q);
    q.syndrome32=0x6220010e;accepted(q); /* legal op0=2 MSR direction */
    q.syndrome32=0x6030010f;refused(q,VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1); /* IL0 */
    q.syndrome32=0x6210010f;refused(q,VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1); /* op0=1 SYS */
    q.syndrome32=0x5a000000;refused(q,VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1); /* HVC */
    q.syndrome32=0xfe000000;refused(q,VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1); /* private */
    q.syndrome32=0x6230010f;q.knownFields=1;refused(q,VZ_CPU_EXIT_REDUCER_INCOMPLETE_V1);
    q.knownFields=15;q.nativeReturnBits=0xfae9400f;refused(q,VZ_CPU_EXIT_REDUCER_NATIVE_FAILED_V1);
    q.nativeReturnBits=0;q.nativeContextVersion^=1;refused(q,VZ_CPU_EXIT_REDUCER_UNSUPPORTED_V1);
    printf("{\"focusedCases\":%u,\"actualNormal41ReceiptForwardedExactly\":true,\"refusalsPreserveOutput\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}\n",checked);
}
