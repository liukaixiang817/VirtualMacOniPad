#include "vm27_no_mac_haptic_port_v1.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
static unsigned checks,failures;
#define CHECK(x) do { ++checks; if (!(x)) ++failures; } while (0)
int main(void) {
    for (unsigned i=0;i<64;++i) {
        uint64_t device=UINT64_MAX-i,options=UINT64_C(0xa03182746655f900)+i;
        int64_t pattern=i&1 ? INT32_MIN : INT32_MAX;
        errno=0;uint32_t status=VM27NoHapticV1();
        CHECK(status==(uint32_t)ENOTSUP);CHECK(errno==ENOTSUP);
        errno=0;CHECK(VM27RejectHapticV1(status,device,pattern,options)==ENOTSUP);CHECK(errno==ENOTSUP);
        VM27HapticRejectV1 report={0};CHECK(VM27CopyHapticRejectV1(&report)==0);
        CHECK(report.statusRequests==i+1 && report.patternRequests==i+1);
        CHECK(report.rejectedStatus==status && report.device==device && report.pattern==pattern && report.options==options);
    }
    CHECK(VM27RejectHapticV1(0,0,0,0)==EINVAL);CHECK(errno==EINVAL);
    CHECK(VM27CopyHapticRejectV1(NULL)==EINVAL);CHECK(errno==EINVAL);
    VM27HapticRejectV1 report={0};CHECK(VM27CopyHapticRejectV1(&report)==0);
    CHECK(report.statusRequests==64 && report.patternRequests==64);
    printf("{\"checks\":%u,\"failures\":%u,\"unsupportedStatusRequests\":64,\"unsupportedPatterns\":64,\"hardwareCalls\":0,\"VZCalls\":0}\n",checks,failures);
    return failures?1:0;
}
