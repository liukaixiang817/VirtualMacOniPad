#include "vm_host_target_policy_v2.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const char *eligible[] = {"iPad13,4","iPad13,5","iPad13,6","iPad13,7",
        "iPad13,8","iPad13,9","iPad13,10","iPad13,11","iPad13,16","iPad13,17",
        "iPad14,3","iPad14,4","iPad14,5","iPad14,6","iPhone15,2","iPhone15,3"};
    for (size_t i=0;i<sizeof(eligible)/sizeof(*eligible);++i) {
        assert(VM27HostExperimentalMatchesV2(eligible[i],"22.1.0","20B101",16384));
        assert(VM27HostExperimentalMatchesV2(eligible[i],"22.3.0","20D67",16384));
        assert(VM27HostExperimentalMatchesV2(eligible[i],"21.0.0","19A346",16384));
        assert(VM27HostExperimentalMatchesV2(eligible[i],"21.6.0","19H12",16384));
        assert(VM27HostExperimentalMatchesV2(eligible[i],"22.0.0","20A362",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.3.0","20D68",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.4.0","20E247",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.3.0","20D5024f",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.1","20B101",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.1.0","",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.1.0","20",16384));
        assert(!VM27HostExperimentalMatchesV2(eligible[i],"22.1.0","20B101",4096));
    }
    assert(VMHostFamilyForMachineV1("iPad14,8")==VMHostFamilyM2V1);
    assert(VMHostFamilyForMachineV1("iPad14,11")==VMHostFamilyM2V1);
    assert(!VM27HostExperimentalMatchesV2("iPad14,8","23.5.0","21F79",16384));
    assert(!VM27HostExperimentalMatchesV2("iPhone15,4","22.1.0","20B101",16384));
    assert(!VM27HostExperimentalMatchesV2("iPad13,3","22.1.0","20B101",16384));
    assert(!VM27HostExperimentalMatchesV2(NULL,"22.1.0","20B101",16384));
    assert(!VM27HostExperimentalMatchesV2("iPad14,6",NULL,"20B101",16384));
    assert(!VM27HostExperimentalMatchesV2("iPad14,6","22.1.0",NULL,16384));
    assert(!VMHostInRequestedDopamineRangeV1(14,8,1));
    assert(VMHostInRequestedDopamineRangeV1(15,0,0));
    assert(VMHostInRequestedDopamineRangeV1(15,8,6));
    assert(VMHostInRequestedDopamineRangeV1(16,3,1));
    assert(!VMHostInRequestedDopamineRangeV1(16,3,2));
    assert(!VMHostInRequestedDopamineRangeV1(16,4,0));
    assert(!VMHostInRequestedDopamineRangeV1(17,0,0));
    puts("Target families and kernel ABI boundary passed; no native operations or device acceptance claimed.");
    return 0;
}
