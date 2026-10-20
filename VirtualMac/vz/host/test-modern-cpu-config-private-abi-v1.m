#include "modern_cpu_config_private_abi_v1.h"
#include "modern_cpu_config_os_object_v3.h"
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t operation,void *out) {
    (void)operation;(void)out;abort(); /* This Mac profile must never issue SVC. */
}
static unsigned Checks;
#define CHECK(v) do { ++Checks; if (!(v)) { fprintf(stderr,"FAIL %d %s\n",__LINE__,#v); abort(); } } while(0)
int main(void) {
    CHECK(_hv_vcpu_config_set_tlbi_workaround_enabled(NULL,false)==VM27_CPU_CONFIG_BAD_ARGUMENT_V3);
    CHECK(_hv_vcpu_config_set_fgt_enabled((hv_vcpu_config_t)(uintptr_t)1,false)==VM27_CPU_CONFIG_BAD_ARGUMENT_V3);
    VM27CPUConfigHandleV3 handle={0};CHECK(!VM27CPUConfigCreateV3(&handle));
    hv_vcpu_config_t actual=(hv_vcpu_config_t)handle.object;
    VM27CPUConfigSnapshotV3 before={0},after={0};CHECK(!VM27CPUConfigCopyV3(handle,&before));
    CHECK(!before.trapTLBISW && !before.fineGrainedTraps && !before.supportKnown);
    CHECK(!_hv_vcpu_config_set_tlbi_workaround_enabled(actual,false));
    CHECK(!VM27CPUConfigCopyV3(handle,&after) && !memcmp(&before,&after,sizeof(before)));
    /* Mac host is outside the actual iPad native capability profile. The true
     * acquisition returns UNKNOWN without SVC, preserving the actual config. */
    CHECK(_hv_vcpu_config_set_tlbi_workaround_enabled(actual,true)==VM27_CPU_CONFIG_UNSUPPORTED_V3);
    CHECK(!VM27CPUConfigCopyV3(handle,&after) && !memcmp(&before,&after,sizeof(before)));
    CHECK(!_hv_vcpu_config_set_fgt_enabled(actual,true));
    CHECK(!VM27CPUConfigCopyV3(handle,&after) && after.fineGrainedTraps==1 && !after.trapTLBISW);
    CHECK(!_hv_vcpu_config_set_fgt_enabled(actual,false));
    CHECK(!VM27CPUConfigCopyV3(handle,&after) && !memcmp(&before,&after,sizeof(before)));
    VM27CPUConfigBorrowV3 *borrow=NULL;CHECK(!VM27CPUConfigBorrowObjectV3(actual,&borrow));
    CHECK(!VM27CPUConfigReadBorrowV3(borrow,&after) && after.generation==handle.generation);
    CFRelease((CFTypeRef)actual);
    CHECK(!_hv_vcpu_config_set_tlbi_workaround_enabled(actual,false));
    CHECK(!VM27CPUConfigReleaseBorrowV3(borrow));
    uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);
    CHECK(created==1 && destroyed==1);
    CHECK(_hv_vcpu_config_set_tlbi_workaround_enabled(actual,false)==VM27_CPU_CONFIG_BAD_ARGUMENT_V3);
    CHECK(_hv_vcpu_config_set_fgt_enabled(actual,true)==VM27_CPU_CONFIG_BAD_ARGUMENT_V3);
    printf("{\"checks\":%u,\"actualOwnedConfigRegistry\":true,\"falseTLBIQueryFree\":true,\"unknownTrueUnchanged\":true,\"actualFGTState\":true,\"nativeOperations\":0,\"deviceOperations\":0}\n",Checks);
    return 0;
}
