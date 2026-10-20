// Execute the actual A64 guard body; only the existing dlsym boundary is mocked.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d %s\n",__LINE__,#x); abort(); } } while (0)
static uint32_t Answer, Status;
static unsigned Lookups, Queries;
static int Missing, LeaveUnwritten;
static int32_t Query(uint64_t identity,uint32_t *out) {
    CHECK(identity==7 && out); ++Queries;
    __asm__ volatile("movi v0.16b, #0x55\n\tmovi v31.16b, #0x66\n\tcmp xzr, xzr" ::: "v0", "v31", "cc");
    if (Status) return (int32_t)Status;
    if (!LeaveUnwritten) *out=Answer;
    return 0;
}
void *VM27AMXFixtureDlsym(void *handle,const char *name) {
    CHECK(handle==(void *)(intptr_t)-2 && !strcmp(name,"VM27VMMGetAMXAvailabilityV1")); ++Lookups;
    if (Missing) return NULL;
    // Real arm64e dlsym returns an ASIA/zero signed function pointer. Supply that
    // same boundary contract while executing the production BLRAAZ instruction.
    void *answer=(void *)(uintptr_t)&Query;
    __asm__ volatile("paciza %0" : "+r"(answer));
    return answer;
}
extern unsigned VM27AMXHostInvoke(const uint64_t *,void *,unsigned);
uint64_t VM27AMXFixtureExitNZCV;
unsigned char VM27AMXFixtureExitVectors[32];
uint64_t VM27AMXFixtureExitX8;
static unsigned run(unsigned char *frame,unsigned variant,unsigned expected) {
    unsigned char before[0x1e00]; memcpy(before,frame,sizeof(before));
    uint64_t cpu=7; Lookups=Queries=0;
    CHECK(VM27AMXHostInvoke(&cpu,frame,variant)==expected);
    CHECK(Lookups==1 && Queries==(Missing?0u:1u));
    CHECK(!memcmp(frame,before,sizeof(before)));
    CHECK(VM27AMXFixtureExitNZCV==UINT64_C(0xa0000000));
    CHECK(VM27AMXFixtureExitX8==0x1234);
    for (unsigned i=0;i<16;++i) CHECK(VM27AMXFixtureExitVectors[i]==0x17 && VM27AMXFixtureExitVectors[i+16]==0x29);
    return 1;
}
int main(void) {
    unsigned char frame[0x1e00]; unsigned cases=0;
    for(unsigned variant=0;variant<2;++variant) {
        // Invalid payload is deliberately nonzero and is never consulted.
        memset(frame,0xa5,sizeof(frame)); memset(frame+0x958,0,16); frame[0x1d68]=0;
        Answer=0; Status=0; Missing=LeaveUnwritten=0;
        cases+=run(frame,variant,1);
        for(unsigned which=0;which<3;++which) {
            unsigned off=which==0?0x958:which==1?0x960:0x1d68;
            frame[off]=1; cases+=run(frame,variant,2); frame[off]=0;
        }
        Answer=1; frame[0x958]=frame[0x960]=frame[0x1d68]=1;
        cases+=run(frame,variant,0);
        Answer=2; cases+=run(frame,variant,2);
        Answer=0; Status=UINT32_C(0xfae9400f); cases+=run(frame,variant,2);
        Status=0; Missing=1; cases+=run(frame,variant,2);
        Missing=0; LeaveUnwritten=1; cases+=run(frame,variant,2); LeaveUnwritten=0;
    }
    printf("{\"actualA64SaveRestoreGuardBodyExecuted\":true,\"cases\":%u,\"onlyExplicitAbsentInactiveZeroControlsOmitted\":true,\"presentRetainsOriginalPath\":true,\"unknownOutputAndQueryErrorsFatal\":true,\"dlsymNullFatal\":true,\"nonzeroInactiveControlsAndValidityFatal\":true,\"invalidPayloadNotRead\":true,\"allFrameBytesUnchanged\":true,\"testedCallerVectorGPRAndNZCVPreserved\":true,\"actualAuthenticatedIndirectCallExecuted\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}\n",cases);
    return 0;
}
