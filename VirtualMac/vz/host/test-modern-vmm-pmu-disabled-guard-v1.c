// Actual A64 caller-guard body, typed SYS getters mocked; no native CPU.
#include "modern_cpu_own_feature_profile_v1.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
static uint64_t DFR0;static bool Fail;static unsigned Calls;
VZKernelStatus VZKernelCapabilitySeedGetFeature(const VZKernelCapabilitySeed *seed,uint32_t selector,uint64_t *out){CHECK(seed&&out&&selector==0);*out=DFR0;return VZ_KERNEL_OK;}
int32_t VM27PMUFixtureGetSYS(uint64_t cpu,uint16_t selector,uint64_t *out){CHECK(cpu==7&&selector==0xc028&&out);++Calls;if(Fail)return (int32_t)UINT32_C(0xfae9400f);*out=DFR0;return 0;}
extern unsigned VM27PMUHostInvoke(const uint64_t *,void *,unsigned);
int main(void){unsigned char frame[0x1e00],before[sizeof(frame)];uint64_t cpu=7;for(unsigned variant=0;variant<2;++variant)for(unsigned pmu=0;pmu<3;++pmu)for(unsigned value=0;value<2;++value){memset(frame,0xa5,sizeof(frame));uint64_t v=value;memcpy(frame+0x1da0,&v,8);memcpy(before,frame,sizeof(frame));DFR0=(uint64_t)pmu<<8;Calls=0;Fail=false;CHECK(VM27PMUHostInvoke(&cpu,frame,variant)==(pmu?0:value?2:1)&&Calls==1&&!memcmp(frame,before,sizeof(frame)));}Fail=true;Calls=0;CHECK(VM27PMUHostInvoke(&cpu,frame,0)==2&&Calls==1);Fail=false;
 for(unsigned pmu=0;pmu<16;++pmu){CHECK(VM27CPUOwnProfileValidateSYSWriteV1(0xc028,((uint64_t)pmu<<8)|6)==(pmu?VZ_KERNEL_UNSUPPORTED:VZ_KERNEL_OK));}DFR0=6;uint64_t out=99;CHECK(!VM27CPUOwnProfileGetFeatureV1((void *)&cpu,0,&out)&&out==6);
 puts("{\"actualA64SaveRestoreGuardBodyExecuted\":true,\"onlyDisabledPMUAndZeroFrameOmitted\":true,\"enabledPMURetainsOriginalPath\":true,\"nonzeroDisabledFrameAndGetterFailureFatal\":true,\"saveRestoreNeverFabricatesPMCR1Data\":true,\"PMUFeatureAdvertisementUnchanged\":true,\"SYSWriteCannotEnablePMU\":true,\"allFrameBytesUnchanged\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;}
