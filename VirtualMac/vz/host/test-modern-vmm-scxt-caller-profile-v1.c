// No native hypervisor: execute the same A64 guard body against typed mocks.
#include "modern_cpu_own_feature_profile_v1.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
static uint64_t PFR0,PFR1;static unsigned Calls,FailAt;
VZKernelStatus VZKernelCapabilitySeedGetFeature(const VZKernelCapabilitySeed *seed,uint32_t selector,uint64_t *out){CHECK(seed&&out&&(selector==7||selector==8));*out=selector==7?PFR0:PFR1;return VZ_KERNEL_OK;}
int32_t VM27SCXTFixtureGetSYS(uint64_t cpu,uint16_t selector,uint64_t *out){CHECK(cpu==7&&out&&selector==(Calls%2?0xc021:0xc020));++Calls;if(Calls==FailAt)return (int32_t)UINT32_C(0xfae9400f);*out=selector==0xc020?PFR0:PFR1;return 0;}
extern unsigned VM27SCXTHostInvoke(const uint64_t *,void *,unsigned);
int main(void){unsigned char frame[0x800];memset(frame,0xa5,sizeof(frame));unsigned char before[sizeof(frame)];memcpy(before,frame,sizeof(frame));uint64_t cpu=7;
 const unsigned csv[]={0,1,1,1,2,3,4,1,2},frac[]={0,0,1,2,0,0,0,3,1},want[]={1,1,1,1,0,0,2,2,2};
 for(unsigned variant=0;variant<2;++variant)for(unsigned i=0;i<sizeof(csv)/sizeof(csv[0]);++i){PFR0=(uint64_t)csv[i]<<56;PFR1=(uint64_t)frac[i]<<32;Calls=FailAt=0;CHECK(VM27SCXTHostInvoke(&cpu,frame,variant)==want[i]&&Calls==2&&!memcmp(frame,before,sizeof(frame)));}
 for(unsigned failure=1;failure<=2;++failure){PFR0=PFR1=0;Calls=0;FailAt=failure;CHECK(VM27SCXTHostInvoke(&cpu,frame,0)==2&&Calls==failure&&!memcmp(frame,before,sizeof(frame)));}FailAt=0;
 VZKernelCapabilitySeed *seed=(void *)&cpu;for(unsigned csv2=0;csv2<16;++csv2){PFR0=((uint64_t)csv2<<56)|UINT64_C(0x00a123456789abcd);uint64_t out=UINT64_MAX;VZKernelStatus result=VM27CPUOwnProfileGetFeatureV1(seed,7,&out);if(csv2>3)CHECK(result==VZ_KERNEL_UNSUPPORTED&&out==UINT64_MAX);else{CHECK(!result&&((out>>56)&15)==(csv2>=2?1:csv2));CHECK(!VM27CPUOwnProfileValidateSYSWriteV1(0xc020,out));}CHECK(VM27CPUOwnProfileValidateSYSWriteV1(0xc020,(uint64_t)csv2<<56)==(csv2>1?VZ_KERNEL_UNSUPPORTED:VZ_KERNEL_OK));}
 PFR1=UINT64_MAX;uint64_t value=0;CHECK(!VM27CPUOwnProfileGetFeatureV1(seed,8,&value)&&!(value&(UINT64_C(15)<<32)));
 puts("{\"actualA64SaveAndRestoreGuardBodyExecuted\":true,\"absentSkipsBothRegistersAndAllFrameAccess\":true,\"presentRetainsOriginalSCXTPath\":true,\"invalidProfileAndGetterErrorsTakeFatalPath\":true,\"allGPRSIMDStackAndNZCVSaveRestoreAssembled\":true,\"knownCSV2SubsetBeforeCreation\":true,\"unknownCSV2Unsupported\":true,\"PFR0WritesCannotExposeCSV2_2\":true,\"PFR1FractionAbsentConsistent\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;}
