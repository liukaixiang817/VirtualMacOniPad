#include "modern_cpu_config_capability_acquisition_v2.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
static unsigned Checks,Queries,SDKCalls,OwnerCalls,SysctlCalls,Unmaps;
static unsigned char Prefix[0x148],Golden[0xe0],SDK[3];
static const char *Mode;
static void *Retained;static size_t RetainedBytes;
#define CHECK(v) do{++Checks;if(!(v)){fprintf(stderr,"FAIL%d %s\n",__LINE__,#v);abort();}}while(0)
static bool Is(const char *s){return !strcmp(Mode,s);}
bool VM27CPUCapabilityTestProfileV2(void){return !Is("unsupported-profile");}
uint64_t VM27CPUCapabilityTestOwnerV2(void){uint64_t value=0;CHECK(!pthread_threadid_np(NULL,&value));++OwnerCalls;return value+(Is("post-owner-change") && OwnerCalls>1);}
int VM27CPUCapabilityTestSysctlV2(const char *name,void *out,size_t *bytes,void *in,size_t n){
 ++SysctlCalls;CHECK(!strcmp(name,"kern.hv_vmm_present") && !in && !n && *bytes==4);
 if(Is("sysctl-failure"))return -1;
 int value=0;memcpy(out,&value,4);*bytes=Is("sysctl-short")?3:4;return 0;
}
bool VM27CPUCapabilityTestSDKV2(uint64_t token){CHECK(token==VZ_KERNEL_FEATURE_SEED_SDK_TOKEN && SDKCalls<3);return SDK[SDKCalls++]!=0;}
int VM27CPUCapabilityTestUnmapV2(void *p,size_t bytes){++Unmaps;
 CHECK(bytes==3*16384);
 if(Is("cleanup-failure")){Retained=p;RetainedBytes=bytes;return -1;}
 return munmap(p,bytes);
}
int32_t VM27CPUConfigCapabilityKernelQueryV1(uint64_t op,void *buffer){
 ++Queries;CHECK(op==0 && Queries==1 && !((uintptr_t)buffer%32));
 if(Is("query-reentry")){VM27CPUCapabilitiesV2 nested;memset(&nested,0xa5,sizeof(nested));VM27CPUConfigAcquireCapabilitiesV2(&nested);
  CHECK(!nested.featureSeedKnown && !nested.TLBI.known && !nested.TLBI.supported);}
 if(Is("native-failure"))return (int32_t)UINT32_C(0xfae94001);
 memcpy(buffer,Prefix,sizeof(Prefix));uint64_t all=UINT64_MAX;memcpy((unsigned char *)buffer+0x40,&all,8);
 uint64_t a=UINT64_C(0xaabbccdd11223344),b=UINT64_C(0x5566778899aabbcc);
 memcpy((unsigned char *)buffer+0x149,&a,8);memcpy((unsigned char *)buffer+0x151,&b,8);
 if(Is("exterior-failure"))((unsigned char *)buffer)[352]=0;
 return 0;
}
static void *Foreign(void *p){VM27CPUCapabilitiesV2 *expected=p,actual={0};VM27CPUConfigAcquireCapabilitiesV2(&actual);CHECK(!memcmp(&actual,expected,sizeof(actual)));return NULL;}
int main(int argc,char **argv){
 CHECK(argc==3);Mode=argv[1];FILE *f=fopen(argv[2],"rb");CHECK(f);CHECK(fread(Prefix,1,sizeof(Prefix),f)==sizeof(Prefix));
 CHECK(fread(SDK,1,3,f)==3);CHECK(fread(Golden,1,sizeof(Golden),f)==sizeof(Golden));CHECK(fgetc(f)==EOF);CHECK(!fclose(f));
 VM27CPUCapabilitiesV2 value;memset(&value,0xa5,sizeof(value));VM27CPUConfigAcquireCapabilitiesV2(&value);
 bool kernelKnown=!Is("unsupported-profile") && !Is("native-failure") && !Is("exterior-failure") && !Is("post-owner-change") && !Is("cleanup-failure");
 CHECK(value.featureSeedKnown==kernelKnown);
 CHECK(value.IPA.known==kernelKnown);
 if(kernelKnown)CHECK(value.IPA.rawFieldA==UINT64_C(0xaabbccdd11223344) && value.IPA.rawFieldB==UINT64_C(0x5566778899aabbcc));
 else CHECK(!value.IPA.rawFieldA && !value.IPA.rawFieldB);
 CHECK(value.TLBI.known==(kernelKnown && !Is("sysctl-failure") && !Is("sysctl-short")));
 CHECK(value.TLBI.supported==value.TLBI.known);
 if(kernelKnown){unsigned char encoded[0xe0];CHECK(!VZKernelCapabilitySeedEncodeLE(&value.featureSeed,encoded));CHECK(!memcmp(encoded,Golden,sizeof(encoded)));}
 else {VZKernelCapabilitySeed zero={0};CHECK(!memcmp(&value.featureSeed,&zero,sizeof(zero)));}
 unsigned before=Queries;VM27CPUTLBICapabilityValueV1 tlbi={0};VM27CPUConfigAcquireTLBICapabilityV1(&tlbi);
 CHECK(tlbi.known==value.TLBI.known && tlbi.supported==value.TLBI.supported && Queries==before);
 VM27CPURawIPAPairV2 pair={0};VM27CPUConfigAcquireRawIPAPairV2(&pair);
 CHECK(pair.known==value.IPA.known && pair.rawFieldA==value.IPA.rawFieldA && pair.rawFieldB==value.IPA.rawFieldB && Queries==before);
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,Foreign,&value));CHECK(!pthread_join(thread,NULL));CHECK(Queries==before);
 CHECK(Queries==(Is("unsupported-profile")?0u:1u));
 CHECK(SDKCalls==((!Is("unsupported-profile") && !Is("native-failure") && !Is("exterior-failure"))?3u:0u));
 if(Retained)CHECK(!munmap(Retained,RetainedBytes));
 printf("{\"mode\":\"%s\",\"checks\":%u,\"mockQueryCalls\":%u,\"mockSDKCalls\":%u,\"sysctlCalls\":%u,\"unmapCalls\":%u,\"genuineGoldenCompared\":%s,\"nativeCallsExecuted\":0,\"deviceOperations\":0}\n",Mode,Checks,Queries,SDKCalls,SysctlCalls,Unmaps,kernelKnown?"true":"false");return 0;
}
