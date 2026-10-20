// Local finite model of the real V21 reader. No device, HV, or real commpage.
#include "modern_cpu_counter_domain_reader_v21.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,profileCalls,mappedCalls,copyCalls,archCalls,physicalCalls,timebaseCalls;
static unsigned profileFail,copyFailAt,archFailAt,releaseFailAt;
static bool machCopyWorks;
static int32_t timebaseFailure;
static uint64_t beforePhysical,afterPhysical,machValue,frequency,biasBefore,biasAfter;
static uint16_t versionBefore,versionAfter;
static uint8_t kindBefore,kindAfter;
static uint32_t numer,denom;
static void Need(bool ok,const char *why) {
 ++checks;if(!ok){fprintf(stderr,"reader21 fixture failed: %s\n",why);exit(1);}
}
static void Reset(void) {
 profileCalls=mappedCalls=copyCalls=archCalls=physicalCalls=timebaseCalls=0;
 profileFail=copyFailAt=archFailAt=releaseFailAt=0;machCopyWorks=false;timebaseFailure=0;
 beforePhysical=100;afterPhysical=120;biasBefore=biasAfter=20;machValue=130;
 frequency=24000000;numer=125;denom=3;versionBefore=versionAfter=3;kindBefore=kindAfter=3;
}
static bool Profile(const char *name,const char *expected) {
 static const char *const names[]={"hw.machine","kern.osrelease","kern.osversion"};
 static const char *const values[]={"iPad14,6","22.1.0","20B101"};
 Need(profileCalls<3,"only three target profile queries");
 Need(!strcmp(name,names[profileCalls]) && !strcmp(expected,values[profileCalls]),"exact hw.machine/release/build key and order");
 ++profileCalls;return profileCalls!=profileFail;
}
static bool Mapped(const void *p,size_t n,bool writable,VM27CPUSelfMappedReceiptV1 *r) {
 ++mappedCalls;Need(!writable,"no writable commpage query");
 Need((uintptr_t)p==VZ_COUNTER_COMMPAGE_BASE_V21+0x1e ||
  (uintptr_t)p==VZ_COUNTER_COMMPAGE_BASE_V21+0x88 ||
  (uintptr_t)p==VZ_COUNTER_COMMPAGE_BASE_V21+0x90,"only fixed architectural page");
 Need(n==1 || n==2 || n==8,"only architectural field widths");
 *r=(VM27CPUSelfMappedReceiptV1){.queries=1,.queryStatus=KERN_INVALID_ADDRESS,
  .portReleaseStatus=mappedCalls==releaseFailAt?KERN_INVALID_NAME:KERN_SUCCESS};return false;
}
static uint64_t Field(unsigned ordinal) {
 switch(ordinal) {
 case 1:return versionBefore;case 2:return kindBefore;case 3:return biasBefore;
 case 4:return biasAfter;case 5:return kindAfter;case 6:return versionAfter;
 default:Need(false,"six ordered fields only");return 0;
 }
}
static int32_t Copy(uintptr_t p,size_t n,void *out,uint64_t *copied) {
 (void)p;++copyCalls;uint64_t value=Field(mappedCalls);
 if(machCopyWorks && copyCalls!=copyFailAt){memcpy(out,&value,n);*copied=n;return KERN_SUCCESS;}
 // Even a nominal success with a short copy must not publish partial bytes.
 *copied=n-1;memset(out,0x5a,n);return KERN_SUCCESS;
}
static bool Arch(uint32_t offset,uint32_t n,uint64_t *out) {
 ++archCalls;Need((offset==0x1e && n==2) || (offset==0x88 && n==8) ||
  (offset==0x90 && n==1),"strict field/width whitelist reaches architectural load");
 if(mappedCalls==archFailAt)return false;*out=Field(mappedCalls);return true;
}
static int32_t Timebase(mach_timebase_info_data_t *t) {
 ++timebaseCalls;t->numer=numer;t->denom=denom;return timebaseFailure;
}
static uint64_t Frequency(void){return frequency;}
static uint64_t Physical(void){++physicalCalls;return physicalCalls==1?beforePhysical:afterPhysical;}
static uint64_t Mach(void){return machValue;}
const VZKernelCounterDomainTestHooksV21 VM27CounterDomainTestHooksV21={
 Profile,Mapped,Copy,Arch,Timebase,Frequency,Physical,Mach};
// The build command supplies an exact extracted frozen V19 validator body.
#include VM27_COUNTER_VALIDATOR_FIXTURE_BODY
#include "modern_cpu_counter_domain_reader_v21.c"
static VZKernelCounterSampleReceiptV21 Sample(bool expected) {
 VZKernelCounterDomainSampleV19 out,sentinel;memset(&out,0xa5,sizeof(out));sentinel=out;
 VZKernelCounterSampleReceiptV21 r={0};bool ok=VZKernelReadCounterDomainSampleDetailedV21(NULL,&out,&r);
 Need(ok==expected && r.completed==expected,"true completion result");
 Need(r.schemaVersion==1,"typed receipt schema");
 if(ok)Need(!memcmp(&out,&r.sample,sizeof(out)),"only complete sample published");
 else Need(!memcmp(&out,&sentinel,sizeof(out)),"failed sample keeps caller output unchanged");
 return r;
}
int main(void) {
 VZKernelCounterSampleReceiptV21 r;
 Reset();r=Sample(true);
 Need(r.targetProfileMatched && r.stage==VZ_COUNTER_SAMPLE_COMPLETE_V21 &&
  r.domainValidationAttempted && r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19,"actual sample guards remain validated");
 Need(profileCalls==3 && timebaseCalls==1 && mappedCalls==6 && copyCalls==6 && archCalls==6 && physicalCalls==2,"finite fallback sampling calls");
 for(unsigned i=0;i<6;++i)Need(r.fields[i].copyAttempted && !r.fields[i].copyComplete &&
  r.fields[i].architecturalAttempted && r.fields[i].completed,"each short copy uses actual fixed load");
 Reset();machCopyWorks=true;r=Sample(true);
 Need(copyCalls==6 && archCalls==0 && r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19,"direct Mach copy works despite generic region rejection");
 for(unsigned i=1;i<=6;++i) {
  Reset();machCopyWorks=true;copyFailAt=i;r=Sample(true);
  Need(archCalls==1 && r.fields[i-1].architecturalAttempted,"only failed Mach copy falls back");
  Reset();archFailAt=i;r=Sample(false);
  Need(r.stage==VZ_COUNTER_SAMPLE_FIELD_V21 && r.failedFieldOrdinal==i &&
   r.attemptedFields==i && r.completedFields==i-1,"exact failed field and partial diagnostics");
  Need(!r.domainValidationAttempted && mappedCalls==i && copyCalls==i,"no extra read or fabricated validation after failure");
  Reset();releaseFailAt=i;r=Sample(false);
  Need(mappedCalls==i && copyCalls==i-1 && archCalls==i-1 && r.failedFieldOrdinal==i,"object-port release failure never falls back");
 }
 for(unsigned i=1;i<=3;++i) {
  Reset();profileFail=i;r=Sample(false);
  Need(profileCalls==i && !mappedCalls && !copyCalls && !archCalls && !physicalCalls && !timebaseCalls,"wrong true target identity rejects before all field/counter access");
  Need(r.stage==VZ_COUNTER_SAMPLE_PROFILE_V21 && !r.targetProfileMatched,"profile failure receipt");
 }
 Reset();timebaseFailure=KERN_FAILURE;r=Sample(false);
 Need(r.stage==VZ_COUNTER_SAMPLE_TIMEBASE_V21 && r.timebaseStatus==KERN_FAILURE &&
  !mappedCalls && !physicalCalls,"actual timebase failure boundary");
 Reset();versionAfter=2;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_COMMPAGE_V19,"version mismatch remains invalid");
 Reset();kindBefore=kindAfter=0;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_COMMPAGE_V19,"unsupported timebase remains invalid");
 Reset();kindAfter=2;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_COMMPAGE_V19,"changed timebase remains invalid");
 Reset();++biasAfter;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_UNSTABLE_V19,"changed bias remains invalid");
 Reset();afterPhysical=99;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_UNSTABLE_V19,"backwards counter remains invalid");
 Reset();frequency=0;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_FREQUENCY_V19,"zero frequency remains invalid");
 Reset();++frequency;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_FREQUENCY_V19,"timebase ratio mismatch remains invalid");
 Reset();frequency=UINT64_C(0x100000000);r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_FREQUENCY_V19,"oversized frequency remains invalid");
 Reset();machValue=119;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_EPOCH_V19,"before bracket remains invalid");
 Reset();machValue=141;r=Sample(true);Need(r.domainResult==VZ_COUNTER_DOMAIN_EPOCH_V19,"after bracket remains invalid");
 Reset();biasBefore=biasAfter=UINT64_MAX-19;machValue=90;r=Sample(true);
 Need(r.domainResult==VZ_COUNTER_DOMAIN_VALID_V19,"genuine negative modular bias accepted without rewriting epoch");
 Reset();VZKernelCounterDomainSampleV19 out={0};Need(VZKernelReadCounterDomainSampleV21(NULL,&out),"unchanged callback ABI publishes complete sample");
 Reset();VZKernelCounterFieldReceiptV21 field;Need(!CounterFixedFieldV21(0x88,4,&field) &&
  !CounterFixedFieldV21(0x18,8,&field) && !mappedCalls && !copyCalls && !archCalls,"wrong offset or width cannot reach reads");
 Reset();Need(!VZKernelReadCounterDomainSampleDetailedV21(NULL,NULL,&r) &&
  r.stage==VZ_COUNTER_SAMPLE_ARGUMENT_V21 && !profileCalls,"null sample never queries profile");
 printf("{\"passed\":true,\"checks\":%u,\"realDeviceExecuted\":false,\"nativeCalls\":0}\n",checks);
 return 0;
}
