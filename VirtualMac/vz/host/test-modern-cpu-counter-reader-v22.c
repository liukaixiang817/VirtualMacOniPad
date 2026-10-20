/* Finite host contract test; no device or real commpage execution claimed. */
#define VM27_COUNTER_DOMAIN_TESTING_V21 1
#include "modern_cpu_counter_domain_reader_v21.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned profiles,timebases,maps,copies,fields,counterReads,failField;
static bool profileOK=true;
static uint64_t bias=20;
static uint16_t afterVersion=3;
static void need(bool v,const char *why){if(!v){fprintf(stderr,"FAIL %s\n",why);exit(1);}}
static bool profile(const char *name,const char *expected){
 static const char *names[]={"hw.machine","kern.osrelease","kern.osversion"};
 static const char *values[]={"iPad14,6","22.1.0","20B101"};
 ++profiles;bool known=false;
 for(unsigned i=0;i<3;++i)if(!strcmp(name,names[i])&&!strcmp(expected,values[i]))known=true;
 need(known,"actual profile keys");return profileOK;
}
static bool mapped(const void *p,size_t n,bool writable,VM27CPUSelfMappedReceiptV1 *r){
 (void)p;(void)n;need(!writable,"read only query");++maps;*r=(VM27CPUSelfMappedReceiptV1){.queryStatus=KERN_INVALID_ADDRESS,.portReleaseStatus=KERN_SUCCESS};return false;
}
static int32_t copy(uintptr_t p,size_t n,void *out,uint64_t *done){(void)p;(void)n;(void)out;++copies;*done=0;return KERN_INVALID_ADDRESS;}
static bool arch(uint32_t offset,uint32_t width,uint64_t *out){
 static const unsigned offsets[]={0x1e,0x90,0x88,0x88,0x90,0x1e},widths[]={2,1,8,8,1,2};
 unsigned i=fields++%6;need(offset==offsets[i]&&width==widths[i],"all six fresh fields and widths in order");
 if(failField && i+1==failField)return false;
 *out=i==0?3:i==5?afterVersion:i==1||i==4?3:bias;return true;
}
static int32_t timebase(mach_timebase_info_data_t *t){++timebases;t->numer=125;t->denom=3;return KERN_SUCCESS;}
static uint64_t frequency(void){return 24000000;}
static uint64_t physical(void){return counterReads++%2?120:100;}
static uint64_t absolute(void){return 110+bias;}
const VZKernelCounterDomainTestHooksV21 VM27CounterDomainTestHooksV21={profile,mapped,copy,arch,timebase,frequency,physical,absolute};
#include VM27_COUNTER_VALIDATOR_FIXTURE_BODY
#include "modern_cpu_counter_domain_reader_v22.c"
static void resetCalls(void){profiles=timebases=maps=copies=fields=counterReads=failField=0;}
int main(void){
 VZKernelCounterDomainSampleV19 out={0},sentinel;
 need(!VZKernelReadCounterDomainSampleV21(NULL,NULL)&&!profiles,"NULL no profile or reads");
 need(VZKernelReadCounterDomainSampleV21(NULL,&out),"first real-shaped sample");
 need(profiles==3&&timebases==1&&!maps&&!copies&&fields==6&&counterReads==2,"only fixed profile/timebase cached; no Mach field calls");
 need(VZKernelValidateCounterDomainV19(&out)==VZ_COUNTER_DOMAIN_VALID_V19,"unchanged actual-domain validator");
 resetCalls();bias=40;afterVersion=2;
 need(VZKernelReadCounterDomainSampleV21(NULL,&out),"second complete sample");
 need(!profiles&&!timebases&&!maps&&!copies&&fields==6&&counterReads==2&&out.commpageBaseBefore==40&&out.commpageVersionAfter==2,"mutable values read freshly");
 need(VZKernelValidateCounterDomainV19(&out)==VZ_COUNTER_DOMAIN_COMMPAGE_V19,"mismatch still invalid");
 resetCalls();failField=4;memset(&out,0xa5,sizeof(out));sentinel=out;
 need(!VZKernelReadCounterDomainSampleV21(NULL,&out)&&!memcmp(&out,&sentinel,sizeof(out)),"partial read never published");
 resetCalls();afterVersion=3;VZKernelCounterSampleReceiptV21 receipt={0};
 need(VZKernelReadCounterDomainSampleDetailedV21(NULL,&out,&receipt),"original detailed reader");
 need(profiles==3&&timebases==1&&maps==6&&copies==6&&fields==6&&receipt.completed&&receipt.domainValidationAttempted,"detailed genuine queries and receipts whole");
 atomic_store(&CounterProfileStateV22,0);resetCalls();profileOK=false;
 need(!VZKernelReadCounterDomainSampleV21(NULL,&out)&&!fields&&!counterReads,"wrong profile cannot use architectural loads");
 resetCalls();profileOK=true;
 need(VZKernelReadCounterDomainSampleV21(NULL,&out)&&profiles==3&&fields==6,"failed initialization can retry");
 puts("PASS counter22 fresh fields; fixed profile cache; detailed receipts; invalid and partial samples");return 0;
}
