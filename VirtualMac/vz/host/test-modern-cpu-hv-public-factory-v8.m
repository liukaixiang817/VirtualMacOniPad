#include "modern_cpu_native_public_factory_v8.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_capability_acquisition_v2.h"
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{++Checks;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);abort();}}while(0)
#define BUSY ((int32_t)UINT32_C(0xfae94002))
#define BAD ((int32_t)UINT32_C(0xfae94003))
#define ERROR ((int32_t)UINT32_C(0xfae94001))
static unsigned Checks;
static uint32_t RunReason=1,RunSyndrome=0x96000004;static int32_t RunReturn;
static bool RunReadFail,RunPostOwnerFail,RunPostVersionFail,After9;
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
static bool FeatureKnown=true,FeatureReenter;static hv_vcpu_config_t FeatureConfig;static unsigned FeatureAcquisitions;
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){(void)o;abort();}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *o){
 ++FeatureAcquisitions;*o=(VM27CPUCapabilitiesV2){0};o->featureSeedKnown=FeatureKnown;
 for(unsigned i=0;i<12;++i)o->featureSeed.featureWords[i]=UINT64_C(0xfedcba9800000000)+i;
 if(FeatureReenter){uint64_t value=55;CHECK(hv_vcpu_config_get_feature_reg(FeatureConfig,(hv_feature_reg_t)0,&value)==BUSY && value==55);}
}
typedef struct {unsigned char *memory;unsigned ops[10],reads,writes;bool reentry,readFail,writeFail,versionFail;hv_vcpu_t id;VM27CPUFactoryVMV2 *vm;}Mock;
static void Reenter(Mock *m){
 uint64_t value=0xa5;CHECK(hv_vcpu_run(m->id)==BUSY);CHECK(hv_vcpu_set_reg(m->id,HV_REG_X0,99)==BUSY);
 CHECK(hv_vcpu_get_reg(m->id,HV_REG_X0,&value)==BUSY && value==0xa5);
 CHECK(hv_vcpu_destroy(m->id)==BUSY);
 hv_vcpu_t id=123;hv_vcpu_exit_t *exit=(void *)0x123;
 CHECK(hv_vcpu_create(&id,&exit,NULL)==BUSY && id==123 && exit==(void *)0x123);
 CHECK(VM27CPUFactoryPublicDrainBorrowV6()==BUSY);
}
static uint64_t Thread(void *p){Mock *m=p;uint64_t id=0;CHECK(!pthread_threadid_np(NULL,&id));if(m->reentry && m->id)Reenter(m);return RunPostOwnerFail && After9?id+1:id;}
static int32_t Trap(void *p,uint64_t op,void *arg){Mock *m=p;CHECK(op==1 || op==2 || op==6 || op==7 || op==8 || op==9);++m->ops[op];
 if(op==1){CHECK(arg && ((VZKernelNativeVMConfig *)arg)->nativeHVISA==1);return 0;}
 if(op==6){CHECK(arg && !((uint64_t *)arg)[0] && !((uint64_t *)arg)[1]);((uint64_t *)arg)[1]=(uintptr_t)m->memory;uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->memory+0x4000,&magic,8);return 0;}
 CHECK(!arg);if(m->reentry && m->id)Reenter(m);
 if(op==9){After9=true;memcpy(m->memory+0x4008,&RunReason,4);memcpy(m->memory+0x400c,&RunSyndrome,4);
  uint64_t va=UINT64_C(0xfeed123456789abc),ipa=UINT64_C(0xabcdef0100008000);memcpy(m->memory+0x4018,&va,8);memcpy(m->memory+0x4020,&ipa,8);
  if(RunPostVersionFail){uint64_t bad=VZ_KERNEL_NATIVE_CONTEXT_VERSION^1;memcpy(m->memory+0x4000,&bad,8);}return RunReturn;}
 return 0;}
static bool Read(void *p,const void *a,size_t n,void *out){Mock *m=p;++m->reads;uintptr_t off=(uintptr_t)a-(uintptr_t)m->memory;CHECK(off<0x8000 && n<=0x8000-off);
 if((m->readFail && off==8) || (RunReadFail && off==0x4008))return false;
 bool result=VM27CPUSelfReadV1(NULL,a,n,out);
 if(m->versionFail && off!=0x4000){uint64_t bad=VZ_KERNEL_NATIVE_CONTEXT_VERSION^(UINT64_C(1)<<32);memcpy(m->memory+0x4000,&bad,8);}
 return result;}
static bool Write(void *p,void *a,size_t n,const void *v){Mock *m=p;++m->writes;bool result=VM27CPUSelfWriteV1(NULL,a,n,v);return result && !m->writeFail;}
typedef struct{Mock *m;}Foreign;
static void *Other(void *p){Foreign *f=p;uint64_t v=55;CHECK(hv_vcpu_run(f->m->id)==BAD);CHECK(hv_vcpu_get_reg(f->m->id,HV_REG_X0,&v)==BAD && v==55);CHECK(hv_vcpu_set_reg(f->m->id,HV_REG_X0,9)==BAD);return NULL;}
static bool ExitValid(Mock *m,hv_vcpu_exit_t *exit){
 VM27CPUFactoryBorrowV2 *b=NULL;VM27CPUFactoryViewV2 v={0};CHECK(!VM27CPUFactoryBorrowAcquireV2(m->id,&b));
 CHECK(!VM27CPUFactoryBorrowViewV2(b,&v));CHECK(v.exitStorage==(VM27CPUFactoryExitV2 *)exit);CHECK(!VM27CPUFactoryBorrowReleaseV2(b));return v.exitRecordValid;
}
static void RunCases(Mock *m,hv_vcpu_exit_t *exit){
 hv_return_t (*caller)(hv_vcpu_t)=hv_vcpu_run;
 CHECK(!ExitValid(m,exit));unsigned native9=m->ops[9];
 CHECK(caller(UINT64_MAX)==BAD && m->ops[9]==native9);
 for(unsigned i=0;i<3;++i){RunReason=(unsigned[]){1,6,8}[i];After9=false;unsigned calls=m->ops[9],writes=m->writes;
  CHECK(!caller(m->id) && m->ops[9]==calls+1 && m->writes==writes);CHECK(ExitValid(m,exit));
  CHECK(exit->reason==1 && exit->exception.syndrome==RunSyndrome && exit->exception.virtual_address==UINT64_C(0xfeed123456789abc) && exit->exception.physical_address==UINT64_C(0xabcdef0100008000));}
 unsigned char saved[32];memcpy(saved,exit,32);
 for(unsigned i=0;i<6;++i){RunReason=(unsigned[]){2,11,0,3,7,99}[i];After9=false;unsigned calls=m->ops[9];
  hv_return_t status=caller(m->id);CHECK(status==(i<2?BUSY:(int32_t)UINT32_C(0xfae9400f)) && m->ops[9]==calls+1);
  CHECK(!memcmp(saved,exit,32) && !ExitValid(m,exit));}
 RunReason=1;
 for(unsigned i=0;i<3;++i){RunSyndrome=(unsigned[]){0x16u<<26,0x18u<<26,0x3fu<<26}[i];After9=false;unsigned calls=m->ops[9];
  CHECK(caller(m->id)==(int32_t)UINT32_C(0xfae9400f) && m->ops[9]==calls+1 && !memcmp(saved,exit,32) && !ExitValid(m,exit));}
 RunSyndrome=0x96000004;RunReturn=-123;After9=false;unsigned calls=m->ops[9];
 CHECK(caller(m->id)==ERROR && m->ops[9]==calls+1 && !memcmp(saved,exit,32) && !ExitValid(m,exit));RunReturn=0;
 RunReadFail=true;After9=false;calls=m->ops[9];CHECK(caller(m->id)==ERROR && m->ops[9]==calls+1 && !memcmp(saved,exit,32));RunReadFail=false;CHECK(!ExitValid(m,exit));
 RunPostOwnerFail=true;After9=false;calls=m->ops[9];CHECK(caller(m->id)==BAD && m->ops[9]==calls+1 && !memcmp(saved,exit,32));RunPostOwnerFail=false;CHECK(!ExitValid(m,exit));
 RunPostVersionFail=true;After9=false;calls=m->ops[9];CHECK(caller(m->id)==ERROR && m->ops[9]==calls+1 && !memcmp(saved,exit,32));RunPostVersionFail=false;
 uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->memory+0x4000,&magic,8);CHECK(!ExitValid(m,exit));
 m->reentry=true;After9=false;calls=m->ops[9];CHECK(!caller(m->id) && m->ops[9]==calls+1);m->reentry=false;CHECK(ExitValid(m,exit));
}
int main(void){
 puts("MAIN actual eleven hv public ABI entries; native lifecycle/SYS only own mocked callbacks");
 _Static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_reg_t)==4 && sizeof(hv_sys_reg_t)==2,"actual Mac27 SDK");
 _Static_assert(sizeof(hv_simd_fp_uchar16_t)==16 && _Alignof(hv_simd_fp_uchar16_t)==16,"actual Q vector");
 hv_return_t (*scalarCaller)(hv_vcpu_t,hv_reg_t,uint64_t)=hv_vcpu_set_reg;
 hv_return_t (*SIMDCaller)(hv_vcpu_t,hv_simd_fp_reg_t,hv_simd_fp_uchar16_t)=hv_vcpu_set_simd_fp_reg;
 hv_return_t (*SYSCaller)(hv_vcpu_t,hv_sys_reg_t,uint64_t)=hv_vcpu_set_sys_reg;
 Mock m={0};m.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelVMOptions options={36,0,1,false,false};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m.vm,NULL));
 hv_vcpu_config_t config=hv_vcpu_config_create();CHECK(config);FeatureConfig=config;
 _Static_assert(sizeof(hv_feature_reg_t)==4,"actual SDK feature ID");
 hv_return_t (*featureCaller)(hv_vcpu_config_t,hv_feature_reg_t,uint64_t *)=hv_vcpu_config_get_feature_reg;
 uint64_t feature=55;
 for(unsigned reg=0;reg<12;++reg){CHECK(!featureCaller(config,(hv_feature_reg_t)reg,&feature));CHECK(feature==UINT64_C(0xfedcba9800000000)+(reg==10?11:reg==11?10:reg));}
 unsigned acquisitions=FeatureAcquisitions;feature=55;
 CHECK(featureCaller(config,(hv_feature_reg_t)12,&feature)==(int32_t)UINT32_C(0xfae9400f) && feature==55 && FeatureAcquisitions==acquisitions);
 CHECK(featureCaller((hv_vcpu_config_t)(void *)0x1,(hv_feature_reg_t)0,&feature)==BAD && feature==55 && FeatureAcquisitions==acquisitions);
 CHECK(featureCaller(config,(hv_feature_reg_t)0,(uint64_t *)(void *)config)==BAD && FeatureAcquisitions==acquisitions);
 FeatureKnown=false;CHECK(featureCaller(config,(hv_feature_reg_t)0,&feature)==(int32_t)UINT32_C(0xfae9400f) && feature==55);FeatureKnown=true;
 FeatureReenter=true;CHECK(!featureCaller(config,(hv_feature_reg_t)0,&feature));FeatureReenter=false;
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());
 hv_vcpu_exit_t *exit=NULL;CHECK(!hv_vcpu_create(&m.id,&exit,config));CHECK(m.id && exit && sizeof(*exit)==32);
 CHECK(!memcmp(exit,(unsigned char[32]){0},32));CFRelease((CFTypeRef)config);
 CHECK(!scalarCaller(m.id,HV_REG_X0,UINT64_C(0x123456789abcdef0)));uint64_t value=0;CHECK(!hv_vcpu_get_reg(m.id,HV_REG_X0,&value));CHECK(value==UINT64_C(0x123456789abcdef0));
 CHECK(!scalarCaller(m.id,HV_REG_FPCR,UINT64_C(0xfeedbeef89abcdef)));CHECK(!hv_vcpu_get_reg(m.id,HV_REG_FPCR,&value));CHECK(value==0x89abcdef);
 CHECK(!scalarCaller(m.id,HV_REG_CPSR,UINT64_C(0xaaaaaaaa800003c5)));CHECK(!hv_vcpu_get_reg(m.id,HV_REG_CPSR,&value));CHECK(value==0x800003c5);
 hv_simd_fp_uchar16_t q={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},back={0};
 CHECK(!SIMDCaller(m.id,HV_SIMD_FP_REG_Q31,q));CHECK(!hv_vcpu_get_simd_fp_reg(m.id,HV_SIMD_FP_REG_Q31,&back));CHECK(!memcmp(&q,&back,16));
 unsigned calls8=m.ops[8];CHECK(!SYSCaller(m.id,(hv_sys_reg_t)0xc080,0x1234));CHECK(m.ops[8]==calls8+1);CHECK(!hv_vcpu_get_sys_reg(m.id,(hv_sys_reg_t)0xc080,&value));CHECK(value==0x1234 && m.ops[8]==calls8+1);
 // Invalid register and alias outputs are rejected without reads or mutation.
 unsigned reads=m.reads,writes=m.writes;value=55;
 CHECK(hv_vcpu_get_reg(m.id,(hv_reg_t)35,&value)==BAD && value==55);
 CHECK(hv_vcpu_set_reg(m.id,(hv_reg_t)35,9)==BAD);
 CHECK(hv_vcpu_get_simd_fp_reg(m.id,(hv_simd_fp_reg_t)32,&back)==BAD);
 CHECK(hv_vcpu_get_reg(m.id,HV_REG_X0,(uint64_t *)exit)==BAD);
 CHECK(hv_vcpu_get_sys_reg(m.id,(hv_sys_reg_t)0xc080,(uint64_t *)exit)==BAD);
 CHECK(m.reads==reads && m.writes==writes);
 hv_vcpu_config_t second=hv_vcpu_config_create();CHECK(second);CHECK(hv_vcpu_get_reg(m.id,HV_REG_X0,(uint64_t *)second)==BAD);CFRelease((CFTypeRef)second);
 CHECK(hv_vcpu_get_reg(UINT64_C(0xffffffffffffffff),HV_REG_X0,&value)==BAD && value==55);
 Foreign f={&m};pthread_t t;CHECK(!pthread_create(&t,NULL,Other,&f));CHECK(!pthread_join(t,NULL));
 m.reentry=true;CHECK(!hv_vcpu_get_reg(m.id,HV_REG_X0,&value));CHECK(!hv_vcpu_set_reg(m.id,HV_REG_X0,77));m.reentry=false;
 m.readFail=true;value=55;CHECK(hv_vcpu_get_reg(m.id,HV_REG_X0,&value)==ERROR && value==55);m.readFail=false;
 m.versionFail=true;CHECK(hv_vcpu_get_reg(m.id,HV_REG_X0,&value)==ERROR && value==55);m.versionFail=false;uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m.memory+0x4000,&magic,8);
 RunCases(&m,exit);
 // Successful actual public destroy and stale public ID rejection. A new
 // sequential own CPU generation is distinct even when native slot stays0.
 hv_vcpu_t oldID=m.id;CHECK(!hv_vcpu_destroy(m.id));
 CHECK(hv_vcpu_get_reg(oldID,HV_REG_X0,&value)==BAD && value==55);
 hv_vcpu_exit_t *newExit=NULL;CHECK(!hv_vcpu_create(&m.id,&newExit,NULL));CHECK(m.id>oldID && newExit);
 // A false writer can already have changed the actual own context. No new ID
 // borrow is published afterward, and real owner destruction still succeeds.
 m.writeFail=true;CHECK(hv_vcpu_set_reg(m.id,HV_REG_X0,88)==ERROR);memcpy(&value,m.memory+8,8);CHECK(value==88);
 value=55;CHECK(hv_vcpu_get_reg(m.id,HV_REG_X0,&value)==BAD && value==55);m.writeFail=false;
 CHECK(!VM27CPUFactoryPublicDrainBorrowV6());CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));
 CHECK(hv_vcpu_destroy(m.id)==BAD);CHECK(!VM27CPUFactoryVMDestroyV2(m.vm,NULL));CHECK(!VM27CPUFactoryVMFreeV2(m.vm));
 CHECK(!munmap(m.memory,0x8000));uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);CHECK(created==3 && destroyed==3);
 CHECK(m.ops[1]==1 && m.ops[2]==1 && m.ops[6]==2 && m.ops[7]==2 && m.ops[9]==17);
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"genuineSDKPublicEntries\":11,\"full27Backend\":false}\n",Checks,(unsigned long long)created,(unsigned long long)destroyed);
}
