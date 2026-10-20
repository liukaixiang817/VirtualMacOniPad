#include "modern_cpu_native_public_factory_v6.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
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
extern void VM27CPUConfigTestCountsV3(uint64_t *,uint64_t *);
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *o){(void)o;abort();}
typedef struct {unsigned char *memory;unsigned ops[10],reads,writes;bool reentry,readFail,writeFail,versionFail;hv_vcpu_t id;VM27CPUFactoryVMV2 *vm;}Mock;
static void Reenter(Mock *m){
 uint64_t value=0xa5;CHECK(hv_vcpu_set_reg(m->id,HV_REG_X0,99)==BUSY);
 CHECK(hv_vcpu_get_reg(m->id,HV_REG_X0,&value)==BUSY && value==0xa5);
 CHECK(hv_vcpu_destroy(m->id)==BUSY);
 hv_vcpu_t id=123;hv_vcpu_exit_t *exit=(void *)0x123;
 CHECK(hv_vcpu_create(&id,&exit,NULL)==BUSY && id==123 && exit==(void *)0x123);
 CHECK(VM27CPUFactoryPublicDrainBorrowV6()==BUSY);
}
static uint64_t Thread(void *p){Mock *m=p;uint64_t id=0;CHECK(!pthread_threadid_np(NULL,&id));if(m->reentry && m->id)Reenter(m);return id;}
static int32_t Trap(void *p,uint64_t op,void *arg){Mock *m=p;CHECK(op==1 || op==2 || op==6 || op==7 || op==8);++m->ops[op];
 if(op==1){CHECK(arg && ((VZKernelNativeVMConfig *)arg)->nativeHVISA==1);return 0;}
 if(op==6){CHECK(arg && !((uint64_t *)arg)[0] && !((uint64_t *)arg)[1]);((uint64_t *)arg)[1]=(uintptr_t)m->memory;uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->memory+0x4000,&magic,8);return 0;}
 CHECK(!arg);if(m->reentry && m->id)Reenter(m);return 0;}
static bool Read(void *p,const void *a,size_t n,void *out){Mock *m=p;++m->reads;uintptr_t off=(uintptr_t)a-(uintptr_t)m->memory;CHECK(off<0x8000 && n<=0x8000-off);
 if(m->readFail && off==8)return false;
 bool result=VM27CPUSelfReadV1(NULL,a,n,out);
 if(m->versionFail && off!=0x4000){uint64_t bad=VZ_KERNEL_NATIVE_CONTEXT_VERSION^(UINT64_C(1)<<32);memcpy(m->memory+0x4000,&bad,8);}
 return result;}
static bool Write(void *p,void *a,size_t n,const void *v){Mock *m=p;++m->writes;bool result=VM27CPUSelfWriteV1(NULL,a,n,v);return result && !m->writeFail;}
typedef struct{Mock *m;}Foreign;
static void *Other(void *p){Foreign *f=p;uint64_t v=55;CHECK(hv_vcpu_get_reg(f->m->id,HV_REG_X0,&v)==BAD && v==55);CHECK(hv_vcpu_set_reg(f->m->id,HV_REG_X0,9)==BAD);return NULL;}
int main(void){
 puts("MAIN actual nine hv public ABI entries; native lifecycle/SYS only own mocked callbacks");
 _Static_assert(sizeof(hv_vcpu_t)==8 && sizeof(hv_reg_t)==4 && sizeof(hv_sys_reg_t)==2,"actual Mac27 SDK");
 _Static_assert(sizeof(hv_simd_fp_uchar16_t)==16 && _Alignof(hv_simd_fp_uchar16_t)==16,"actual Q vector");
 hv_return_t (*scalarCaller)(hv_vcpu_t,hv_reg_t,uint64_t)=hv_vcpu_set_reg;
 hv_return_t (*SIMDCaller)(hv_vcpu_t,hv_simd_fp_reg_t,hv_simd_fp_uchar16_t)=hv_vcpu_set_simd_fp_reg;
 hv_return_t (*SYSCaller)(hv_vcpu_t,hv_sys_reg_t,uint64_t)=hv_vcpu_set_sys_reg;
 Mock m={0};m.memory=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m.memory!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelVMOptions options={36,0,1,false,false};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m.vm,NULL));
 hv_vcpu_config_t config=hv_vcpu_config_create();CHECK(config);
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
 CHECK(m.ops[1]==1 && m.ops[2]==1 && m.ops[6]==2 && m.ops[7]==2 && !m.ops[9]);
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"genuineSDKPublicEntries\":9,\"full27Backend\":false}\n",Checks,(unsigned long long)created,(unsigned long long)destroyed);
}
