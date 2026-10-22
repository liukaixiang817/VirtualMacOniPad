#if defined(VM27_BENCH_UNFAIR_V11)
#include "modern_gic_v3_engine_v11_unfair.c"
#else
#include "modern_gic_v3_engine_v10_owner_validation.c"
#endif
#include <mach/mach_time.h>
#include <stdio.h>
#include <errno.h>
static void Need(bool v){if(!v)abort();}
typedef struct {VM27GICV3V1 *g;uint64_t rounds;unsigned id;} Worker;
static VZKernelStatus Retain(void *p,const VZKernelRunPendingRequestV14 *q,void **out){(void)p;*out=(void *)(uintptr_t)q->expectedPublicIdentity;return VZ_KERNEL_OK;}
static VZKernelStatus Release(void *p,void *token){(void)p;return token?VZ_KERNEL_OK:VZ_KERNEL_BAD_ARGUMENT;}
static VZKernelStatus Wake(void *p,const VZKernelRunPendingRequestV14 *q){(void)p;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Quiet(void *p,const VZKernelRunPendingRequestV14 *q){(void)p;(void)q;return VZ_KERNEL_OK;}
static VZKernelStatus Schedule(void *p,const VZKernelRunPendingRequestV14 *q,bool arm,uint64_t deadline){(void)p;return q->expectedPublicIdentity>=100&&q->expectedPublicIdentity<104&&arm==(bool)(deadline&1)?VZ_KERNEL_OK:VZ_KERNEL_BAD_ARGUMENT;}
static VZKernelStatus Boundary(void *p){return p?VZ_KERNEL_OK:VZ_KERNEL_BAD_ARGUMENT;}
static void *Run(void *p){
 Worker *w=p;uint64_t tid=0;Need(pthread_threadid_np(NULL,&tid)==0);
 VZKernelRunPendingRequestV14 q={.schemaVersion=1,.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1,.nativeHVISA=2,.expectedVMEpoch=817,.expectedPublicIdentity=100+w->id,.expectedOwnerThread=tid,.expectedCPUGeneration=300+w->id};
 Need(VM27GICAttachCPUV1(w->g,&q,w->id)==VZ_KERNEL_OK);
 LockGIC(w->g);int slot=FindCPU(w->g,&q,false);Need(slot>=0);GICCPU *c=&w->g->cpus[slot];w->g->groupEnabled[1]=true;c->groupEnabled[1]=true;c->pmr=255;c->privateIRQ[30].group1=true;c->privateIRQ[30].edge=false;SetEnabledV7(w->g,(uint32_t)slot,30,true);UnlockGIC(w->g);
 for(uint64_t n=0;n<w->rounds;++n){
  Need(VM27GICValidateTimerOwnerV1(w->g,&q)==VZ_KERNEL_OK);
  VM27GICPhysicalBatchResultV9 r={0};bool asserted=n&1;
  Need(VM27GICRouteAndDeadlineV9(w->g,&q,asserted,n&1,n,Boundary,w,&r)==VZ_KERNEL_OK);
  Need(r.routeComplete&&r.deadlineAttempted&&r.irq==asserted);
 }
 Need(VM27GICDetachCPUV1(w->g,&q)==VZ_KERNEL_OK);return NULL;
}
int main(int argc,char **argv){
 uint64_t rounds=200000;if(argc==2){char *end=NULL;errno=0;rounds=strtoull(argv[1],&end,10);Need(!errno&&end&&!*end&&rounds>=1000&&rounds<=2000000);}else Need(argc==1);
 VM27GICV3V1 *g=NULL;VM27GICConfigV1 cfg={.schemaVersion=1,.maxCPUs=4,.ipaBits=36,.vmEpoch=817,.distributorBase=0x100000,.redistributorBase=0x200000};VM27GICBindingsV1 b={NULL,Retain,Release,Wake,Schedule,Quiet};Need(VM27GICCreateV1(&cfg,&b,&g)==VZ_KERNEL_OK);
 mach_timebase_info_data_t tb={0};Need(mach_timebase_info(&tb)==KERN_SUCCESS);uint64_t begin=mach_absolute_time();Worker w[4];pthread_t th[4];
 for(unsigned i=0;i<4;++i){w[i]=(Worker){g,rounds,i};Need(!pthread_create(&th[i],NULL,Run,&w[i]));}
 for(unsigned i=0;i<4;++i)Need(!pthread_join(th[i],NULL));
 double seconds=(double)(mach_absolute_time()-begin)*tb.numer/tb.denom/1e9;
 Need(!g->callbacks);Need(VM27GICDestroyV1(g)==VZ_KERNEL_OK);
 printf("{\"actualHostGICOperations\":%llu,\"owners\":4,\"elapsedSeconds\":%.6f,\"everyIRQAndDeadlineResultValidated\":true,\"guestPerformanceClaimed\":false}\n",(unsigned long long)(rounds*4),seconds);return 0;
}
