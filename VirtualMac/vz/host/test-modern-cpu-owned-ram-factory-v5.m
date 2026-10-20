#include "modern_cpu_native_public_factory_v5.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <sys/mman.h>
#include <pthread.h>
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
typedef struct {
 unsigned calls[10];unsigned char *cpu;
 VM27CPUFactoryVMV2 *vm;VM27CPUFactoryRAMV5 *ram;
 uint64_t host, bytes, ipa, flags;
 unsigned failOp;bool reentry, threadReentry, changeOwner, changeOwnerOnTrap;
} Mock;
static void Reenter(Mock *m){
 VZKernelRAMResultV9 r;memset(&r,0xa5,sizeof(r));VZKernelRAMResultV9 old=r;
 VM27CPUFactoryRAMV5 *h=(void *)0x1234;void *p=(void *)0x4567;
 CHECK(VM27CPUFactoryRAMCreateV5(m->vm,0x4000,&h,&p,&r)==BUSY);
 CHECK(h==(void *)0x1234 && p==(void *)0x4567 && !memcmp(&r,&old,sizeof(r)));
 CHECK(VM27CPUFactoryRAMUnmapV5(m->ram,&r)==BUSY && !memcmp(&r,&old,sizeof(r)));
 CHECK(VM27CPUFactoryRAMFreeV5(m->ram)==BUSY);
 CHECK(VM27CPUFactoryVMDestroyV2(m->vm,NULL)==BUSY);
 CHECK(VM27CPUFactoryVMFreeV2(m->vm)==BUSY);
 VM27CPUFactoryIDV2 id=77;VM27CPUFactoryExitV2 *exit=(void *)0x789;
 CHECK(VM27CPUFactoryCreateV2(m->vm,&id,&exit,NULL,NULL)==BUSY);
 CHECK(id==77 && exit==(void *)0x789);
}
static uint64_t Thread(void *p){Mock *m=p;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));
 if(m->threadReentry && m->ram)Reenter(m);return m->changeOwner?t+1:t;}
static int32_t Trap(void *p,uint64_t op,void *arg){
 Mock *m=p;CHECK(op==1 || op==2 || op==3 || op==4 || op==5 || op==6 || op==7);++m->calls[op];
 if(op==1){CHECK(arg && ((VZKernelNativeVMConfig *)arg)->nativeHVISA==1);return 0;}
 if(op==2 || op==7){CHECK(!arg);return 0;}
 if(op==6){CHECK(arg && !((uint64_t *)arg)[0] && !((uint64_t *)arg)[1]);
  uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->cpu+0x4000,&magic,8);
  ((uint64_t *)arg)[1]=(uintptr_t)m->cpu;return 0;}
 VZKernelMemoryPacket *q=arg;CHECK(q && sizeof(*q)==40 && q->bytes==m->bytes && !q->spaceWord);
 CHECK(q->guestAddress==m->ipa);
 CHECK(q->hostAddress==(op==3?m->host:0));CHECK(q->flags==(op==4?0:m->flags));
 if(m->reentry)Reenter(m);
 if(m->changeOwnerOnTrap)m->changeOwner=true;
 return m->failOp==op?-17:0;
}
static bool Read(void *p,const void *a,size_t n,void *out){Mock *m=p;CHECK((uintptr_t)a>=(uintptr_t)m->cpu && (uintptr_t)a+n<=(uintptr_t)m->cpu+0x8000);return VM27CPUSelfReadV1(NULL,a,n,out);}
static bool Write(void *p,void *a,size_t n,const void *v){Mock *m=p;CHECK((uintptr_t)a>=(uintptr_t)m->cpu && (uintptr_t)a+n<=(uintptr_t)m->cpu+0x8000);return VM27CPUSelfWriteV1(NULL,a,n,v);}
typedef struct {Mock *m;VM27CPUFactoryRAMV5 *ram;} Foreign;
static void *Other(void *p){Foreign *f=p;VZKernelRAMResultV9 r={0};
 CHECK(VM27CPUFactoryRAMUnmapV5(f->ram,&r)==BAD && r.status==VZ_KERNEL_WRONG_THREAD);
 CHECK(VM27CPUFactoryRAMFreeV5(f->ram)==BAD);CHECK(!r.nativeInvoked && r.cleanupPending);return NULL;}
int main(void){
 puts("MAIN own RAM Factory5; real anonymous backing/self Mach memory, all VM/CPU native callbacks mocked");
 Mock m={0};m.cpu=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(m.cpu!=MAP_FAILED);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};
 VZKernelVMOptions options={36,0,1,false,false};VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27CPUFactoryVMCreateV2(&ops,&options,&writer,&m.vm,NULL));
 VZKernelRAMResultV9 r={0};void *host=NULL;m.bytes=0x4000;m.ipa=0x40000000;m.flags=7;
 CHECK(!VM27CPUFactoryRAMCreateV5(m.vm,m.bytes,&m.ram,&host,&r));m.host=(uintptr_t)host;
 CHECK(m.ram && host && !(m.host&0x3fff) && r.cleanupPending && r.bytes==m.bytes && r.vmEpoch);
 CHECK(!VM27CPUSelfMappedRangeV1((const unsigned char *)host-1,1,false,NULL));
 CHECK(!VM27CPUSelfMappedRangeV1((const unsigned char *)host+m.bytes,1,false,NULL));
 unsigned char code[]={0x00,0x00,0x20,0xd4,0x1f,0x20,0x03,0xd5};
 CHECK(!VM27CPUFactoryRAMWriteV5(m.ram,0x3ff8,code,sizeof(code),&r));CHECK(!memcmp((unsigned char *)host+0x3ff8,code,sizeof(code)));
 CHECK(VM27CPUFactoryRAMWriteV5(m.ram,0x3ffc,code,sizeof(code),&r)==BAD);
 CHECK(VM27CPUFactoryRAMWriteV5(m.ram,0,host,8,&r)==BAD);
 unsigned char before[8];memcpy(before,host,8);VZKernelRAMResultV9 old=r;
 CHECK(VM27CPUFactoryRAMWriteV5(m.ram,0,code,8,(VZKernelRAMResultV9 *)host)==BAD);
 CHECK(!memcmp(before,host,8));
 CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,(VZKernelRAMResultV9 *)m.ram)==BAD);
 CHECK(m.calls[3]==0);
 // Both surrounding guard pages are known own private backing, not accepted
 // as generic caller storage. Never reach memcpy into PROT_NONE memory.
 CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,(VZKernelRAMResultV9 *)((unsigned char *)host-0x100))==BAD);
 CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,(VZKernelRAMResultV9 *)((unsigned char *)host+m.bytes))==BAD);
 CHECK(m.calls[3]==0);
 CHECK(VM27CPUFactoryVMDestroyV2(m.vm,NULL)==BUSY && m.calls[2]==0);
 // Same-thread currentThread/native callbacks cannot destroy backing or VM.
 m.threadReentry=m.reentry=true;CHECK(!VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,&r));m.threadReentry=m.reentry=false;
 CHECK(m.calls[3]==1 && r.mapped && !r.mappingUncertain && r.nativeInvoked && !r.nativeReturn);
 CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,&r)==BUSY && m.calls[3]==1);
 CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BUSY);
 // Reject overlap before native3; a distinct owned allocation is kept.
 VM27CPUFactoryRAMV5 *second=NULL;void *secondHost=NULL;CHECK(!VM27CPUFactoryRAMCreateV5(m.vm,m.bytes,&second,&secondHost,&r));
 CHECK(VM27CPUFactoryRAMMapV5(second,m.ipa,m.flags,&r)==BUSY && m.calls[3]==1);
 CHECK(!VM27CPUFactoryRAMFreeV5(second));CHECK(VM27CPUFactoryRAMFreeV5(second)==BAD);
 m.flags=1;CHECK(!VM27CPUFactoryRAMProtectV5(m.ram,m.flags,&r));CHECK(r.flags==1 && m.calls[5]==1);
 m.flags=3;CHECK(!VM27CPUFactoryRAMProtectV5(m.ram,m.flags,&r));CHECK(r.flags==3 && m.calls[5]==2);
 Foreign f={&m,m.ram};pthread_t t;CHECK(!pthread_create(&t,NULL,Other,&f));CHECK(!pthread_join(t,NULL));CHECK(m.calls[4]==0);
 // Actual own OS CF config + factory CPU/native6 model can coexist with RAM;
 // all mapping mutations and writes/free remain excluded until CPU cleanup.
 VM27CPUFactoryIDV2 id=0;VM27CPUFactoryExitV2 *exit=NULL;CHECK(!VM27CPUFactoryCreateV2(m.vm,&id,&exit,NULL,NULL));CHECK(id && exit);
 CHECK(VM27CPUFactoryRAMUnmapV5(m.ram,&r)==BUSY && r.cleanupPending && m.calls[4]==0);
 CHECK(VM27CPUFactoryRAMProtectV5(m.ram,1,&r)==BUSY && m.calls[5]==2);
 CHECK(VM27CPUFactoryRAMWriteV5(m.ram,0,code,8,&r)==BUSY);CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BUSY);
 CHECK(VM27CPUFactoryVMDestroyV2(m.vm,NULL)==BUSY);
 CHECK(!VM27CPUFactoryOwnerCleanupV2(m.vm,NULL));CHECK(m.calls[6]==1 && m.calls[7]==1);
 m.failOp=5;m.flags=1;CHECK(VM27CPUFactoryRAMProtectV5(m.ram,m.flags,&r)==ERROR);
 CHECK(r.nativeReturn==-17 && r.mappingUncertain && r.cleanupPending && r.mapped);
 CHECK(VM27CPUFactoryRAMProtectV5(m.ram,m.flags,&r)==BUSY);
 m.failOp=4;CHECK(VM27CPUFactoryRAMUnmapV5(m.ram,&r)==ERROR);CHECK(r.mappingUncertain && r.nativeReturn==-17);
 CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BUSY);CHECK(!memcmp((unsigned char *)host+0x3ff8,code,8));
 m.failOp=0;CHECK(!VM27CPUFactoryRAMUnmapV5(m.ram,&r));CHECK(!r.mapped && !r.mappingUncertain && r.cleanupPending);
 // Failed initial native3 never releases or treats the mapping as absent.
 m.failOp=3;m.flags=7;CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,&r)==ERROR);
 CHECK(r.mappingUncertain && !r.mapped && r.nativeReturn==-17 && m.calls[3]==2);
 CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BUSY);
 m.failOp=0;CHECK(!VM27CPUFactoryRAMUnmapV5(m.ram,&r));
 // Native success followed by a changed owner is uncertain, never releasable.
 m.changeOwnerOnTrap=true;CHECK(VM27CPUFactoryRAMMapV5(m.ram,m.ipa,m.flags,&r)==BAD);
 CHECK(r.nativeInvoked && !r.nativeReturn && r.mappingUncertain && !r.mapped && r.cleanupPending);
 m.changeOwner=false;m.changeOwnerOnTrap=false;
 CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BUSY);
 CHECK(!VM27CPUFactoryRAMUnmapV5(m.ram,&r));
 CHECK(!VM27CPUFactoryRAMFreeV5(m.ram));CHECK(VM27CPUFactoryRAMFreeV5(m.ram)==BAD);
 CHECK(!VM27CPUSelfMappedRangeV1(host,m.bytes,false,NULL));
 CHECK(VM27CPUFactoryRAMUnmapV5((void *)1,&r)==BAD);
 CHECK(!VM27CPUFactoryVMDestroyV2(m.vm,NULL));CHECK(!VM27CPUFactoryVMFreeV2(m.vm));CHECK(!munmap(m.cpu,0x8000));
 uint64_t created=0,destroyed=0;VM27CPUConfigTestCountsV3(&created,&destroyed);CHECK(created==1 && destroyed==1);
 CHECK(m.calls[1]==1 && m.calls[2]==1 && !m.calls[8] && !m.calls[9]);(void)old;
 printf("{\"checks\":%u,\"CFcreated\":%llu,\"CFdestroyed\":%llu,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"guestInstructions\":0,\"full27Backend\":false}\n",Checks,(unsigned long long)created,(unsigned long long)destroyed);
}
