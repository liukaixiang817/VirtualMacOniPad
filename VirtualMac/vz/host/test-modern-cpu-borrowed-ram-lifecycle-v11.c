#include "modern_cpu_kernel_lifecycle_v11.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{++Checks;if(!(v)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);abort();}}while(0)
static unsigned Checks;
typedef struct {VZKernelVM *vm;VZKernelRAMV9 *ram;unsigned char *host,*cpu;unsigned calls[10],fail;bool reenter,changeOwner,changeOnTrap;}Mock;
static uint64_t Thread(void *context){Mock *m=context;uint64_t t=0;CHECK(!pthread_threadid_np(NULL,&t));return t+(m->changeOwner?1:0);}
static void Reenter(Mock *m){VZKernelRAMResultV9 r;memset(&r,0xa5,sizeof(r));VZKernelRAMResultV9 before=r;VZKernelRAMV9 *h=(void *)1;
 CHECK(VZKernelRAMAdoptHostRangeV11(m->vm,m->host,0x4000,&h,&r)==VZ_KERNEL_BUSY&&h==(void *)1&&!memcmp(&r,&before,sizeof(r)));
 CHECK(VZKernelRAMFreeV9(m->ram)==VZ_KERNEL_BUSY);VZKernelLifecycleResult life={0};CHECK(VZKernelVMDestroy(m->vm,&life)==VZ_KERNEL_BUSY);}
static int32_t Trap(void *context,uint64_t op,void *arg){Mock *m=context;CHECK(op>=1&&op<=7);++m->calls[op];
 if(op==1){CHECK(arg&&((VZKernelNativeVMConfig *)arg)->nativeHVISA==1);return 0;}
 if(op==2||op==7){CHECK(!arg);return 0;}
 if(op==6){CHECK(arg&&!((uint64_t *)arg)[0]&&!((uint64_t *)arg)[1]);uint64_t magic=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy(m->cpu+0x4000,&magic,8);((uint64_t *)arg)[1]=(uintptr_t)m->cpu;return 0;}
 VZKernelMemoryPacket *p=arg;CHECK(p&&p->bytes==0x4000&&p->guestAddress==0x40000000&&!p->spaceWord);
 CHECK(p->hostAddress==(op==3?(uintptr_t)m->host:0));CHECK(p->flags==(op==4?0:3));
 if(m->reenter)Reenter(m);if(m->changeOnTrap)m->changeOwner=true;return m->fail==op?-17:0;
}
static bool Read(void *context,const void *p,size_t bytes,void *out){Mock *m=context;CHECK((uintptr_t)p>=(uintptr_t)m->cpu&&(uintptr_t)p+bytes<=(uintptr_t)m->cpu+0x8000);return VM27CPUSelfReadV1(NULL,p,bytes,out);}
static void *Foreign(void *context){Mock *m=context;VZKernelRAMResultV9 r={0};CHECK(VZKernelRAMUnmapV9(m->ram,&r)==VZ_KERNEL_WRONG_THREAD);CHECK(VZKernelRAMFreeV9(m->ram)==VZ_KERNEL_WRONG_THREAD);return NULL;}
int main(void){
 puts("MAIN caller-owned RAM adoption; actual Mach self-range checks, every native trap mocked");
 Mock m={0};m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);m.cpu=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.host!=MAP_FAILED&&m.cpu!=MAP_FAILED&&!((uintptr_t)m.host&0x3fff));memset(m.host,0x5a,0x8000);
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,Trap,Thread,Read};VZKernelVMOptions options={36,0,1,false,false};VZKernelLifecycleResult life={0};
 CHECK(!VZKernelVMCreate(&ops,&options,&m.vm,&life));VZKernelRAMResultV9 r={0};VZKernelRAMV9 *ram=(void *)1;
 CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host+1,0x4000,&ram,&r)==VZ_KERNEL_BAD_ARGUMENT&&ram==(void *)1);
 CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host,1,&ram,&r)==VZ_KERNEL_BAD_ARGUMENT&&ram==(void *)1);
 CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host,0x4000,(VZKernelRAMV9 **)m.host,&r)==VZ_KERNEL_BAD_ARGUMENT&&m.host[0]==0x5a);
 CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host,0x4000,&ram,(VZKernelRAMResultV9 *)m.host)==VZ_KERNEL_BAD_ARGUMENT&&m.host[0]==0x5a);
 CHECK(!mprotect(m.host,0x4000,PROT_READ));CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host,0x4000,&ram,&r)==VZ_KERNEL_CONTEXT_UNREADABLE);CHECK(!mprotect(m.host,0x4000,PROT_READ|PROT_WRITE));
 CHECK(!VZKernelRAMAdoptHostRangeV11(m.vm,m.host,0x4000,&m.ram,&r)&&m.ram&&r.cleanupPending&&!r.nativeInvoked);
 CHECK(VZKernelRAMAdoptHostRangeV11(m.vm,m.host,0x4000,&ram,&r)==VZ_KERNEL_BAD_ARGUMENT&&ram==(void *)1);
 CHECK(VZKernelVMDestroy(m.vm,&life)==VZ_KERNEL_BUSY&&m.calls[2]==0);
 m.reenter=true;CHECK(!VZKernelRAMMapV9(m.ram,0x40000000,3,&r));m.reenter=false;CHECK(r.mapped&&!r.mappingUncertain&&m.calls[3]==1);
 CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BUSY);pthread_t t;CHECK(!pthread_create(&t,NULL,Foreign,&m));CHECK(!pthread_join(t,NULL));CHECK(m.calls[4]==0);
 VZKernelCPU *cpu=NULL;CHECK(!VZKernelCPUCreate(m.vm,&cpu,&life)&&cpu);CHECK(VZKernelRAMUnmapV9(m.ram,&r)==VZ_KERNEL_BUSY);CHECK(VZKernelRAMProtectV9(m.ram,3,&r)==VZ_KERNEL_BUSY);
 CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BUSY);CHECK(!VZKernelCPUDestroy(cpu,&life));CHECK(!VZKernelCPUFree(cpu));
 m.fail=5;CHECK(VZKernelRAMProtectV9(m.ram,3,&r)==VZ_KERNEL_NATIVE_ERROR&&r.mappingUncertain&&r.mapped);CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BUSY);
 m.fail=4;CHECK(VZKernelRAMUnmapV9(m.ram,&r)==VZ_KERNEL_NATIVE_ERROR&&r.mappingUncertain);CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BUSY&&m.host[0]==0x5a);
 m.fail=0;CHECK(!VZKernelRAMUnmapV9(m.ram,&r));m.fail=3;CHECK(VZKernelRAMMapV9(m.ram,0x40000000,3,&r)==VZ_KERNEL_NATIVE_ERROR&&r.mappingUncertain&&!r.mapped);
 CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BUSY);m.fail=0;CHECK(!VZKernelRAMUnmapV9(m.ram,&r));
 m.changeOnTrap=true;CHECK(VZKernelRAMMapV9(m.ram,0x40000000,3,&r)==VZ_KERNEL_WRONG_THREAD&&r.mappingUncertain);m.changeOnTrap=m.changeOwner=false;
 CHECK(!VZKernelRAMUnmapV9(m.ram,&r));CHECK(!VZKernelRAMFreeV9(m.ram));CHECK(VZKernelRAMFreeV9(m.ram)==VZ_KERNEL_BAD_ARGUMENT);
 CHECK(VM27CPUSelfMappedRangeV1(m.host,0x8000,true,NULL)&&m.host[0]==0x5a);m.host[0]=0xa5;CHECK(m.host[0]==0xa5);
 CHECK(!VZKernelVMDestroy(m.vm,&life));CHECK(!VZKernelVMFree(m.vm));CHECK(!munmap(m.host,0x8000));CHECK(!munmap(m.cpu,0x8000));
 CHECK(m.calls[1]==1&&m.calls[2]==1&&m.calls[6]==1&&m.calls[7]==1&&!m.calls[8]&&!m.calls[9]);
 printf("{\"checks\":%u,\"callerHostStillMappedAfterHandleFree\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"guestInstructions\":0,\"full27Backend\":false}\n",Checks);
}
