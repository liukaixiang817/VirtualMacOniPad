/* Canonical engine differential on real owner pthread/mapping admission.
 * Native HV creation/entry is not substituted with a successful stub. */
#include "modern_cpu_production_native_ops_v20_control0.c"
#include <stdio.h>
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);abort();}}while(0)
int32_t VM27ProductionNativeTrapV1(uint64_t op,void *p){(void)op;(void)p;abort();}
static bool ReferenceRead(void *p,uint32_t off,size_t n,void *out){memcpy(out,(char *)p+off,n);return true;}
static bool ReferenceWrite(void *p,uint32_t off,size_t n,const void *value){memcpy((char *)p+off,value,n);return true;}
static void *Foreign(void *p){VM27Control0ResultV20 r=VM27ProductionControl0V20((uintptr_t)p,2,7);CHECK(!r.handled);return NULL;}
int main(void){
 void *memory=NULL;CHECK(!posix_memalign(&memory,0x4000,0x8000));uintptr_t ctx=(uintptr_t)memory;
 ProductionCPUV1 cpu={.pthread=pthread_self(),.nativeContext=ctx,.live=true,.usable=true,.contextReadablePages=3,.contextWritablePages=3};
 CHECK(!pthread_threadid_np(NULL,&cpu.thread));ProductionV1.installed=ProductionV1.vmLive=true;ProductionV1.cpus=&cpu;
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t bytes=pthread_get_stacksize_np(pthread_self());
 CHECK(VM27CPUOwnedMappingPublishV1(0,(uintptr_t)&cpu,cpu.thread,ctx,3,3,top-bytes,bytes,true));
 for(unsigned isa=1;isa<=2;++isa)for(unsigned trial=0;trial<256;++trial){
  for(unsigned i=0;i<0x8000;++i)((unsigned char *)memory)[i]=(unsigned char)(i*17+trial);
  uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy((char *)memory+0x4000,&version,8);
  unsigned char expected[0x8000];memcpy(expected,memory,sizeof(expected));
  uint64_t value=trial==255?UINT64_MAX:UINT64_C(0x8532f73adebc17)*trial;
  VZKernelInitRequest q={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,cpu.thread,0,cpu.slot,isa,VZ_KERNEL_INIT_CONTROL,0,value,0};
  VZKernelInitAccess access={expected,ReferenceRead,ReferenceWrite};VZKernelInitReceipt receipt={0};
  receipt.failedNativeOffset=receipt.failedWriteOrdinal=UINT32_MAX;
  CHECK(VZKernelInitApplyVerifiedSlice(&q,&access,&receipt)==VZ_KERNEL_OK);
  /* Completing while this lock is held proves the new path cannot silently
   * fall back to the former shared writer. */
  LockProductionV1();VM27Control0ResultV20 r=VM27ProductionControl0V20(ctx,isa,value);UnlockProductionV1();
  CHECK(r.handled && !r.receipt.status);CHECK(!memcmp(expected,memory,sizeof(expected)));
  CHECK(!memcmp(&receipt,&r.receipt,sizeof(receipt)));
  CHECK(r.receipt.attemptedReads==3 && r.receipt.attemptedWrites==4 && r.receipt.completedWrites==4);
 }
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,Foreign,memory));CHECK(!pthread_join(foreign,NULL));
 for(unsigned kind=0;kind<7;++kind){
  uint64_t version=VZ_KERNEL_NATIVE_CONTEXT_VERSION;memcpy((char *)memory+0x4000,&version,8);
  if(kind==0)cpu.live=false;if(kind==1)cpu.usable=false;if(kind==2)cpu.destroying=true;
  if(kind==3)cpu.writeFailed=true;if(kind==4)cpu.contextWritablePages=0;
  if(kind==5)cpu.contextReadablePages=0;if(kind==6){version=0;memcpy((char *)memory+0x4000,&version,8);}
  unsigned char before[0x8000];memcpy(before,memory,sizeof(before));
  VM27Control0ResultV20 r=VM27ProductionControl0V20(ctx,2,7);CHECK(!r.handled);CHECK(!memcmp(before,memory,sizeof(before)));
  cpu.live=cpu.usable=true;cpu.destroying=cpu.writeFailed=false;cpu.contextReadablePages=cpu.contextWritablePages=3;
 }
 CHECK(!VM27ProductionControl0V20(ctx,0,7).handled);CHECK(!VM27ProductionControl0V20(ctx+8,2,7).handled);
 VM27CPUOwnedMappingWithdrawV1(0,(uintptr_t)&cpu,NULL);CHECK(!VM27ProductionControl0V20(ctx,2,7).handled);
 ProductionV1.cpus=NULL;ProductionV1.installed=ProductionV1.vmLive=false;free(memory);
 printf("canonical control0 all-byte and full-receipt differential, alias/order, actual owner, foreign, permissions, poison, withdrawal and mutex independence: %u checks PASS; native execution not claimed\n",checks);
}
