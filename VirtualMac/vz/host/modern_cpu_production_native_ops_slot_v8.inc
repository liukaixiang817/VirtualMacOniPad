#include "modern_cpu_production_native_ops_v1.h"
#include "vm27_hv_public_vm_bootstrap_v12.h"
#include "modern_cpu_kernel_initialization_private.h"
#include "modern_cpu_kernel_system_private.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_vm_memory_packet.h"
#include <mach/mach.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

extern int32_t VM27ProductionNativeTrapV1(uint64_t,void *);
#define NATIVE_USER_BYTES_V1 ((size_t)0x8000)
#define PRODUCTION_BAD_V1 ((int32_t)UINT32_C(0xfae94003))
#define PRODUCTION_BUSY_V1 ((int32_t)UINT32_C(0xfae94002))
typedef struct ProductionCPUV1 {
 struct ProductionCPUV1 *next;
 pthread_t pthread;
 uint64_t thread,slot;
 uintptr_t nativeContext;
 unsigned wakePins;
 bool live,usable,destroying,writeFailed;
} ProductionCPUV1;
typedef struct ProductionMapV1 {
 struct ProductionMapV1 *next;
 VZKernelMemoryPacket packet;
 bool mapped,uncertain,target;
} ProductionMapV1;
static pthread_mutex_t ProductionMutexV1=PTHREAD_MUTEX_INITIALIZER;
static struct {
 pthread_t ownerPthread;
 uint64_t ownerThread;
 pid_t taskPID;
 ProductionCPUV1 *cpus;
 ProductionMapV1 *maps,*pendingMaps;
 bool installed,vmLive,vmMutation;
} ProductionV1;

static void LockProductionV1(void){if(pthread_mutex_lock(&ProductionMutexV1))abort();}
static void UnlockProductionV1(void){if(pthread_mutex_unlock(&ProductionMutexV1))abort();}
static uint64_t ProductionThreadV1(void *unused) {
 (void)unused;uint64_t id=0;return pthread_threadid_np(NULL,&id)?0:id;
}
static bool DisjointProductionV1(const void *a,size_t n,const void *b,size_t m) {
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 return x && y && n && m && n<=UINTPTR_MAX-x && m<=UINTPTR_MAX-y && (x+n<=y || y+m<=x);
}
// Called with this provider's mutex; it never calls into Factory/Root locks.
static bool OutsideOwnerStorageProductionV1(const void *p,size_t n) {
 if(!p || !n || n>UINTPTR_MAX-(uintptr_t)p ||
  !DisjointProductionV1(p,n,&ProductionV1,sizeof(ProductionV1)) ||
  !DisjointProductionV1(p,n,&ProductionMutexV1,sizeof(ProductionMutexV1)))return false;
 for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next)
  if(!DisjointProductionV1(p,n,c,sizeof(*c)) || (c->nativeContext &&
   !DisjointProductionV1(p,n,(void *)c->nativeContext,NATIVE_USER_BYTES_V1)))return false;
 for(ProductionMapV1 *m=ProductionV1.maps;m;m=m->next)
  if(!DisjointProductionV1(p,n,m,sizeof(*m)))return false;
 for(ProductionMapV1 *m=ProductionV1.pendingMaps;m;m=m->next)
  if(!DisjointProductionV1(p,n,m,sizeof(*m)))return false;
 return true;
}
static bool ExternalRangeProductionV1(const void *p,size_t n) {
 if(!OutsideOwnerStorageProductionV1(p,n))return false;
 for(ProductionMapV1 *m=ProductionV1.maps;m;m=m->next)
  if(!DisjointProductionV1(p,n,(void *)(uintptr_t)m->packet.hostAddress,(size_t)m->packet.bytes))return false;
 return true;
}
static bool CopyProductionV1(const void *from,size_t n,void *to) {
 vm_size_t copied=0;
 return vm_read_overwrite(mach_task_self(),(vm_address_t)from,n,(vm_address_t)to,&copied)==KERN_SUCCESS && copied==n;
}
static ProductionCPUV1 *CurrentCPUProductionV1(uint64_t thread) {
 for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next)
  if(c->thread==thread && pthread_equal(c->pthread,pthread_self()))return c;
 return NULL;
}
static ProductionCPUV1 *RangeCPUProductionV1(const void *p,size_t n,uint64_t thread) {
 uintptr_t a=(uintptr_t)p;
 if(!n || n>16)return NULL;
 for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next) {
  if(!c->live || !c->usable || c->destroying || a<c->nativeContext ||
   a-c->nativeContext>=NATIVE_USER_BYTES_V1 || n>NATIVE_USER_BYTES_V1-(a-c->nativeContext))continue;
  // Wake17 reads only the real version word under its retained CPU lease.
  // Every other native-context access remains on its actual CPU pthread.
  bool own=c->thread==thread && pthread_equal(c->pthread,pthread_self());
  if(own || (a-c->nativeContext==0x4000 && n==8))return c;
 }
 return NULL;
}
static bool ProductionReadV1(void *opaque,const void *address,size_t bytes,void *out) {
 if(opaque!=&ProductionV1 || !ProductionThreadV1(NULL))return false;
 LockProductionV1();
 ProductionCPUV1 *cpu=RangeCPUProductionV1(address,bytes,ProductionThreadV1(NULL));
 bool ok=ProductionV1.installed && cpu && ExternalRangeProductionV1(out,bytes) &&
  VM27CPUSelfMappedRangeV1(address,bytes,false,NULL) &&
  VM27CPUSelfMappedRangeV1(out,bytes,true,NULL) && CopyProductionV1(address,bytes,out);
 UnlockProductionV1();return ok;
}
static bool WritableProductionV1(uint32_t off,size_t bytes) {
 return VZKernelInitOffsetWritable(off,bytes) || VZKernelSysNativeFieldAllowed(off,bytes) ||
  (bytes==8 && (off==0x3f8 || off==0x3f0 || off==0x438 || off==0x6d8)) ||
  (bytes==1 && off==0x668);
}
static bool ProductionWriteV1(void *opaque,void *address,size_t bytes,const void *value) {
 if(opaque!=&ProductionV1 || !bytes || bytes>16)return false;
 uint64_t thread=ProductionThreadV1(NULL);if(!thread)return false;
 LockProductionV1();ProductionCPUV1 *cpu=CurrentCPUProductionV1(thread);
 uintptr_t a=(uintptr_t)address;bool inRange=cpu && cpu->live && cpu->usable && !cpu->destroying &&
  !cpu->writeFailed && a>=cpu->nativeContext && a-cpu->nativeContext<NATIVE_USER_BYTES_V1 &&
  bytes<=NATIVE_USER_BYTES_V1-(a-cpu->nativeContext);
 bool ok=ProductionV1.installed && inRange && WritableProductionV1((uint32_t)(a-cpu->nativeContext),bytes) &&
  ExternalRangeProductionV1(value,bytes) && VM27CPUSelfMappedRangeV1(value,bytes,false,NULL) &&
  VM27CPUSelfMappedRangeV1(address,bytes,true,NULL);
 unsigned char staged[16],readback[16];uint64_t version=0;
 if(ok)ok=CopyProductionV1((void *)(cpu->nativeContext+0x4000),8,&version) &&
  version==VZ_KERNEL_NATIVE_CONTEXT_VERSION && CopyProductionV1(value,bytes,staged);
 if(ok) {
  kern_return_t result=vm_write(mach_task_self(),(vm_address_t)address,(vm_offset_t)staged,(mach_msg_type_number_t)bytes);
  ok=result==KERN_SUCCESS && CopyProductionV1(address,bytes,readback) && !memcmp(staged,readback,bytes);
  if(!ok)cpu->writeFailed=true; // Preserve true ownership, permit only cleanup.
 }
 UnlockProductionV1();return ok;
}
static bool OwnerProductionV1(uint64_t thread) {
 return ProductionV1.installed && thread==ProductionV1.ownerThread &&
  pthread_equal(ProductionV1.ownerPthread,pthread_self());
}
static int32_t NativeWakeProductionV1(uint64_t mask) {
 if(!mask || !ProductionThreadV1(NULL))return PRODUCTION_BAD_V1;
 ProductionCPUV1 *pinned[64];size_t count=0;uint64_t known=0;
 LockProductionV1();
 if(!ProductionV1.installed || !ProductionV1.vmLive){UnlockProductionV1();return PRODUCTION_BAD_V1;}
 for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next)if(c->live && c->usable && !c->destroying && c->slot<64 && (mask&(UINT64_C(1)<<c->slot))) {
  if(count==64 || c->wakePins==UINT_MAX){UnlockProductionV1();return PRODUCTION_BUSY_V1;}
  uint64_t version=0;
  if(!CopyProductionV1((void *)(c->nativeContext+0x4000),8,&version) || version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  pinned[count++]=c;known|=UINT64_C(1)<<c->slot;
 }
 if(known!=mask){UnlockProductionV1();return PRODUCTION_BAD_V1;}
 for(size_t i=0;i<count;++i)++pinned[i]->wakePins;
 UnlockProductionV1();
 int32_t result=VM27ProductionNativeTrapV1(10,(void *)(uintptr_t)mask);
 LockProductionV1();for(size_t i=0;i<count;++i)--pinned[i]->wakePins;UnlockProductionV1();return result;
}
#include "modern_cpu_production_ram_range_v8.inc"
static int32_t ProductionNativeV1(void *opaque,uint64_t op,void *arguments) {
 if(opaque!=&ProductionV1)return PRODUCTION_BAD_V1;
 if(op==10)return NativeWakeProductionV1((uintptr_t)arguments);
 uint64_t thread=ProductionThreadV1(NULL);if(!thread || op<1 || op>9)return PRODUCTION_BAD_V1;
 LockProductionV1();ProductionCPUV1 *cpu=CurrentCPUProductionV1(thread);
 if(!ProductionV1.installed){UnlockProductionV1();return PRODUCTION_BAD_V1;}
 if(op==8 || op==9 || op==7) {
  if(arguments || !ProductionV1.vmLive || !cpu || !cpu->live || cpu->destroying ||
   (op!=7 && (!cpu->usable || cpu->writeFailed))){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  if(op==7 && cpu->wakePins){UnlockProductionV1();return PRODUCTION_BUSY_V1;}
  if(op!=7) {
   uint64_t version=0;
   if(!CopyProductionV1((void *)(cpu->nativeContext+0x4000),8,&version) || version!=VZ_KERNEL_NATIVE_CONTEXT_VERSION){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  }
  if(op==7)cpu->destroying=true;
  UnlockProductionV1();
  // Do not hold this mutex across Run: the scheduler must be able to wake it.
  int32_t result=VM27ProductionNativeTrapV1(op,NULL);
  if(op==7) {
   LockProductionV1();
   if(!result){ProductionCPUV1 **link=&ProductionV1.cpus;while(*link!=cpu)link=&(*link)->next;*link=cpu->next;}
   else cpu->destroying=false;
   UnlockProductionV1();if(!result)free(cpu);
  }
  return result;
 }
 if(op==6) {
  uint64_t packet[2]={UINT64_MAX,UINT64_MAX};
  bool valid=ProductionV1.vmLive && !ProductionV1.vmMutation && !cpu &&
   ExternalRangeProductionV1(arguments,sizeof(packet)) && VM27CPUSelfMappedRangeV1(arguments,sizeof(packet),true,NULL) &&
   CopyProductionV1(arguments,sizeof(packet),packet) && packet[0]<64 && !packet[1];
  for(ProductionMapV1 *m=ProductionV1.maps;m;m=m->next)if(!m->mapped || m->uncertain)valid=false;
  size_t cpuCount=0;for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next){++cpuCount;if(c->slot==packet[0])valid=false;}
  if(cpuCount>=64)valid=false;
  if(!valid){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  cpu=calloc(1,sizeof(*cpu));if(!cpu){UnlockProductionV1();return PRODUCTION_BUSY_V1;}
  cpu->pthread=pthread_self();cpu->thread=thread;cpu->slot=packet[0];cpu->next=ProductionV1.cpus;ProductionV1.cpus=cpu;
  UnlockProductionV1();int32_t result=VM27ProductionNativeTrapV1(6,arguments);
  LockProductionV1();
  if(!result) {
   // Native success creates ownership even if subsequent geometry/read fails.
   cpu->live=true;bool read=CopyProductionV1(arguments,sizeof(packet),packet);
   bool external=read && ExternalRangeProductionV1((void *)(uintptr_t)packet[1],NATIVE_USER_BYTES_V1);
   if(read){cpu->slot=packet[0];cpu->nativeContext=(uintptr_t)packet[1];}
   cpu->usable=read && external && cpu->slot<64 && cpu->nativeContext && !(cpu->nativeContext&0x3fff) &&
    cpu->nativeContext<=UINTPTR_MAX-NATIVE_USER_BYTES_V1 && VM27CPUSelfMappedRangeV1((void *)cpu->nativeContext,NATIVE_USER_BYTES_V1,false,NULL);
   for(ProductionCPUV1 *c=ProductionV1.cpus;c;c=c->next)if(c!=cpu && c->live &&
    (c->slot==cpu->slot || (c->nativeContext && cpu->nativeContext &&
     !DisjointProductionV1((void *)c->nativeContext,NATIVE_USER_BYTES_V1,(void *)cpu->nativeContext,NATIVE_USER_BYTES_V1)))){cpu->usable=false;c->usable=false;}
  }else{ProductionCPUV1 **link=&ProductionV1.cpus;while(*link!=cpu)link=&(*link)->next;*link=cpu->next;}
  UnlockProductionV1();if(result)free(cpu);return result;
 }
 // The current kernel resolves native3/4/5 through this task's real VM.
 // VM lifecycle still requires the exact creator; CPU operations above keep
 // their own real CPU pthread/TLS. Every memory call stays serialized here.
 bool memory=op==3 || op==4 || op==5;
 bool taskMemory=memory && ProductionV1.taskPID>0 && ProductionV1.taskPID==getpid();
 if((memory?!taskMemory:!OwnerProductionV1(thread)) || ProductionV1.vmMutation){UnlockProductionV1();return PRODUCTION_BAD_V1;}
 if(op==1) {
  VZKernelNativeVMConfig q;
  bool valid=!ProductionV1.vmLive && !ProductionV1.cpus && !ProductionV1.maps &&
   ExternalRangeProductionV1(arguments,sizeof(q)) && CopyProductionV1(arguments,sizeof(q),&q) &&
   !q.reserved && q.ipaLimit==(UINT64_C(1)<<36) && !q.ipaGranule && !q.reserved20 &&
   (q.nativeHVISA==1 || q.nativeHVISA==2) && !q.reserved28;
  if(!valid){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  ProductionV1.vmMutation=true;UnlockProductionV1();int32_t result=VM27ProductionNativeTrapV1(1,&q);
  LockProductionV1();if(!result)ProductionV1.vmLive=true;ProductionV1.vmMutation=false;UnlockProductionV1();return result;
 }
 if(op==2) {
  if(arguments || !ProductionV1.vmLive || ProductionV1.cpus || ProductionV1.maps){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  ProductionV1.vmMutation=true;UnlockProductionV1();int32_t result=VM27ProductionNativeTrapV1(2,NULL);
  LockProductionV1();if(!result)ProductionV1.vmLive=false;ProductionV1.vmMutation=false;UnlockProductionV1();return result;
 }
 if(op==3 || op==4 || op==5) {
  VZKernelMemoryPacket q,encoded;
  bool valid=ProductionV1.vmLive && ExternalRangeProductionV1(arguments,sizeof(q)) &&
   CopyProductionV1(arguments,sizeof(q),&q) && VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,
    (VZKernelMemoryOperation)op,(uintptr_t)q.hostAddress,q.guestAddress,q.bytes,q.flags,q.spaceWord,&encoded)==VZ_KERNEL_OK && !memcmp(&q,&encoded,sizeof(q));
  if(!valid){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  if(op!=3)return NativeRangeProductionV8(op,&q); // consumes this mutex.
  for(ProductionMapV1 *m=ProductionV1.maps;m;m=m->next)
   if(q.guestAddress<m->packet.guestAddress+m->packet.bytes && m->packet.guestAddress<q.guestAddress+q.bytes)valid=false;
  valid=valid && q.bytes<=SIZE_MAX && OutsideOwnerStorageProductionV1((void *)(uintptr_t)q.hostAddress,(size_t)q.bytes) &&
   VM27CPUSelfMappedRangeV1((void *)(uintptr_t)q.hostAddress,(size_t)q.bytes,(q.flags&UINT64_C(2))!=0,NULL);
  if(!valid){UnlockProductionV1();return PRODUCTION_BAD_V1;}
  ProductionMapV1 *map=calloc(1,sizeof(*map));if(!map){UnlockProductionV1();return PRODUCTION_BUSY_V1;}
  map->packet=q;map->uncertain=true;map->next=ProductionV1.maps;ProductionV1.maps=map;
  ProductionV1.vmMutation=true;UnlockProductionV1();int32_t result=VM27ProductionNativeTrapV1(op,&q);
  LockProductionV1();map->mapped=result==0;map->uncertain=result!=0;
  ProductionV1.vmMutation=false;UnlockProductionV1();return result;
 }
 UnlockProductionV1();return PRODUCTION_BAD_V1;
}
static bool ProfileProductionV1(const char *name,const char *expected) {
 char value[128]={0};size_t n=sizeof(value);
 return !sysctlbyname(name,value,&n,NULL,0) && n && n<=sizeof(value) && !value[n-1] && !strcmp(value,expected);
}
hv_return_t VM27InstallProductionNativeOpsV1(void) {
 uint64_t thread=ProductionThreadV1(NULL);if(!thread)return (hv_return_t)PRODUCTION_BAD_V1;
 LockProductionV1();
 if(ProductionV1.installed){bool own=OwnerProductionV1(thread);UnlockProductionV1();return own?0:(hv_return_t)PRODUCTION_BAD_V1;}
 struct rlimit cpu={0};
 bool profile=getpagesize()==0x4000 && ProfileProductionV1("hw.machine","iPad14,6") &&
  ProfileProductionV1("kern.osrelease","22.1.0") && ProfileProductionV1("kern.osversion","20B101") &&
  !getrlimit(RLIMIT_CPU,&cpu) && cpu.rlim_cur==RLIM_INFINITY && cpu.rlim_max==RLIM_INFINITY;
 if(!profile){UnlockProductionV1();return (hv_return_t)PRODUCTION_BAD_V1;}
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&ProductionV1,ProductionNativeV1,ProductionThreadV1,ProductionReadV1};
 VZKernelInitWriter writer={&ProductionV1,ProductionWriteV1};
 hv_return_t result=VM27HVVMInstallNativeOpsV1(&ops,&writer);
 if(!result){ProductionV1.ownerPthread=pthread_self();ProductionV1.ownerThread=thread;ProductionV1.taskPID=getpid();ProductionV1.installed=true;}
 UnlockProductionV1();return result;
}
hv_return_t VM27UninstallProductionNativeOpsV1(void) {
 uint64_t thread=ProductionThreadV1(NULL);LockProductionV1();
 if(!OwnerProductionV1(thread) || ProductionV1.vmLive || ProductionV1.cpus || ProductionV1.maps || ProductionV1.vmMutation){UnlockProductionV1();return (hv_return_t)PRODUCTION_BUSY_V1;}
 hv_return_t result=VM27HVVMUninstallNativeOpsV1();
 if(!result)memset(&ProductionV1,0,sizeof(ProductionV1));UnlockProductionV1();return result;
}
