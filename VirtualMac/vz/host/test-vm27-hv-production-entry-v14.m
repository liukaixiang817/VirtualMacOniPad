// Mac-only finite admission/query tests. No real SVC or device operations.
#include "vm27_hv_public_vm_bootstrap_v14.h"
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern VZKernelStatus ControlActualReleaseV18(VZKernelCPUBorrowV5 *);
VZKernelStatus VZKernelCPUReleaseBorrowV5(VZKernelCPUBorrowV5 *b){return ControlActualReleaseV18(b);}
static _Atomic unsigned Checks,InstallerCalls,RawQueries,NativeVMCreate,NativeVMDestroy;
#define NEED(x) do {atomic_fetch_add(&Checks,1);if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();}}while(0)
static unsigned char *Image;
static char Path[1024]="/var/root/VirtualMac/payload/VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static uintptr_t ReturnPC;
static int PathError;
static VM27CPURawIPAPairV2 Pair={true,40,42};
const struct mach_header *VM27HVVMEntryTestImageV14(void){return (const void *)Image;}
int VM27HVVMEntryTestPathV14(char *out,uint32_t *n){if(PathError)return PathError;size_t z=strlen(Path)+1;if(*n<z)return -1;memcpy(out,Path,z);*n=(uint32_t)z;return 0;}
uintptr_t VM27HVVMEntryTestReturnV14(void){return ReturnPC;}
void VM27CPUConfigAcquireRawIPAPairV2(VM27CPURawIPAPairV2 *out){atomic_fetch_add(&RawQueries,1);*out=Pair;}
void VM27CPUConfigAcquireCapabilitiesV2(VM27CPUCapabilitiesV2 *out){*out=(VM27CPUCapabilitiesV2){0};}
void VM27CPUConfigAcquireTLBICapabilityV1(VM27CPUTLBICapabilityValueV1 *out){*out=(VM27CPUTLBICapabilityValueV1){0};}
static pthread_mutex_t InstallerMutex=PTHREAD_MUTEX_INITIALIZER;
static bool Installed;
static pthread_t Owner;
static uint64_t OwnerID;
static uint64_t CurrentThread(void *p){(void)p;uint64_t t=0;return pthread_threadid_np(NULL,&t)?0:t;}
static int32_t Trap(void *p,uint64_t op,void *args){(void)p;if(op==1){VZKernelNativeVMConfig *c=args;NEED(c && c->ipaLimit==(UINT64_C(1)<<36) && c->nativeHVISA==2);atomic_fetch_add(&NativeVMCreate,1);return 0;}if(op==2){NEED(!args);atomic_fetch_add(&NativeVMDestroy,1);return 0;}abort();}
static bool Read(void *p,const void *a,size_t n,void *out){(void)p;(void)a;(void)n;(void)out;abort();}
static bool Write(void *p,void *a,size_t n,const void *v){(void)p;(void)a;(void)n;(void)v;abort();}
hv_return_t VM27HVVMEntryTestInstallV14(void) {
 atomic_fetch_add(&InstallerCalls,1);NEED(!pthread_mutex_lock(&InstallerMutex));
 hv_return_t result=0;
 if(Installed)result=pthread_equal(Owner,pthread_self()) && OwnerID==CurrentThread(NULL)?0:(hv_return_t)UINT32_C(0xfae94003);
 else {
  VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,NULL,Trap,CurrentThread,Read};VZKernelInitWriter writer={NULL,Write};
  result=VM27HVVMInstallNativeOpsV1(&ops,&writer);
  if(!result){Installed=true;Owner=pthread_self();OwnerID=CurrentThread(NULL);}
 }
 NEED(!pthread_mutex_unlock(&InstallerMutex));return result;
}
static void InitializeImage(void) {
 Image=mmap(NULL,0x300000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);NEED(Image!=MAP_FAILED);
 struct mach_header_64 h={MH_MAGIC_64,CPU_TYPE_ARM64,2,MH_EXECUTE,1,sizeof(struct uuid_command),0,0};memcpy(Image,&h,sizeof(h));
 struct uuid_command u={LC_UUID,sizeof(u),{0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b}};memcpy(Image+sizeof(h),&u,sizeof(u));
 uint32_t bl=0x9404a45a;memcpy(Image+0x2e9d4c,&bl,4);ReturnPC=(uintptr_t)Image+0x2e9d50;
}
static void *CreateConfig(void *ignored){(void)ignored;hv_vm_config_t c=hv_vm_config_create();CFRelease((CFTypeRef)c);return NULL;}
static void *InstallFirstThread(void *ignored){(void)ignored;hv_vm_config_t c=hv_vm_config_create();NEED(c);CFRelease((CFTypeRef)c);return NULL;}
static void Rejection(unsigned which) {
 pid_t child=fork();NEED(child>=0);
 if(!child) {
  switch(which) {
  case 0:ReturnPC-=4;break;
  case 1:Image[sizeof(struct mach_header_64)+8]^=1;break;
  case 2:strcpy(Path,"/var/root/VirtualMac/payload/VirtualMac");break;
  case 3:Image[0x2e9d4c]^=1;break;
  case 4:((struct uuid_command *)(Image+sizeof(struct mach_header_64)))->cmdsize=8;break;
  case 5:((struct mach_header_64 *)(void *)Image)->sizeofcmds=UINT32_MAX;break;
  case 6:PathError=-1;break;
  case 7:((struct mach_header_64 *)(void *)Image)->filetype=MH_DYLIB;break;
  case 8:Image=NULL;break;
  case 9: {
   pthread_t first,second;NEED(!pthread_create(&first,NULL,InstallFirstThread,NULL));NEED(!pthread_join(first,NULL));
   NEED(!pthread_create(&second,NULL,CreateConfig,NULL));NEED(!pthread_join(second,NULL));_exit(77);
  }
  default:abort();
  }
  (void)hv_vm_config_create();_exit(77);
 }
 int status=0;NEED(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
}
static void *OwnerWorker(void *ignored) {
 (void)ignored;NEED(!Installed);hv_vm_config_t a=hv_vm_config_create(),b=hv_vm_config_create();NEED(a && b && a!=b);
 NEED(!_hv_vm_config_set_isa(a,2));NEED(!hv_vm_create(a));NEED(NativeVMCreate==1);NEED(!hv_vm_destroy());NEED(NativeVMDestroy==1);
 CFRelease((CFTypeRef)a);CFRelease((CFTypeRef)b);NEED(!VM27HVVMUninstallNativeOpsV1());return NULL;
}
int main(void) {
 alarm(20);struct rlimit core={0,0};NEED(!setrlimit(RLIMIT_CORE,&core));InitializeImage();
 uint32_t out=91;Pair=(VM27CPURawIPAPairV2){false,40,42};NEED(hv_vm_config_get_max_ipa_size(&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==91);
 Pair=(VM27CPURawIPAPairV2){true,UINT64_C(1)<<32,42};NEED(hv_vm_config_get_max_ipa_size(&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==91);
 Pair=(VM27CPURawIPAPairV2){true,35,42};NEED(hv_vm_config_get_max_ipa_size(&out)==(hv_return_t)UINT32_C(0xfae9400f) && out==91);
 Pair=(VM27CPURawIPAPairV2){true,40,42};NEED(!hv_vm_config_get_max_ipa_size(&out) && out==36);NEED(!hv_vm_config_get_default_ipa_size(&out) && out==36);
 unsigned queries=RawQueries;uint32_t *volatile missing=NULL;NEED(hv_vm_config_get_max_ipa_size(missing)==(hv_return_t)UINT32_C(0xfae94003) && RawQueries==queries);
 NEED(InstallerCalls==0 && !Installed && NativeVMCreate==0);
 for(unsigned i=0;i<10;++i)Rejection(i);
 NEED(InstallerCalls==0 && !Installed && NativeVMCreate==0);
 pthread_t worker;NEED(!pthread_create(&worker,NULL,OwnerWorker,NULL));NEED(!pthread_join(worker,NULL));
 NEED(InstallerCalls==2 && NativeVMCreate==1 && NativeVMDestroy==1);NEED(!munmap(Image,0x300000));
 printf("{\"checks\":%u,\"passed\":true,\"pureQueryBeforeInstall\":true,\"queryPreservesUnknown\":true,\"rejectedEntryCases\":9,\"foreignVMThreadRejected\":true,\"sameOwnerConfigCreates\":2,\"actualRootInstallAndCreate\":true,\"nativeKernelOperations\":0,\"deviceOperations\":0}\n",Checks);
 return 0;
}
