#define _DARWIN_C_SOURCE 1
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
// iPhoneOS SDK mach_vm.h intentionally contains #error. These exact typed
// declarations come from the real macOS SDK mach_vm.h. Both exports are
// present in the captured current iPad kernel library; no syscall is invented.
extern kern_return_t mach_vm_map(vm_map_t,mach_vm_address_t *,mach_vm_size_t,
 mach_vm_offset_t,int,mem_entry_name_port_t,memory_object_offset_t,boolean_t,
 vm_prot_t,vm_prot_t,vm_inherit_t);
extern kern_return_t mach_vm_deallocate(vm_map_t,mach_vm_address_t,mach_vm_size_t);
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

// Self-only public Mach APIs. At most 16 KiB is committed and read/written.
// Explicit sparse mode reserves the real 8 GiB virtual span with no access,
// and never commits or touches that span. No HV/VM/driver operation occurs.
static const uint64_t Page=UINT64_C(0x4000),Payload=UINT64_C(0x4000);
static const unsigned char KernelUUID[16]={0xff,0x27,0xfc,0x8f,0x90,0xba,0x33,0x32,0xab,0x7a,0xc5,0xbc,0x2d,0x9c,0xa7,0xb1};
static void Timeout(int signalNumber) {
 (void)signalNumber;
 const char message[]="MEMORY_PROBE_TIMEOUT self-only kernel cleanup on exit\n";
 (void)write(STDOUT_FILENO,message,sizeof(message)-1);_exit(124);
}
static int Native(void *pointer,uint64_t rva,const char *name) {
#if __has_feature(ptrauth_calls)
 pointer=ptrauth_strip(pointer,ptrauth_key_function_pointer);
#endif
 Dl_info info={0};if(!dladdr(pointer,&info)||!info.dli_fbase||!info.dli_fname||
  strcmp(info.dli_fname,"/usr/lib/system/libsystem_kernel.dylib")||
  (uintptr_t)pointer<(uintptr_t)info.dli_fbase||
  (uintptr_t)pointer-(uintptr_t)info.dli_fbase!=rva)return 0;
 const struct mach_header_64 *h=info.dli_fbase;
 if(h->magic!=MH_MAGIC_64||h->cputype!=CPU_TYPE_ARM64||h->filetype!=MH_DYLIB||
  !h->ncmds||h->ncmds>512||h->sizeofcmds>16384)return 0;
 const unsigned char *raw=(const unsigned char *)(h+1);size_t cursor=0;unsigned found=0;
 for(uint32_t i=0;i<h->ncmds;++i) {
  if(cursor>h->sizeofcmds||h->sizeofcmds-cursor<sizeof(struct load_command))return 0;
  const struct load_command *c=(const void *)(raw+cursor);
  if(c->cmdsize<8||c->cmdsize%8||c->cmdsize>h->sizeofcmds-cursor)return 0;
  if(c->cmd==LC_UUID) {
   if(c->cmdsize!=sizeof(struct uuid_command)||++found!=1||
    memcmp(((const struct uuid_command *)c)->uuid,KernelUUID,16))return 0;
  }
  cursor+=c->cmdsize;
 }
 if(cursor!=h->sizeofcmds||found!=1)return 0;
 printf("NATIVE name=%s path=%s rva=%llu actual=1\n",name,info.dli_fname,(unsigned long long)rva);return 1;
}
static kern_return_t Reserve(mach_vm_size_t bytes,mach_vm_address_t *address,const char *name) {
 *address=0;errno=0;
 kern_return_t kr=mach_vm_map(mach_task_self(),address,bytes,0,0x400001,
  MACH_PORT_NULL,0,FALSE,VM_PROT_NONE,VM_PROT_NONE,VM_INHERIT_NONE);
 printf("RESERVE phase=%s flags=0x400001 bytes=%llu kr=%d errno=%d address=%llu\n",
  name,(unsigned long long)bytes,kr,errno,(unsigned long long)*address);
 if(kr!=KERN_SUCCESS) {
  *address=0;errno=0;
  kr=mach_vm_map(mach_task_self(),address,bytes,0,1,MACH_PORT_NULL,0,FALSE,
   VM_PROT_NONE,VM_PROT_NONE,VM_INHERIT_NONE);
  printf("RESERVE phase=%s flags=0x1 bytes=%llu kr=%d errno=%d address=%llu\n",
   name,(unsigned long long)bytes,kr,errno,(unsigned long long)*address);
 }
 return kr;
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IONBF,0);setvbuf(stderr,NULL,_IONBF,0);
 int sparse=argc==2&&!strcmp(argv[1],"--sparse-original-reserve");
 if((argc!=1&&!sparse)||getuid()!=501||geteuid()!=501||getpid()<=1||getpagesize()!=16384)return 2;
 struct rlimit cpu={5,5},core={0,0};
 if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_CORE,&core))return 2;
 struct sigaction action={0};action.sa_handler=Timeout;sigemptyset(&action.sa_mask);
 if(sigaction(SIGALRM,&action,NULL))return 2;alarm(18);
 printf("IDENTITY pid=%d uid=%u euid=%u page=%d sparseRequested=%d cpuLimit=5 coreLimit=0\n",
  getpid(),getuid(),geteuid(),getpagesize(),sparse);
 if(!Native((void *)(uintptr_t)&mach_vm_map,0x180c,"mach_vm_map")||
  !Native((void *)(uintptr_t)&mach_make_memory_entry_64,0x3eb0,"mach_make_memory_entry_64"))return 3;
 mach_vm_address_t address=0;mach_vm_size_t span=Payload+2*Page;mach_port_t entry=MACH_PORT_NULL;
 int owned=0,result=0;unsigned committed=0;
 kern_return_t reserve=Reserve(span,&address,"local16k");
 if(reserve==KERN_SUCCESS) {
  owned=1;
  if(!address||(address&(Page-1))||address>UINT64_MAX-span){result=4;goto cleanup;}
  memory_object_size_t actualSize=Payload;errno=0;
  kern_return_t make=mach_make_memory_entry_64(mach_task_self(),&actualSize,0,
   (vm_prot_t)0x22007,&entry,MACH_PORT_NULL);
  printf("MAKE_ENTRY requested=%llu returned=%llu permission=0x22007 kr=%d errno=%d port=%u\n",
   (unsigned long long)Payload,(unsigned long long)actualSize,make,errno,entry);
  if(make==KERN_SUCCESS&&actualSize==Payload&&MACH_PORT_VALID(entry)) {
   mach_vm_address_t interior=address+Page;errno=0;
   kern_return_t commit=mach_vm_map(mach_task_self(),&interior,Payload,0,(int)UINT32_C(0xf0004000),
    entry,0,FALSE,VM_PROT_READ|VM_PROT_WRITE,VM_PROT_ALL,VM_INHERIT_NONE);
   printf("COMMIT bytes=%llu flags=0xf0004000 curProtection=3 maxProtection=7 inherit=2 kr=%d errno=%d address=%llu expected=%llu\n",
    (unsigned long long)Payload,commit,errno,(unsigned long long)interior,(unsigned long long)(address+Page));
   if(commit==KERN_SUCCESS&&interior==address+Page) {
    volatile unsigned char *bytes=(void *)(uintptr_t)interior;
    for(uint64_t i=0;i<Payload;++i)bytes[i]=(unsigned char)(i^0x5a);
    unsigned mismatches=0;
    for(uint64_t i=0;i<Payload;++i)if(bytes[i]!=(unsigned char)(i^0x5a))++mismatches;
    committed=mismatches==0;
    printf("READ_WRITE actualBytes=%llu mismatches=%u verified=%u\n",(unsigned long long)Payload,mismatches,committed);
    if(mismatches)result=5;
   }
  }
 }
cleanup:
 if(MACH_PORT_VALID(entry)) {
  errno=0;kern_return_t release=mach_port_deallocate(mach_task_self(),entry);
  printf("CLEANUP entryPort=%u kr=%d errno=%d\n",entry,release,errno);
  if(release!=KERN_SUCCESS)result=6;
 }
 if(owned) {
  errno=0;kern_return_t release=mach_vm_deallocate(mach_task_self(),address,span);
  printf("CLEANUP phase=local16k address=%llu bytes=%llu kr=%d errno=%d\n",
   (unsigned long long)address,(unsigned long long)span,release,errno);
  if(release!=KERN_SUCCESS)result=6;
 }
 if(sparse&&!result) {
  mach_vm_address_t big=0;const mach_vm_size_t virtualBytes=UINT64_C(0x200000000)+2*Page;
  kern_return_t kr=Reserve(virtualBytes,&big,"original8g-sparse-only");
  if(kr==KERN_SUCCESS) {
   errno=0;kern_return_t release=mach_vm_deallocate(mach_task_self(),big,virtualBytes);
   printf("CLEANUP phase=original8g-sparse-only address=%llu virtualBytes=%llu physicalCommitBytes=0 kr=%d errno=%d\n",
    (unsigned long long)big,(unsigned long long)virtualBytes,release,errno);
   if(release!=KERN_SUCCESS)result=6;
  }
 }
 printf("RESULT exit=%d localCommitVerified=%u original8gPhysicalCommitPerformed=0 hvCalls=0 vmCreated=0\n",result,committed);
 alarm(0);return result;
}
