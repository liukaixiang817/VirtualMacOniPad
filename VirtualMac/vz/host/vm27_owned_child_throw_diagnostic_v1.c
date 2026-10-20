#include "modern_cpu_native_self_memory_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

static const uint8_t ChildUUIDV1[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
static const uint8_t NativeABIUUIDV1[16]={0xfa,0x87,0x14,0x17,0xbe,0x08,0x3e,0x90,0xb3,0x3c,0xa6,0xaa,0x89,0x81,0x3f,0x3b};
static const char ChildPathV1[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static unsigned ThrowCountV1;

/* This reads real loaded headers through the existing bounded self reader.
 * It does not assume a dyld image index or replace executable identity. */
static bool ImageUUIDV1(const void *base,uint32_t filetype,const uint8_t expected[16]) {
 struct mach_header_64 h={0};
 if(!base || !VM27CPUSelfReadV1(NULL,base,sizeof(h),&h) || h.magic!=MH_MAGIC_64 ||
    h.filetype!=filetype || !h.ncmds || h.ncmds>2048 || h.sizeofcmds>65536)return false;
 size_t offset=0;unsigned matches=0;
 for(uint32_t i=0;i<h.ncmds;++i) {
  struct load_command c={0};
  if(offset>h.sizeofcmds || sizeof(c)>h.sizeofcmds-offset ||
     !VM27CPUSelfReadV1(NULL,(const uint8_t *)base+sizeof(h)+offset,sizeof(c),&c) ||
     c.cmdsize<8 || (c.cmdsize&7) || c.cmdsize>h.sizeofcmds-offset)return false;
  if(c.cmd==LC_UUID) {
   uint8_t uuid[16];
   if(c.cmdsize!=sizeof(struct uuid_command) || ++matches!=1 ||
      !VM27CPUSelfReadV1(NULL,(const uint8_t *)base+sizeof(h)+offset+8,16,uuid) ||
      memcmp(uuid,expected,16))return false;
  }
  offset+=c.cmdsize;
 }
 return matches==1 && offset==h.sizeofcmds;
}

static bool ChildCallerV1(void *caller,uintptr_t *rva) {
 if(getuid()!=501 || geteuid()!=501 || getpid()<=1)return false;
 char path[4096]={0},canonical[4096]={0};uint32_t capacity=sizeof(path);
 if(_NSGetExecutablePath(path,&capacity) || capacity>sizeof(path) ||
    !memchr(path,0,sizeof(path)) || !realpath(path,canonical) || strcmp(canonical,ChildPathV1))return false;
 Dl_info image={0};
 if(!caller || !dladdr(caller,&image) || !image.dli_fname ||
    strcmp(image.dli_fname,ChildPathV1) || !ImageUUIDV1(image.dli_fbase,MH_EXECUTE,ChildUUIDV1) ||
    (uintptr_t)caller<(uintptr_t)image.dli_fbase)return false;
 *rva=(uintptr_t)caller-(uintptr_t)image.dli_fbase;return true;
}

/* An arbitrary C++ object is never called as an invented interface. Only
 * readable printable NUL-terminated bytes are reported as a pointer string. */
static bool PlainStringV1(uintptr_t address,char out[97]) {
 if(!address || address>UINTPTR_MAX-96)return false;
 for(size_t i=0;i<96;++i) {
  unsigned char c;
  if(!VM27CPUSelfReadV1(NULL,(const void *)(address+i),1,&c))return false;
  if(!c) { out[i]=0;return i!=0; }
  if(c<32 || c>126)return false;
  out[i]=(char)c;
 }
 out[0]=0;return false;
}

static bool AdmitLogV1(void) {
 unsigned value=__atomic_load_n(&ThrowCountV1,__ATOMIC_RELAXED);
 while(value<8)if(__atomic_compare_exchange_n(&ThrowCountV1,&value,value+1,false,
    __ATOMIC_RELAXED,__ATOMIC_RELAXED))return true;
 return false;
}

__attribute__((noreturn,visibility("default")))
void __cxa_throw(void *exceptionObject,void *exceptionType,void (*destructor)(void *)) {
 int incomingErrno=errno;
 void *caller=__builtin_return_address(0);
#if __has_feature(ptrauth_calls)
 caller=ptrauth_strip(caller,ptrauth_key_return_address);
#endif
 uintptr_t callerRVA=0;
 bool traced=ChildCallerV1(caller,&callerRVA) && AdmitLogV1();
 void *handle=dlopen("/usr/lib/libc++abi.dylib",RTLD_NOW|RTLD_LOCAL|RTLD_NOLOAD);
 void *symbol=handle?dlsym(handle,"__cxa_throw"):NULL,*address=symbol;
#if __has_feature(ptrauth_calls)
 address=ptrauth_strip(symbol,ptrauth_key_function_pointer);
#endif
 Dl_info native={0};
 bool genuine=symbol && dladdr(address,&native) && native.dli_fname &&
  !strcmp(native.dli_fname,"/usr/lib/libc++abi.dylib") && native.dli_fbase &&
  (uintptr_t)address==(uintptr_t)native.dli_fbase+UINT64_C(80716) &&
  ImageUUIDV1(native.dli_fbase,MH_DYLIB,NativeABIUUIDV1);
 if(!genuine) {
  if(handle)dlclose(handle);
  if(traced)dprintf(2,"[Independent27HV] actual-child-throw guardFailed=1 callerRVA=0x%lx nativeCalled=0\n",(unsigned long)callerRVA);
  errno=ENOTSUP;__builtin_trap();
 }
 if(traced) {
  uintptr_t typeWords[2]={0};char typeName[97]={0},reason[97]={0},hex[129]={0};
  uint8_t payload[64]={0};static const char digits[]="0123456789abcdef";
  bool typeRead=exceptionType && VM27CPUSelfReadV1(NULL,exceptionType,sizeof(typeWords),typeWords);
  /* Genuine Darwin LP64 type_info::name() removes only its nonunique bit. */
  bool nameRead=typeRead && PlainStringV1(typeWords[1]&UINT64_C(0x7fffffffffffffff),typeName);
  bool payloadRead=exceptionObject && VM27CPUSelfReadV1(NULL,exceptionObject,sizeof(payload),payload);
  int reasonWord=-1;
  if(payloadRead) {
   for(size_t i=0;i<sizeof(payload);++i){hex[2*i]=digits[payload[i]>>4];hex[2*i+1]=digits[payload[i]&15];}
   for(unsigned i=0;i<4;++i) {
    uintptr_t value;memcpy(&value,payload+i*sizeof(value),sizeof(value));
    if(PlainStringV1(value,reason)){reasonWord=(int)i;break;}
   }
  }
  dprintf(2,"[Independent27HV] actual-child-throw callerRVA=0x%lx type=%p typeNameRaw=0x%lx typeNameReadable=%u typeName=%s payloadReadable=%u payload64=%s plainPointerWord=%d plainPointerString=%s nativeCalled=1 nativeRVA=0x13b4c\n",
   (unsigned long)callerRVA,exceptionType,(unsigned long)typeWords[1],nameRead?1U:0U,nameRead?typeName:"(unreadable)",
   payloadRead?1U:0U,payloadRead?hex:"(unreadable)",reasonWord,reasonWord>=0?reason:"(none)");
 }
 /* libc++abi stays loaded by the original executable's required dependency.
  * Release this NOLOAD reference before the native nonreturning call. */
 dlclose(handle);errno=incomingErrno;
 typedef void (*NativeThrowV1)(void *,void *,void (*)(void *)) __attribute__((noreturn));
 ((NativeThrowV1)symbol)(exceptionObject,exceptionType,destructor);
 __builtin_unreachable();
}
