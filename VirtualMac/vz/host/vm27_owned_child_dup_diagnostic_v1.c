#include "modern_cpu_native_self_memory_v1.h"
#include "vm27_actual_executable_image_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
static const uint8_t NativeKernelUUIDV1[16]={0xff,0x27,0xfc,0x8f,0x90,0xba,0x33,0x32,0xab,0x7a,0xc5,0xbc,0x2d,0x9c,0xa7,0xb1};
static const uint8_t OriginalChildUUIDV1[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
static const char ChildPathV1[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static bool NativeUUIDV1(const void *base) {
 struct mach_header_64 header={0};
 if(!VM27CPUSelfReadV1(NULL,base,sizeof(header),&header) || header.magic!=MH_MAGIC_64 ||
    header.filetype!=MH_DYLIB || !header.ncmds || header.ncmds>128 || header.sizeofcmds>4096)return false;
 uint8_t commands[4096];if(!VM27CPUSelfReadV1(NULL,(const uint8_t *)base+sizeof(header),header.sizeofcmds,commands))return false;
 size_t offset=0;unsigned matches=0;
 for(uint32_t i=0;i<header.ncmds;++i) {
  struct load_command command;
  if(offset>header.sizeofcmds || sizeof(command)>header.sizeofcmds-offset)return false;
  memcpy(&command,commands+offset,sizeof(command));
  if(command.cmdsize<8 || (command.cmdsize&7) || command.cmdsize>header.sizeofcmds-offset)return false;
  if(command.cmd==LC_UUID) {
   if(command.cmdsize!=sizeof(struct uuid_command) || memcmp(commands+offset+8,NativeKernelUUIDV1,16))return false;
   ++matches;
  }
  offset+=command.cmdsize;
 }
 return matches==1 && offset==header.sizeofcmds;
}
static bool ExactChildCallerV1(void *caller) {
#if __has_feature(ptrauth_calls)
 caller=ptrauth_strip(caller,ptrauth_key_return_address);
#endif
 Dl_info info={0};VM27ActualExecutableImageV1 actual={0};
 return dladdr(caller,&info) && info.dli_fname && !strcmp(info.dli_fname,ChildPathV1) &&
  VM27ActualExecutableImageFindSelfV1(&actual)==0 && info.dli_fbase==actual.header &&
  !memcmp(actual.uuid,OriginalChildUUIDV1,16) &&
  (uintptr_t)caller==(uintptr_t)actual.header+UINT64_C(0x91c00);
}
int dup(int descriptor) {
 int incomingErrno=errno;
 bool traced=ExactChildCallerV1(__builtin_return_address(0));
 void *handle=dlopen("/usr/lib/libSystem.B.dylib",RTLD_NOW|RTLD_LOCAL|RTLD_NOLOAD);
 void *symbol=handle?dlsym(handle,"dup"):NULL,*address=symbol;
#if __has_feature(ptrauth_calls)
 address=ptrauth_strip(symbol,ptrauth_key_function_pointer);
#endif
 Dl_info native={0};
 bool genuine=symbol && dladdr(address,&native) && native.dli_fname &&
  !strcmp(native.dli_fname,"/usr/lib/system/libsystem_kernel.dylib") && native.dli_fbase &&
  (uintptr_t)address==(uintptr_t)native.dli_fbase+UINT64_C(9144) && NativeUUIDV1(native.dli_fbase);
 if(!genuine) {
  if(handle)dlclose(handle);
  if(traced)dprintf(2,"[Independent27HV] actual-emulator-dup guardFailed=1 fd=%d errno=%d nativeCalled=0\n",descriptor,ENOTSUP);
  errno=ENOTSUP;return -1;
 }
 typedef int (*NativeDupV1)(int);
 errno=incomingErrno;
 int result=((NativeDupV1)symbol)(descriptor),actualErrno=errno;
 dlclose(handle);
 if(traced)dprintf(2,"[Independent27HV] actual-emulator-dup fd=%d result=%d errno=%d callerRVA=0x91c00 nativeCalled=1 nativeRVA=0x23b8\n",descriptor,result,actualErrno);
 errno=actualErrno;return result;
}
