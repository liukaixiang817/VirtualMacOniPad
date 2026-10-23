#include "vm27_display_refresh_policy_v1.h"
struct VM27PGSizeV1 {uint16_t width,height;};
typedef id (*VM27PGModeInitFunctionV1)(id,SEL,struct VM27PGSizeV1,double);
static VM27PGModeInitFunctionV1 VM27PGModeOriginalV1;
static Class VM27PGModeClassV1;
static unsigned VM27PGModeLogsV1;
static id VM27PGModeInitV1(id object,SEL selector,struct VM27PGSizeV1 size,double rate) {
 void *caller=__builtin_extract_return_addr(__builtin_return_address(0));Dl_info info={0};
 unsigned requested=60;uintptr_t at=0;
 if(object_getClass(object)==VM27PGModeClassV1 && rate==60.0 && getuid()==501 && geteuid()==501 &&
  dladdr(caller,&info) && info.dli_fbase && info.dli_fname &&
  !strcmp(info.dli_fname,"/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine")) {
  at=(uintptr_t)caller-(uintptr_t)info.dli_fbase;
  if(at==0x14d0f8 || at==0x14f000 || at==0x14f684)requested=VM27RefreshReadParentV1();
 }
 id result=VM27PGModeOriginalV1(object,selector,size,requested==120?120.0:rate);
 if(requested==120 && __atomic_fetch_add(&VM27PGModeLogsV1,1,__ATOMIC_RELAXED)<8)
  fprintf(stderr,"[Independent27DisplayRefreshV1] nativePGMode=%ux%u requestedHz=120 originalHz=%.0f callerRVA=%lx originalInitializer=1\n",size.width,size.height,rate,(unsigned long)at);
 return result;
}
__attribute__((constructor)) static void VM27PGModeInstallV1(void) {
 if(getuid()!=501 || geteuid()!=501)return;
 Class cls=objc_getClass("PGDisplayMode");SEL selector=sel_registerName("initWithSizeInPixels:refreshRateInHz:");
 Method method=cls?class_getInstanceMethod(cls,selector):NULL;Dl_info info={0};
 if(!method || strcmp(method_getTypeEncoding(method),"@28@0:8{?=SS}16d20") || class_getInstanceSize(cls)!=32)return;
 IMP original=method_getImplementation(method);void *stripped=ptrauth_strip((void *)original,ptrauth_key_function_pointer);
 if(!dladdr(stripped,&info) || !info.dli_fbase || !info.dli_fname ||
  strcmp(info.dli_fname,"/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/ParavirtualizedGraphics27.dylib") ||
  (uintptr_t)stripped-(uintptr_t)info.dli_fbase!=0x4148c)return;
 VM27PGModeClassV1=cls;VM27PGModeOriginalV1=(VM27PGModeInitFunctionV1)original;
 if(method_setImplementation(method,(IMP)VM27PGModeInitV1)!=original)abort();
 fprintf(stderr,"[Independent27DisplayRefreshV1] ownedVMMModeAdapter=1 defaultHz=60 perParentPlan=1 nativePGCommandsUnchanged=1\n");
}
