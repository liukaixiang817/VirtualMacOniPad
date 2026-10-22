/* Preserve the native getter path while adapting one absent Mac query to the
 * public Apple8 device profile proven by actual framebuffer-fetch readback. */
#define VM27OwnedPVGIsFramebufferReadSupportedV1 VM27OwnedPVGFramebufferReadOriginalV30
/* Preserve every current capability, resource, VT and display observation. */
#include "modern_metal_display_identity_cache_v35.m"
#include "vm27_owned_gpu_task_parent_v1.h"
#ifndef VM27_OWNED_GPU_PARENT_PROFILE_HEADER
#error Root must supply the generated profile from the actual signed GPU task
#endif
#include VM27_OWNED_GPU_PARENT_PROFILE_HEADER
#include "vm27_owned_gpu_task_parent_v4.inc"

#include "vm27_owned_vmm_fatal_context_v1.inc"

#undef VM27OwnedPVGIsFramebufferReadSupportedV1

__attribute__((visibility("default")))
BOOL VM27OwnedPVGIsFramebufferReadSupportedV1(id device, SEL selector) {
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    Class cls=object_getClass(device);
    Method original=cls?class_getInstanceMethod(cls,selector):NULL;
    if(original)return PVGCmd58OptionalBOOLV1(device,selector,caller,8);
    int incoming=errno;uintptr_t rva=0;
    if(!selector || strcmp(sel_getName(selector),"isFramebufferReadSupported") ||
       !PVGCapabilityScopeV3(caller,&rva,8)) {
        dprintf(2,"[VM27OwnedPVGFramebufferReadV30] admission=0\n");errno=ENOTSUP;__builtin_trap();
    }
    SEL family=sel_registerName("supportsFamily:");
    Method method=cls?class_getInstanceMethod(cls,family):NULL;
    char result[16]={0},self[16]={0},command[16]={0},argument[16]={0};
    if(!method || method_getNumberOfArguments(method)!=3){errno=incoming;return NO;}
    method_getReturnType(method,result,sizeof(result));
    method_getArgumentType(method,0,self,sizeof(self));method_getArgumentType(method,1,command,sizeof(command));
    method_getArgumentType(method,2,argument,sizeof(argument));
    if(strcmp(result,@encode(BOOL)) || strcmp(self,"@") || strcmp(command,":") || strcmp(argument,@encode(MTLGPUFamily))) {
        errno=incoming;return NO;
    }
    errno=incoming;
    BOOL supported=((BOOL(*)(id,SEL,MTLGPUFamily))objc_msgSend)(device,family,MTLGPUFamilyApple8);
    int actualErrno=errno;
    if(PVGCapabilityLogV1())dprintf(2,"[VM27OwnedPVGFramebufferReadV30] callerRVA=0x%lx privateGetterMissing=1 nativeApple8QueryOnce=1 nativeFamily8=%u actualReadbackProfileProven=1 returned=%u\n",(unsigned long)rva,supported?1u:0u,supported?1u:0u);
    errno=actualErrno;return supported;
}
