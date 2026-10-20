// An ordinary own-process native GPU/NSArray leaf. It loads no VM frameworks.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int vm27_metal_device_array_profile_matches(void);
extern NSArray<id<MTLDevice>> *VM27MetalDeviceArrayFixture(void) __attribute__((ns_returns_retained));
static unsigned checks, failures;
static void need(int value) { ++checks; if (!value) ++failures; }
static const char *unqualified(const char *type) {
    while (*type && strchr("rnNoORV",*type)) ++type;
    return type;
}
static int bool_getter(id object, SEL selector, BOOL *value, int *responds) {
    *responds=[object respondsToSelector:selector];
    if (!*responds) return 0;
    NSMethodSignature *signature=[object methodSignatureForSelector:selector];
    if (!signature || [signature numberOfArguments]!=2) return 0;
    const char *result=unqualified([signature methodReturnType]);
    if (strcmp(result,"B") && strcmp(result,"c")) return 0;
    if (strcmp(unqualified([signature getArgumentTypeAtIndex:0]),"@") ||
        strcmp(unqualified([signature getArgumentTypeAtIndex:1]),":")) return 0;
    if (!strcmp(result,"B")) *value=((BOOL(*)(id,SEL))objc_msgSend)(object,selector);
    else *value=((signed char(*)(id,SEL))objc_msgSend)(object,selector)!=0;
    return 1;
}
static int registry_identity(id object, uint64_t *value) {
    SEL selector=sel_registerName("registryID");
    if (![object respondsToSelector:selector]) return 0;
    NSMethodSignature *signature=[object methodSignatureForSelector:selector];
    if (!signature || [signature numberOfArguments]!=2 ||
        strcmp(unqualified([signature methodReturnType]),"Q") ||
        strcmp(unqualified([signature getArgumentTypeAtIndex:0]),"@") ||
        strcmp(unqualified([signature getArgumentTypeAtIndex:1]),":")) return 0;
    *value=((uint64_t(*)(id,SEL))objc_msgSend)(object,selector);
    return 1;
}
int main(void) {
    static const char begin[]="VM27_ORDINARY_METAL_ARRAY_MAIN_V1\n";
    write(STDOUT_FILENO,begin,sizeof(begin)-1);
    alarm(40);
    unsigned nil_defaults=0,non_nil_defaults=0,owned_arrays=0,registry_checks=0;
    unsigned low_responds=0,low_valid=0,low_true=0,remove_responds=0,remove_valid=0,remove_true=0;
    uint64_t first_registry=0;
    int profile=vm27_metal_device_array_profile_matches();need(profile);
    if (!profile) {
        printf("{\"profileMatches\":false,\"checks\":%u,\"failures\":%u,\"nativeDefaultCalls\":0,\"nativeHVCalls\":0,\"full27Backend\":false}\n",checks,failures);
        return 2;
    }
    for (unsigned i=0;i<64;++i) {
        NSArray *candidate=nil;
        uint64_t native_registry=0;
        int had_native=0,had_registry=0;
        @autoreleasepool {
            id native=MTLCreateSystemDefaultDevice();had_native=native!=nil;
            candidate=VM27MetalDeviceArrayFixture();need(candidate!=nil);
            if (!candidate) { [native release];continue; }
            ++owned_arrays;
            if (!native) { ++nil_defaults;need([candidate count]==0); }
            else {
                ++non_nil_defaults;need([candidate count]==1);
                had_registry=registry_identity(native,&native_registry);need(had_registry);
                if (i==0 && had_registry) first_registry=native_registry;
            }
            [native release];
        }
        if (!candidate) continue;
        need([candidate count]==(had_native?1u:0u));
        if (had_native && [candidate count]==1) {
            id selected=[[candidate objectAtIndex:0] retain];
            uint64_t actual=0;int typed=registry_identity(selected,&actual);need(typed);
            if (typed && had_registry) {need(actual==native_registry);++registry_checks;}
            BOOL value=NO;int responds=0;
            int valid=bool_getter(selected,sel_registerName("isLowPower"),&value,&responds);
            low_responds+=responds;low_valid+=valid;low_true+=valid&&value;
            valid=bool_getter(selected,sel_registerName("isRemovable"),&value,&responds);
            remove_responds+=responds;remove_valid+=valid;remove_true+=valid&&value;
            [candidate release];candidate=nil;
            uint64_t after=0;typed=registry_identity(selected,&after);need(typed);
            if (typed && had_registry) need(after==native_registry);
            [selected release];
        }
        [candidate release];
    }
    need(owned_arrays==64);
    printf("{\"profileMatches\":true,\"checks\":%u,\"failures\":%u,\"nativeDefaultCalls\":64,\"candidateNativeDefaultCalls\":64,\"ownedArrays\":%u,\"nilNativeDefaults\":%u,\"nonNilNativeDefaults\":%u,\"registryIdentityComparisons\":%u,\"firstRegistryID\":%llu,\"isLowPowerResponses\":%u,\"isLowPowerTypedCalls\":%u,\"isLowPowerTrue\":%u,\"isRemovableResponses\":%u,\"isRemovableTypedCalls\":%u,\"isRemovableTrue\":%u,\"allConsumerSelectorsCallable\":%s,\"methodsAdded\":0,\"nativeHVCalls\":0,\"nativeVMMCalls\":0,\"originalVZLoaded\":false,\"full27Backend\":false}\n",
        checks,failures,owned_arrays,nil_defaults,non_nil_defaults,registry_checks,
        (unsigned long long)first_registry,low_responds,low_valid,low_true,remove_responds,remove_valid,remove_true,
        non_nil_defaults==64&&low_valid==64&&remove_valid==64?"true":"false");
    alarm(0);return failures?2:0;
}
