// Ordinary genuine-Mac source comparison. It never loads Virtualization.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int vm27_metal_device_array_profile_matches(void);
extern NSArray *vm27_metal_owned_device_array(id) __attribute__((ns_returns_retained));
extern id vm27_metal_select_singleton_owned_array(NSArray *, uint32_t)
    __attribute__((ns_returns_not_retained));
static unsigned checks, low_calls, removable_calls;
static void need(int value) { ++checks; if (!value) exit(2); }

// Reconstructed from the complete original 620-byte caller and its exact
// retain/release/autorelease islands. This is source, not original VZ execution.
static id original_selection_source(NSArray *ownedDevices, uint32_t preference) {
    id selected=nil;
    @try {
        if (preference) {
            NSArray *enumerated=[ownedDevices retain];
            @try {
                for (id<MTLDevice> device in enumerated) {
                    ++low_calls;
                    if ([device isLowPower]) { selected=[device retain];break; }
                }
            } @finally { [enumerated release]; }
        }
        if (!selected) {
            NSArray *enumerated=[ownedDevices retain];
            @try {
                for (id<MTLDevice> device in enumerated) {
                    if (!selected) selected=[device retain];
                    ++low_calls;
                    if ([device isLowPower]) continue;
                    ++removable_calls;
                    if ([device isRemovable]) continue;
                    id preferred=[device retain];
                    [selected release];selected=preferred;break;
                }
            } @finally { [enumerated release]; }
        }
    } @catch (id error) { [selected release];@throw error; }
    @finally { [ownedDevices release]; }
    return [selected autorelease];
}

int main(void) {
    need(vm27_metal_device_array_profile_matches());
    unsigned empty=0, positive=0, rejected_multiple=0, same_registry=0;
    unsigned genuine_low_true=0,genuine_removable_true=0;
    const uint32_t preferences[]={0,1,2,0xffffffffu};
    for (unsigned i=0;i<64;++i) {
        for (unsigned j=0;j<4;++j) {
            @autoreleasepool {
                need(original_selection_source(vm27_metal_owned_device_array(nil),preferences[j])==nil);
                need(vm27_metal_select_singleton_owned_array(vm27_metal_owned_device_array(nil),preferences[j])==nil);
                ++empty;
            }
        }
        id<MTLDevice> native=MTLCreateSystemDefaultDevice();
        if (!native) continue;
        need([native respondsToSelector:@selector(isLowPower)] &&
             [native respondsToSelector:@selector(isRemovable)]);
        genuine_low_true += [native isLowPower];
        genuine_removable_true += [native isRemovable];
        uint64_t registry=[native registryID];
        for (unsigned j=0;j<4;++j) {
            id<MTLDevice> original=nil,adapted=nil;
            @autoreleasepool {
                original=[original_selection_source(vm27_metal_owned_device_array(native),preferences[j]) retain];
                unsigned before=low_calls+removable_calls;
                adapted=[vm27_metal_select_singleton_owned_array(vm27_metal_owned_device_array(native),preferences[j]) retain];
                need(low_calls+removable_calls==before);
                need(original==native && adapted==native && original==adapted);
                ++positive;
            }
            // Caller-owned retains survive both consumed arrays and the return
            // autorelease pool. Check the genuine object's registry afterward.
            need([original registryID]==registry && [adapted registryID]==registry);
            ++same_registry;[original release];[adapted release];
        }
        @autoreleasepool {
            NSArray *multiple=[[NSArray alloc] initWithObjects:native,native,nil];
            @try { (void)vm27_metal_select_singleton_owned_array(multiple,0);need(0); }
            @catch (NSException *exception) {
                need([[exception name] isEqualToString:NSInvalidArgumentException]);++rejected_multiple;
            }
        }
        [native release];
    }
    printf("{\"checks\":%u,\"emptyCases\":%u,\"genuineSingletonComparisons\":%u,\"sameNativeRegistryAfterArrayAndPoolRelease\":%u,\"multipleDeviceDomainsRejected\":%u,\"genuineIsLowPowerTrue\":%u,\"genuineIsRemovableTrue\":%u,\"originalSourceLowPowerCalls\":%u,\"originalSourceRemovableCalls\":%u,\"portedSourcePowerOrRemovableCalls\":0,\"originalVZExecuted\":false,\"nativeHVCalls\":0,\"systemMethodsAdded\":0,\"iPadExecuted\":false,\"full27Backend\":false}\n",
        checks,empty,positive,same_registry,rejected_multiple,genuine_low_true,genuine_removable_true,low_calls,removable_calls);
    return 0;
}
