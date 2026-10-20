#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>

extern int vm27_metal_device_array_profile_matches(void);
extern NSArray *vm27_metal_owned_device_array(id) __attribute__((ns_returns_retained));
extern NSArray<id<MTLDevice>> *VM27MetalDeviceArrayFixture(void) __attribute__((ns_returns_retained));
static unsigned checks, deallocations;
static void need(int value, const char *why) {
    ++checks;
    if (!value) { fprintf(stderr,"FAIL: %s\n",why); exit(2); }
}
@interface VM27ArrayLifetimeObject : NSObject
@end
@implementation VM27ArrayLifetimeObject
- (void)dealloc { ++deallocations; [super dealloc]; }
@end

int main(void) {
#ifdef VM27_METAL_PRODUCTION_REJECTION_FIXTURE
    for (unsigned i=0; i<64; ++i) {
        need(!vm27_metal_device_array_profile_matches(), "production Metal UUID rejects actual different Mac");
        need(VM27MetalDeviceArrayFixture()==nil, "no array on unsupported genuine host UUID");
    }
    printf("{\"checks\":%u,\"productionProfileRejectedOnRealDifferentMac\":true,\"nativeDeviceCallsMade\":0,\"deviceOperations\":0}\n",checks);
#else
    need(vm27_metal_device_array_profile_matches(), "genuine Mac Metal UUID");
    unsigned default_calls=0, original_arrays=0, candidate_arrays=0, empty_arrays=0;
    unsigned real_nil_defaults=0, real_non_nil_defaults=0, original_catalog_devices=0;
    unsigned actual_selectors=0;
    unsigned initial=deallocations;
    for (unsigned i=0; i<1024; ++i) {
        NSArray *owned=nil;
        @autoreleasepool {
            id object=[[VM27ArrayLifetimeObject alloc] init];
            owned=vm27_metal_owned_device_array(object);
            need([owned isKindOfClass:[NSArray class]], "real owned NSArray");
            need([owned count]==1 && [owned objectAtIndex:0]==object, "same borrowed input object retained");
            [object release];
            need(deallocations==initial+i, "array retains object after caller release");
        }
        need([owned count]==1, "owned array survives autorelease-pool drain");
        id selected=[[owned objectAtIndex:0] retain];
        [owned release];
        need(deallocations==initial+i, "selected object survives owned array release");
        [selected release];
        need(deallocations==initial+i+1, "final selected ownership release exactly once");
        @autoreleasepool {
            NSArray *empty=vm27_metal_owned_device_array(nil);
            need(empty!=nil && [empty count]==0, "real empty owned NSArray branch");
            [empty release]; ++empty_arrays;
        }
    }
    for (unsigned i=0; i<512; ++i) {
        @autoreleasepool {
            id<MTLDevice> native=MTLCreateSystemDefaultDevice(); ++default_calls;
            NSArray<id<MTLDevice>> *original=MTLCopyAllDevices(); ++original_arrays;
            need(original!=nil, "genuine original27 owned catalog collection");
            original_catalog_devices+=(unsigned)[original count];
            NSArray<id<MTLDevice>> *candidate=VM27MetalDeviceArrayFixture(); ++candidate_arrays;
            need(candidate!=nil, "finite iOS contract always returns owned NSArray on supported UUID");
            if (native==nil) {
                ++real_nil_defaults;
                need([candidate count]==0, "real nil native default maps to owned empty array");
                [candidate release]; [original release];
                continue;
            }
            ++real_non_nil_defaults;
            need([candidate count]==1, "finite iOS contract returns one native default device");
            id<MTLDevice> borrowed=[candidate objectAtIndex:0];
            need([borrowed registryID]==[native registryID], "same genuine system default registry identity");
            BOOL found=NO;
            for (id<MTLDevice> actual in original) if ([actual registryID]==[native registryID]) found=YES;
            need(found, "genuine original27 catalog contains system default device");
            need([borrowed respondsToSelector:@selector(isLowPower)] &&
                 [borrowed respondsToSelector:@selector(isRemovable)], "actual Mac consumer selectors present");
            ++actual_selectors;
            id<MTLDevice> selected=[borrowed retain];
            [candidate release];
            need([selected registryID]==[native registryID], "device remains alive after owned candidate array release");
            [original release];
            need([selected registryID]==[native registryID], "device remains alive after genuine original catalog release");
            [selected release]; [native release];
        }
    }
    need(deallocations==1024, "all actual lifetime objects deallocated");
    printf("{\"checks\":%u,\"nativeDefaultCalls\":%u,\"genuineOriginalCatalogArrays\":%u,\"candidateOwnedArrays\":%u,\"actualLifetimeObjectsDeallocated\":%u,\"realEmptyOwnedArrays\":%u,\"realNilNativeDefaults\":%u,\"realNonNilNativeDefaults\":%u,\"genuineOriginalCatalogDeviceCountTotal\":%u,\"actualMacConsumerSelectorObjectsValidated\":%u,\"originalEntireMacMultiGPUCatalogEquivalent\":false,\"actualIPadConsumerSelectorsValidated\":false,\"deviceOperations\":0}\n",
        checks,default_calls,original_arrays,candidate_arrays,deallocations,empty_arrays,
        real_nil_defaults,real_non_nil_defaults,original_catalog_devices,actual_selectors);
#endif
    return 0;
}
