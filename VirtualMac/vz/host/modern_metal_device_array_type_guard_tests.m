// Synthetic own NSObject classes test the ordinary leaf's typed-call guards.
// These objects are not fake native GPU objects and no system method is changed.
#define main vm27_unused_native_gpu_fixture_entry
#include "modern_metal_device_array_ipad_fixture.m"
#undef main
#include <stdlib.h>
static unsigned bool_calls,char_calls,wrong_calls;
@interface VM27GuardBool : NSObject
- (BOOL)isLowPower;
- (uint64_t)registryID;
@end
@implementation VM27GuardBool
- (BOOL)isLowPower { ++bool_calls;return NO; }
- (uint64_t)registryID { return UINT64_C(0xfedcba9876543210); }
@end
@interface VM27GuardChar : NSObject
- (signed char)isLowPower;
@end
@implementation VM27GuardChar
- (signed char)isLowPower { ++char_calls;return -1; }
@end
@interface VM27GuardWrongReturn : NSObject
- (uint64_t)isLowPower;
@end
@implementation VM27GuardWrongReturn
- (uint64_t)isLowPower { ++wrong_calls;return 1; }
@end
@interface VM27GuardWrongArity : VM27GuardBool
@end
@implementation VM27GuardWrongArity
- (NSMethodSignature *)methodSignatureForSelector:(SEL)s {
    if (s==sel_registerName("isLowPower")) return [NSMethodSignature signatureWithObjCTypes:"B@:i"];
    return [super methodSignatureForSelector:s];
}
@end
@interface VM27GuardWrongSelfType : VM27GuardBool
@end
@implementation VM27GuardWrongSelfType
- (NSMethodSignature *)methodSignatureForSelector:(SEL)s {
    if (s==sel_registerName("isLowPower")) return [NSMethodSignature signatureWithObjCTypes:"Bq:"];
    return [super methodSignatureForSelector:s];
}
@end
int main(void) {
    SEL low=sel_registerName("isLowPower");
    for (unsigned index=0;index<1024;++index) {
        @autoreleasepool {
            id objects[] = {[[VM27GuardBool alloc]init],[[VM27GuardChar alloc]init],
                [[VM27GuardWrongReturn alloc]init],[[VM27GuardWrongArity alloc]init],
                [[VM27GuardWrongSelfType alloc]init],[[NSObject alloc]init]};
            for (unsigned i=0;i<6;++i) {
                BOOL value=YES;int responds=0;
                int valid=bool_getter(objects[i],low,&value,&responds);
                need(responds==(i!=5));need(valid==(i<2));
                if(i<2)need(value==(i==1));
                uint64_t identity=0;int typed=registry_identity(objects[i],&identity);
                need(typed==(i==0||i==3||i==4));
                if(typed)need(identity==UINT64_C(0xfedcba9876543210));
                [objects[i]release];
            }
        }
    }
    need(bool_calls==1024);need(char_calls==1024);need(wrong_calls==0);
    printf("{\"checks\":%u,\"failures\":%u,\"ownSyntheticObjects\":6144,\"actualBOOLCalls\":%u,\"actualSignedCharCalls\":%u,\"wrongTypeCalls\":%u,\"nativeGPUCalls\":0,\"systemMethodsAdded\":0,\"deviceOperations\":0}\n",checks,failures,bool_calls,char_calls,wrong_calls);
    return failures?2:0;
}
