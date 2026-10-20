/* Actual own ObjC metadata checks only. No VZ class or Protocol is invented,
 * no native VM is created, and no TCP/VSOCK listener is opened. */
/* Including an implementation solely to exercise its private validators makes
 * Clang apply header-only nullability completeness warnings to inherited
 * private implementation declarations. Production is compiled separately with
 * all warnings as errors; this fixture changes no public nullability ABI. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
#import "vm27_genuine_vz_ssh_bridge_v2.m"
#pragma clang diagnostic pop
#include <stdio.h>

@interface VM27SSHABISetterFixture : NSObject
- (void)setDelegate:(id)value;
@end
@implementation VM27SSHABISetterFixture
- (void)setDelegate:(id)value { (void)value; }
@end
@interface VM27SSHABIBadSetterFixture : NSObject
- (BOOL)setDelegate:(id)value;
@end
@implementation VM27SSHABIBadSetterFixture
- (BOOL)setDelegate:(id)value { (void)value; return NO; }
@end
@interface VM27SSHABIBadReturnFixture : NSObject
- (id)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(id)device;
@end
@implementation VM27SSHABIBadReturnFixture
- (id)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(id)device {
    (void)listener; (void)connection; (void)device; return nil;
}
@end
@interface VM27SSHABIBadArgumentFixture : NSObject
- (BOOL)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(int)device;
@end
@implementation VM27SSHABIBadArgumentFixture
- (BOOL)listener:(id)listener shouldAcceptNewConnection:(id)connection fromSocketDevice:(int)device {
    (void)listener; (void)connection; (void)device; return NO;
}
@end

int main(void) {
    @autoreleasepool {
        BOOL facts[]={VM27VZSSHDelegateMethodABIV2([VM27GenuineVZSSHBridgeV1 class]),
            !VM27VZSSHDelegateMethodABIV2(Nil),
            !VM27VZSSHDelegateMethodABIV2([NSObject class]),
            !VM27VZSSHDelegateMethodABIV2([VM27SSHABIBadReturnFixture class]),
            !VM27VZSSHDelegateMethodABIV2([VM27SSHABIBadArgumentFixture class]),
            VM27VZSSHListenerSetterABIV2([VM27SSHABISetterFixture class]),
            !VM27VZSSHListenerSetterABIV2([VM27SSHABIBadSetterFixture class]),
            !VM27VZSSHListenerSetterABIV2(Nil)};
        for (unsigned i=0;i<sizeof(facts)/sizeof(facts[0]);++i) {
            if(!facts[i]) {fprintf(stderr,"actualOwnMetadataCheck=%u failed\n",i); return 1;}
        }
        Method method=class_getInstanceMethod([VM27GenuineVZSSHBridgeV1 class],
            @selector(listener:shouldAcceptNewConnection:fromSocketDevice:));
        printf("actualOwnObjCMetadataChecks=8 callbackEncoding=%s originalVZRuntimeTested=0 listenersOpened=0\n",
            method_getTypeEncoding(method));
    }
    return 0;
}
