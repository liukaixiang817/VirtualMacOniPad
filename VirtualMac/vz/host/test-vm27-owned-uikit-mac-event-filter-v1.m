#import "vm27_owned_uikit_mac_event_filter_v1.h"
#import <objc/runtime.h>
#include <stdio.h>
#include <string.h>
static BOOL available=YES;
BOOL VM27MacEventFilterFixtureProfileV1(void) {return available;}
static unsigned checks;
static void require(BOOL value) {if(!value)__builtin_trap();++checks;}
static void rejects(void (^call)(void)) {
    BOOL rejected=NO;
    @try {call();} @catch(NSException *error) {rejected=[error.name isEqualToString:@"VM27OwnedUIKitMacEventFilterUnavailable"];}
    require(rejected);
}
int main(void) {@autoreleasepool {
    Class cls=VM27OwnedUIKitMacEventFilterV1.class;
    require(![cls isEnabled]);require(![cls hasEventTranslators]);
    require(!strcmp(method_getTypeEncoding(class_getClassMethod(cls,@selector(isEnabled))),"B16@0:8"));
    require(!strcmp(method_getTypeEncoding(class_getClassMethod(cls,@selector(hasEventTranslators))),"B16@0:8"));
    require(!strcmp(method_getTypeEncoding(class_getInstanceMethod(cls,@selector(getHIDReportsFromHIDEvent:))),"@24@0:8^{__IOHIDEvent=}16"));
    require(!strcmp(method_getTypeEncoding(class_getInstanceMethod(cls,@selector(getHIDReportsFromNSEvent:))),"@24@0:8@16"));
    require(!strcmp(method_getTypeEncoding(class_getInstanceMethod(cls,@selector(updateCoordinateTransform:isFlipped:))),"v52@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16B48"));
    VM27OwnedUIKitMacEventFilterV1 *object=[[cls alloc] init];require(object!=nil);
    rejects(^{(void)[object getHIDReportsFromHIDEvent:NULL];});
    rejects(^{(void)[object getHIDReportsFromNSEvent:[NSObject new]];});
    rejects(^{[object updateCoordinateTransform:CGRectZero isFlipped:YES];});
    available=NO;rejects(^{(void)[cls isEnabled];});rejects(^{(void)[cls hasEventTranslators];});
    rejects(^{(void)[[cls alloc] init];});rejects(^{(void)[object getHIDReportsFromNSEvent:nil];});
    printf("owned UIKit Mac-event filter: %u finite checks passed; no guest execution\n",checks);
}return 0;}
