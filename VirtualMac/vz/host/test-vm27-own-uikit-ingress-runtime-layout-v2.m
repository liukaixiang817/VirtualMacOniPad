#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error This real-runtime layout fixture must not enter iOS products.
#endif
/* Own classes reproduce the independently decoded field types. They are
 * runtime ABI models, never substitutes for original VZ classes or identities. */
@interface VM27LayoutKeyV2 : NSObject { uint16_t _keyCode; int64_t _type; } @end
@implementation VM27LayoutKeyV2 @end
@interface VM27LayoutPointerValueV2 : NSObject { int64_t _pressedButtons; CGPoint _location; } @end
@implementation VM27LayoutPointerValueV2 @end
@interface VM27LayoutKeyboardV2 : NSObject { id _eventSender; uint32_t _deviceIdentifier; int64_t _type; uint64_t _activeIndicators; } @end
@implementation VM27LayoutKeyboardV2 @end
@interface VM27LayoutUSBKeyboardV2 : VM27LayoutKeyboardV2 { id _configuration; } @end
@implementation VM27LayoutUSBKeyboardV2 @end
@interface VM27LayoutPointingV2 : NSObject { id _eventSender; uint64_t _pointingDeviceIndex; int64_t _type; } @end
@implementation VM27LayoutPointingV2 @end
@interface VM27LayoutScreenPointingV2 : VM27LayoutPointingV2 { uint32_t _pressedButtons; } @end
@implementation VM27LayoutScreenPointingV2 @end
@interface VM27LayoutScrollV2 : NSObject { double _scrollingDeltaX, _scrollingDeltaY, _acceleratedScrollingDeltaX, _acceleratedScrollingDeltaY; uint64_t _scrollPhase, _momentumPhase; } @end
@implementation VM27LayoutScrollV2 @end
static unsigned checks;
static void Need(BOOL actual,const char *label) {
    ++checks; if(!actual) {fprintf(stderr,"layout failure: %s\n",label);exit(1);}
}
static void CheckSizeV2(Class cls,size_t value) {Need(class_getInstanceSize(cls)==value,class_getName(cls));}
static void CheckOffsetV2(Class cls,const char *name,ptrdiff_t value) {
    Ivar ivar=class_getInstanceVariable(cls,name);Need(ivar && ivar_getOffset(ivar)==value,name);
}
int main(void) {@autoreleasepool {
    Need(sizeof(void *)==8,"LP64");CheckSizeV2(NSObject.class,8);
    CheckSizeV2(VM27LayoutKeyV2.class,24);CheckOffsetV2(VM27LayoutKeyV2.class,"_keyCode",8);CheckOffsetV2(VM27LayoutKeyV2.class,"_type",16);
    CheckSizeV2(VM27LayoutPointerValueV2.class,32);CheckOffsetV2(VM27LayoutPointerValueV2.class,"_pressedButtons",8);CheckOffsetV2(VM27LayoutPointerValueV2.class,"_location",16);
    CheckSizeV2(VM27LayoutKeyboardV2.class,40);CheckOffsetV2(VM27LayoutKeyboardV2.class,"_eventSender",8);CheckOffsetV2(VM27LayoutKeyboardV2.class,"_deviceIdentifier",16);CheckOffsetV2(VM27LayoutKeyboardV2.class,"_type",24);CheckOffsetV2(VM27LayoutKeyboardV2.class,"_activeIndicators",32);
    CheckSizeV2(VM27LayoutUSBKeyboardV2.class,48);CheckOffsetV2(VM27LayoutUSBKeyboardV2.class,"_configuration",40);Need(class_getSuperclass(VM27LayoutUSBKeyboardV2.class)==VM27LayoutKeyboardV2.class,"USB super");
    CheckSizeV2(VM27LayoutPointingV2.class,32);CheckOffsetV2(VM27LayoutPointingV2.class,"_eventSender",8);CheckOffsetV2(VM27LayoutPointingV2.class,"_pointingDeviceIndex",16);CheckOffsetV2(VM27LayoutPointingV2.class,"_type",24);
    CheckSizeV2(VM27LayoutScreenPointingV2.class,40);CheckOffsetV2(VM27LayoutScreenPointingV2.class,"_pressedButtons",32);Need(class_getInstanceSize(VM27LayoutScreenPointingV2.class)!=36,"raw36 cannot match runtime40");Need(class_getSuperclass(VM27LayoutScreenPointingV2.class)==VM27LayoutPointingV2.class,"screen super");
    CheckSizeV2(VM27LayoutScrollV2.class,56);CheckOffsetV2(VM27LayoutScrollV2.class,"_scrollingDeltaX",8);CheckOffsetV2(VM27LayoutScrollV2.class,"_scrollingDeltaY",16);CheckOffsetV2(VM27LayoutScrollV2.class,"_acceleratedScrollingDeltaX",24);CheckOffsetV2(VM27LayoutScrollV2.class,"_acceleratedScrollingDeltaY",32);CheckOffsetV2(VM27LayoutScrollV2.class,"_scrollPhase",40);CheckOffsetV2(VM27LayoutScrollV2.class,"_momentumPhase",48);
    printf("{\"checks\":%u,\"realMacObjectiveCRuntimeLayout\":true,\"originalVZExecuted\":false,\"screenPointingRawEnd\":36,\"screenPointingRuntimeSize\":40}\n",checks);return 0;
}}
