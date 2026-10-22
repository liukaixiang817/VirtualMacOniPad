#import "vm27_owned_native_trackpad_v1.h"
#import "modern_processed_scroll_native_v1.h"
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <objc/runtime.h>
extern uint32_t IOHIDEventGetType(CFTypeRef);
typedef void (*VM27NativeHIDCallbackV1)(void*,void*,void*,CFTypeRef);
static struct {
 CFTypeRef (*create)(CFAllocatorRef,int,CFDictionaryRef);
 CFArrayRef (*services)(CFTypeRef),(*children)(CFTypeRef);
 CFTypeRef (*property)(CFTypeRef,CFStringRef),(*registry)(CFTypeRef);
 void (*match)(CFTypeRef,CFDictionaryRef);
 uint64_t (*sender)(CFTypeRef);
 uint32_t (*type)(CFTypeRef);
 double (*floating)(CFTypeRef,uint32_t);
 CFIndex (*integer)(CFTypeRef,uint32_t);
 void (*registerEvent)(CFTypeRef,VM27NativeHIDCallbackV1,void*,void*),(*unregisterEvent)(CFTypeRef);
 void (*schedule)(CFTypeRef,CFRunLoopRef,CFStringRef),(*unschedule)(CFTypeRef,CFRunLoopRef,CFStringRef);
 BOOL ready;
} api;
static BOOL LoadNativeAPI(void) {
 static dispatch_once_t once;
 dispatch_once(&once,^{
  if(!vm27_processed_scroll_native_profile_matches())return;
  void *handle=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_NOLOAD);
  Dl_info original={0};if(!handle || !dladdr((void *)&IOHIDEventGetType,&original))return;
#define LOAD(field,name) do{void *p=dlsym(handle,name);Dl_info info={0};if(!p || !dladdr(p,&info) || info.dli_fbase!=original.dli_fbase){dlclose(handle);return;}*(void **)&api.field=p;}while(0)
  LOAD(create,"IOHIDEventSystemClientCreateWithType");LOAD(services,"IOHIDEventSystemClientCopyServices");LOAD(children,"IOHIDEventGetChildren");
  LOAD(property,"IOHIDServiceClientCopyProperty");LOAD(registry,"IOHIDServiceClientGetRegistryID");LOAD(match,"IOHIDEventSystemClientSetMatching");
  LOAD(sender,"IOHIDEventGetSenderID");LOAD(type,"IOHIDEventGetType");LOAD(floating,"IOHIDEventGetFloatValue");LOAD(integer,"IOHIDEventGetIntegerValue");
  LOAD(registerEvent,"IOHIDEventSystemClientRegisterEventCallback");LOAD(unregisterEvent,"IOHIDEventSystemClientUnregisterEventCallback");
  LOAD(schedule,"IOHIDEventSystemClientScheduleWithRunLoop");LOAD(unschedule,"IOHIDEventSystemClientUnscheduleWithRunLoop");
#undef LOAD
  api.ready=YES;dlclose(handle);
 });
 return api.ready;
}
static id Property(CFTypeRef service,NSString *key) {
 CFTypeRef object=api.property(service,(__bridge CFStringRef)key);
 return object?CFBridgingRelease(object):nil;
}
static uint64_t Registry(CFTypeRef service) {
 CFTypeRef number=api.registry(service);uint64_t value=0;
 if(!number || CFGetTypeID(number)!=CFNumberGetTypeID() || !CFNumberGetValue((CFNumberRef)number,kCFNumberSInt64Type,&value))return 0;
 return value;
}
static BOOL IsTrackpad(CFTypeRef service) {
 if(![Property(service,@"VendorID") isEqual:@1452] || ![Property(service,@"PrimaryUsagePage") isEqual:@13] ||
    ![Property(service,@"PrimaryUsage") isEqual:@12] || ![Property(service,@"Transport") isEqual:@"AID"])return NO;
 id pairs=Property(service,@"DeviceUsagePairs");
 if(![pairs isKindOfClass:NSArray.class])return NO;
 for(id row in pairs)if([row isKindOfClass:NSDictionary.class] && [row[@"DeviceUsagePage"] isEqual:@13] && [row[@"DeviceUsage"] isEqual:@5])return YES;
 return NO;
}
static BOOL Gather(CFTypeRef event,unsigned depth,unsigned *nodes,VM27NativeTrackpadContactV1 contacts[10],unsigned *count) {
 if(!event || depth>3 || ++*nodes>32 || object_getClass((__bridge id)event)!=objc_getClass("HIDEvent"))return NO;
 uint32_t type=api.type(event);if(type==3 || type==30)return YES;
 CFArrayRef children=api.children(event);CFIndex size=0;BOOL nestedDigitizer=NO;
 if(children){if(CFGetTypeID(children)!=CFArrayGetTypeID())return NO;size=CFArrayGetCount(children);if(size>16)return NO;}
 for(CFIndex i=0;i<size;++i){CFTypeRef child=CFArrayGetValueAtIndex(children,i);if(!child || object_getClass((__bridge id)child)!=objc_getClass("HIDEvent"))return NO;if(api.type(child)==11)nestedDigitizer=YES;}
 if(type==11 && !nestedDigitizer && api.integer(event,0xb0009)) {
  if(*count>=10)return NO;CFIndex identifier=api.integer(event,0xb0005);
  if(identifier<0 || (uint64_t)identifier>UINT32_MAX)return NO;
  contacts[(*count)++]=(VM27NativeTrackpadContactV1){(uint32_t)identifier,api.floating(event,0xb0000),api.floating(event,0xb0001)};
 }
 for(CFIndex i=0;i<size;++i){CFTypeRef child=CFArrayGetValueAtIndex(children,i);if(api.type(child)==11 && !Gather(child,depth+1,nodes,contacts,count))return NO;}
 return YES;
}
@class VM27OwnedNativeTrackpadV1;
@interface VM27TrackpadCallbackContextV1:NSObject
@property(nonatomic,weak) VM27OwnedNativeTrackpadV1 *owner;
@end
@implementation VM27TrackpadCallbackContextV1
@end
@interface VM27OwnedNativeTrackpadV1 ()
- (void)receive:(CFTypeRef)event;
@end
static void NativeCallback(void *target,void *refcon,void *sender,CFTypeRef event) {
 (void)refcon;(void)sender;
 VM27TrackpadCallbackContextV1 *context=(__bridge id)target;
 VM27OwnedNativeTrackpadV1 *owner=context.owner;
 if(owner)[owner receive:event];
}
@implementation VM27OwnedNativeTrackpadV1 {
 CFTypeRef _client;VM27TrackpadCallbackContextV1 *_context;
 void (^_action)(unsigned,VM27TrackpadDirectionV1);
 uint64_t _registry;pid_t _owner;double _lastAdmission;
 VM27NativeTrackpadSwipeV1 _swipe;unsigned _lastCount,_contactLogs,_actionLogs;
}
- (instancetype)initWithAction:(void (^)(unsigned,VM27TrackpadDirectionV1))action {
 if(!action)return nil;self=[super init];if(self){_action=[action copy];_owner=getpid();}return self;
}
- (BOOL)admitted {return _client && _registry && _owner==getpid() && pthread_main_np();}
- (BOOL)admitCurrentService {
 if(!_client || !pthread_main_np() || _owner!=getpid())return NO;
 CFArrayRef services=api.services(_client);uint64_t selected=0;
 if(services && CFGetTypeID(services)==CFArrayGetTypeID() && CFArrayGetCount(services)==1) {
  CFTypeRef service=CFArrayGetValueAtIndex(services,0);if(IsTrackpad(service))selected=Registry(service);
 }
 if(services)CFRelease(services);
 if(selected!=_registry){_registry=selected;VM27NativeTrackpadResetV1(&_swipe);_lastCount=0;
  fprintf(stderr,"[Independent27NativeTrackpadV1] admitted=%u registry=%llu uid=%u onlyAIDAppleTouchpad=1 eventWrites=0\n",selected!=0,(unsigned long long)selected,(unsigned)getuid());}
 return selected!=0;
}
- (BOOL)start {
 if(_owner!=getpid() || !pthread_main_np() || !LoadNativeAPI())return NO;
 if(_client)return YES;
 _client=api.create(NULL,1,NULL);if(!_client){fprintf(stderr,"[Independent27NativeTrackpadV1] monitorUnavailable=1 uid=%u\n",(unsigned)getuid());return NO;}
 api.match(_client,(__bridge CFDictionaryRef)@{@"PrimaryUsagePage":@13,@"PrimaryUsage":@12,@"VendorID":@1452,@"Transport":@"AID"});
 _context=[VM27TrackpadCallbackContextV1 new];_context.owner=self;
 [self admitCurrentService];
 api.registerEvent(_client,NativeCallback,(__bridge void *)_context,NULL);
 api.schedule(_client,CFRunLoopGetMain(),kCFRunLoopCommonModes);
 fprintf(stderr,"[Independent27NativeTrackpadV1] monitorScheduled=1 uid=%u matchingUsage=13/12 keyboardUsageExcluded=1\n",(unsigned)getuid());return YES;
}
- (void)receive:(CFTypeRef)event {
 if(_owner!=getpid() || !pthread_main_np() || !_client || !event || object_getClass((__bridge id)event)!=objc_getClass("HIDEvent"))return;
 uint32_t type=api.type(event);if(type!=11 && type!=17)return;
 uint64_t sender=api.sender(event);double now=NSProcessInfo.processInfo.systemUptime;
 if(!sender)return;
 if(sender!=_registry){if(now-_lastAdmission<1)return;_lastAdmission=now;if(![self admitCurrentService] || sender!=_registry)return;}
 VM27NativeTrackpadContactV1 contacts[10];unsigned count=0,nodes=0;
 if(!Gather(event,0,&nodes,contacts,&count)){_swipe.cancelled=true;return;}
 if(count!=_lastCount){if(count>=3 && _contactLogs++<24)fprintf(stderr,"[Independent27NativeTrackpadContactV1] fingers=%u registry=%llu copiedActualContacts=1\n",count,(unsigned long long)sender);_lastCount=count;}
 VM27TrackpadDirectionV1 direction=VM27NativeTrackpadUpdateV1(&_swipe,contacts,count,now);
 if(direction){if(_actionLogs++<32)fprintf(stderr,"[Independent27NativeTrackpadSwipeV1] fingers=%u direction=%u actualContactMotion=1\n",_swipe.count,(unsigned)direction);_action(_swipe.count,direction);}
}
- (void)stop {
 CFTypeRef client=_client;_client=NULL;_registry=0;VM27NativeTrackpadResetV1(&_swipe);
 VM27TrackpadCallbackContextV1 *context=_context;context.owner=nil;_context=nil;
 if(!client)return;
 void (^cleanup)(void)=^{api.unregisterEvent(client);api.unschedule(client,CFRunLoopGetMain(),kCFRunLoopCommonModes);CFRelease(client);context.owner=nil;};
 if(pthread_main_np())cleanup();else dispatch_async(dispatch_get_main_queue(),cleanup);
}
- (void)dealloc {[self stop];}
@end
