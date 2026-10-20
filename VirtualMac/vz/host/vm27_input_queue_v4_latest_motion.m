#import "vm27_input_queue_v3.h"
#import "vm27_own_uikit_ingress_profile_v1.h"
#import "vm27_genuine_display_observer_v1.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#if !__has_feature(objc_arc)
#error Genuine input queue requires ARC.
#endif
@protocol VM27ActualInputVMV3 <NSObject>
- (dispatch_queue_t)queue;
- (NSInteger)state;
- (NSArray *)_keyboards;
- (NSArray *)_pointingDevices;
@end
static NSError *InputQueueErrorV3(NSString *reason) {
 return [NSError errorWithDomain:@"VirtualMac.ActualInputQueueV3" code:1
  userInfo:@{NSLocalizedDescriptionKey:reason}];
}
@interface VM27InputQueueV3 () <VM27CopiedInputSinkV2>
- (nullable instancetype)initActualVM:(id)vm pointing:(id)pointing keyboard:(id)keyboard
 surface:(VM27UIKitInputSurfaceV2 *)surface epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates
 error:(NSError **)error;
- (void)beginCloseOnActualQueue;
- (void)finishCloseOnActualQueue;
@end
@implementation VM27InputQueueV3 {
 id<VM27ActualInputVMV3> _vm;
 id _pointing,_keyboard;
 VM27UIKitInputSurfaceV2 *_surface;
 VM27OwnUIKitIngressProfileV1 *_profile;
 VM27UIKitInputSessionV2 *_session;
 VM27InputQueueV3 *_lifetimeLease;
 dispatch_queue_t _queue;
 dispatch_source_t _pump;
 void *_queueKey;
 pid_t _pid;
 uint64_t _epoch,_coordinates;
 BOOL _admitted,_closing,_profileClosed,_cancelDrained,_finished;
 VM27InputResult _lastDeliveryResult,_cleanupResult;
 NSMutableArray<void (^)(VM27InputResult)> *_completions;
}
- (BOOL)actualIdentity:(BOOL)requireExecuting {
 if(_pid!=getpid() || !_queueKey || !_vm || _finished ||
  _queue!=dispatch_get_main_queue() || [_vm queue]!=_queue ||
  dispatch_queue_get_specific(_queue,_queueKey)!=(__bridge void *)self)return NO;
 if(requireExecuting && dispatch_get_specific(_queueKey)!=(__bridge void *)self)return NO;
 return YES;
}
- (BOOL)actualDevicesBelongToVM {
 NSArray *keyboards=[_vm _keyboards],*pointing=[_vm _pointingDevices];
 return [keyboards isKindOfClass:NSArray.class] && [pointing isKindOfClass:NSArray.class] &&
  [keyboards indexOfObjectIdenticalTo:_keyboard]!=NSNotFound &&
  [pointing indexOfObjectIdenticalTo:_pointing]!=NSNotFound &&
  [VM27OwnUIKitIngressProfileV1 genuine27PointingAndKeyboardProfileMatches:_pointing keyboard:_keyboard];
}
- (instancetype)initActualVM:(id)vm pointing:(id)pointing keyboard:(id)keyboard
 surface:(VM27UIKitInputSurfaceV2 *)surface epoch:(uint64_t)epoch coordinates:(uint64_t)coordinates error:(NSError **)error {
 if(!pthread_main_np() || !vm || !surface || !epoch || !coordinates ||
  ![surface.window isKindOfClass:VM27UIKitInputWindowV2.class] ||
  !VM27GenuineDisplayProfileAvailableV1(vm,error))return nil;
 if(![vm respondsToSelector:@selector(queue)] || ![vm respondsToSelector:@selector(state)] ||
  ![vm respondsToSelector:@selector(_keyboards)] || ![vm respondsToSelector:@selector(_pointingDevices)]) {
  if(error)*error=InputQueueErrorV3(@"Actual VZ27 VM input/control selectors are unavailable.");return nil;
 }
 self=[super init];if(!self)return nil;
 _vm=vm;_pointing=pointing;_keyboard=keyboard;_surface=surface;
 _queue=[_vm queue];_pid=getpid();_epoch=epoch;_coordinates=coordinates;
 _lastDeliveryResult=VM27InputEmpty;_cleanupResult=VM27InputOK;
 _completions=[NSMutableArray array];
 if(_queue!=dispatch_get_main_queue() || ![self actualDevicesBelongToVM]) {
  if(error)*error=InputQueueErrorV3(@"Input devices do not belong to the actual VZ27 VM main queue.");return nil;
 }
 CGRect b=surface.bounds;
 _profile=[[VM27OwnUIKitIngressProfileV1 alloc] initWithPointingDevice:pointing keyboard:keyboard
  consumerThread:NSThread.mainThread epoch:epoch coordinates:coordinates
  viewport:(VM27InputViewportV1){b.origin.x,b.origin.y,b.size.width,b.size.height}];
 if(!_profile)return nil;
 _queueKey=malloc(1);if(!_queueKey)return nil;
 dispatch_queue_set_specific(_queue,_queueKey,(__bridge void *)self,NULL);
 /* The VM is held until actual close/drain completes, including a failed
  * original sender cleanup. This cannot silently deallocate an active VM. */
 _lifetimeLease=self;
 return self;
}
- (BOOL)startAdmission:(NSError **)error {
 if(!pthread_main_np() || _closing || _admitted || ![self actualIdentity:YES]) {
  if(error)*error=InputQueueErrorV3(@"Input admission requires execution on the actual VM serial queue.");return NO;
 }
 @try {
  /* Current macOS27 SDK VZVirtualMachineStateRunning is the genuine value1.
   * No copied backend flag substitutes for the actual VM state getter. */
  if([_vm state]!=1 || ![self actualDevicesBelongToVM]) {
   if(error)*error=InputQueueErrorV3(@"The actual VM is not running with its original input devices.");return NO;
  }
  _session=[_surface activateWithSink:self epoch:_epoch coordinateGeneration:_coordinates capacity:128];
  if(!_session){if(error)*error=InputQueueErrorV3(@"Actual UIKit copied packet admission could not be established.");return NO;}
  _admitted=YES;
  _pump=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,_queue);
  if(!_pump){[self beginCloseOnActualQueue];return NO;}
  __weak VM27InputQueueV3 *weakSelf=self;
  dispatch_source_set_event_handler(_pump,^{
   VM27InputQueueV3 *owner=weakSelf;if(!owner || owner->_closing)return;
   if(![owner actualIdentity:YES]) {owner->_lastDeliveryResult=VM27InputUnavailable;[owner beginCloseOnActualQueue];return;}
   for(unsigned i=0;i<128 && !owner->_closing;++i) {
    VM27InputResult result=[owner->_session consumeNextCopiedPacket];owner->_lastDeliveryResult=result;
    if(result==VM27InputEmpty)break;
    if(result!=VM27InputOK && result!=VM27InputUnsupported) {[owner beginCloseOnActualQueue];break;}
   }
  });
  /* Cancellation handler executes after the source's actual serial handler
   * has drained. It is the asynchronous completion of VM input ownership. */
  dispatch_source_set_cancel_handler(_pump,^{
   VM27InputQueueV3 *owner=weakSelf;if(!owner)return;
   owner->_cancelDrained=YES;owner->_pump=nil;[owner finishCloseOnActualQueue];
  });
  /* UIKit can deliver 120 motion samples/s. Coalesce pending motion to
   * the latest position at a 60 Hz delivery cadence, preserving every edge.
   * This avoids filling the real guest HID stream with obsolete positions. */
  dispatch_source_set_timer(_pump,dispatch_time(DISPATCH_TIME_NOW,0),NSEC_PER_SEC/60,NSEC_PER_MSEC);
  dispatch_resume(_pump);return YES;
 } @catch(NSException *exception) {
  (void)exception;_lastDeliveryResult=VM27InputUnavailable;[self beginCloseOnActualQueue];
  if(error)*error=InputQueueErrorV3(@"Original VZ27 input admission raised an exception.");return NO;
 }
}
- (VM27InputResult)consumeCopiedInputPacket:(const VM27InputPacket *)packet {
 if(_closing || !_admitted)return VM27InputClosed;
 if(![self actualIdentity:YES])return VM27InputWrongThread;
 @try {
  if([_vm state]!=1 || ![self actualDevicesBelongToVM])return VM27InputUnavailable;
  return [_profile consumeCopiedInputPacket:packet];
 } @catch(NSException *exception) {(void)exception;return VM27InputUnavailable;}
}
- (VM27InputResult)lastDeliveryResult {return _lastDeliveryResult;}
- (void)finishCloseOnActualQueue {
 if(!_closing || !_cancelDrained || ![self actualIdentity:YES])return;
 if(!_profileClosed && (_cleanupResult==VM27InputOK || _cleanupResult==VM27InputClosed))
  _cleanupResult=VM27InputUnavailable;
 NSArray *callbacks=[_completions copy];[_completions removeAllObjects];
 VM27InputResult result=_cleanupResult;
 if(_profileClosed && (result==VM27InputOK || result==VM27InputClosed)) {
  dispatch_queue_set_specific(_queue,_queueKey,NULL,NULL);free(_queueKey);_queueKey=NULL;
  _finished=YES;_session=nil;_profile=nil;_surface=nil;_pointing=nil;_keyboard=nil;_vm=nil;
  _lifetimeLease=nil;
 }
 /* Failed release retains the same VM/identity and the original error. A
  * second call cannot relabel uncertain original consumption as successful. */
 for(void (^completion)(VM27InputResult) in callbacks)completion(result);
}
- (void)beginCloseOnActualQueue {
 if(_finished || _closing)return;
 if(![self actualIdentity:YES]){_cleanupResult=VM27InputWrongThread;return;}
 _closing=YES;_admitted=NO;
 VM27InputResult admission=[_surface close];
 if(admission!=VM27InputOK && admission!=VM27InputClosed)_cleanupResult=admission;
 @try {
  VM27InputResult released=[_profile closeOnConsumerThread];
  _profileClosed=[_profile hasClosedAdmissionOnConsumerThread];
  if(_cleanupResult==VM27InputOK && released!=VM27InputOK && released!=VM27InputClosed)_cleanupResult=released;
 } @catch(NSException *exception) {(void)exception;_cleanupResult=VM27InputUnavailable;}
 if(_pump)dispatch_source_cancel(_pump);
 else {_cancelDrained=YES;[self finishCloseOnActualQueue];}
}
- (VM27InputResult)close {
 if(_pid!=getpid())return VM27InputStaleEpoch;
 if(!pthread_main_np())return VM27InputWrongThread;
 if(_finished)return VM27InputClosed;
 if(![self actualIdentity:YES]) {
  dispatch_async(_queue,^{[self beginCloseOnActualQueue];});return VM27InputBusy;
 }
 [self beginCloseOnActualQueue];
 return _finished?VM27InputClosed:_cancelDrained?_cleanupResult:VM27InputBusy;
}
- (void)closeWithCompletion:(void (^)(VM27InputResult))completion {
 if(!completion)return;
 if(_pid!=getpid()){completion(VM27InputStaleEpoch);return;}
 if(!pthread_main_np()){completion(VM27InputWrongThread);return;}
 if(_finished){completion(VM27InputClosed);return;}
 dispatch_block_t close=^{
  [self->_completions addObject:[completion copy]];
  [self beginCloseOnActualQueue];
  if(self->_cancelDrained)[self finishCloseOnActualQueue];
 };
 if([self actualIdentity:YES])close();else dispatch_async(_queue,close);
}
@end
VM27InputQueueV3 *VM27ConnectGenuineInputQueueV3(id vm,id pointing,id keyboard,
 VM27UIKitInputSurfaceV2 *surface,uint64_t epoch,uint64_t coordinates,NSError **error) {
 @try {return [[VM27InputQueueV3 alloc] initActualVM:vm pointing:pointing keyboard:keyboard
  surface:surface epoch:epoch coordinates:coordinates error:error];}
 @catch(NSException *exception) {(void)exception;if(error)*error=InputQueueErrorV3(@"Actual VM input profile raised an exception.");return nil;}
}
