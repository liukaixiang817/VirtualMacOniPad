// Host-only fixtures exercise the actual guard; they do not simulate device
// gesture delivery or claim that a physical three-finger swipe was tested.
#import <Foundation/Foundation.h>
#import "VM27GestureGuard_v1.m"
#include <assert.h>
static BOOL lockedFixture;
static NSString *frontFixture;
static unsigned originalCalls;
@interface SBLockScreenManager:NSObject
@end
@implementation SBLockScreenManager
+ (id)sharedInstance {static id v; if(!v)v=[self new];return v;}
- (BOOL)isUILocked {return lockedFixture;}
@end
@interface VM27FakeApplication:NSObject
@end
@implementation VM27FakeApplication
- (NSString *)bundleIdentifier{return frontFixture;}
@end
@interface UIApplication:NSObject
@end
@implementation UIApplication
+ (id)sharedApplication{static id v;if(!v)v=[self new];return v;}
- (id)_accessibilityFrontMostApplication{return [[[VM27FakeApplication alloc]init]autorelease];}
@end
@interface SBSystemGestureManager:NSObject
@end
@implementation SBSystemGestureManager
- (BOOL)shouldEnableSystemGestureWithType:(unsigned long long)t {(void)t;++originalCalls;return YES;}
@end
@interface SBFluidSwitcherGestureManager:NSObject
@end
@implementation SBFluidSwitcherGestureManager
- (BOOL)gestureRecognizerShouldBegin:(id)g{(void)g;++originalCalls;return YES;}
- (BOOL)gestureRecognizer:(id)g shouldReceiveTouch:(id)t{(void)g;(void)t;++originalCalls;return YES;}
@end
int main(void){@autoreleasepool{
 char path[]="/private/tmp/vm27-gesture-fixture-XXXXXX";int fd=mkstemp(path);assert(fd>=0);marker=path;
 char pid[24];int n=snprintf(pid,sizeof(pid),"%d\n",getpid());assert(write(fd,pid,n)==n);close(fd);
 settings=[@{@"SystemGestureSuppression":@YES,@"MultitaskingGestureSuppression":@YES}copy];
 frontFixture=@"com.mac.virtual.independent27";
 assert(install("SBSystemGestureManager","shouldEnableSystemGestureWithType:",(IMP)systemGesture,&systemPublic,"Q"));
 assert(install("SBFluidSwitcherGestureManager","gestureRecognizerShouldBegin:",(IMP)beginGesture,&fluidBegin,"@"));
 assert(install("SBFluidSwitcherGestureManager","gestureRecognizer:shouldReceiveTouch:",(IMP)touchGesture,&fluidTouch,"@@"));
 SBSystemGestureManager *sys=[SBSystemGestureManager new];SBFluidSwitcherGestureManager *fluid=[SBFluidSwitcherGestureManager new];
 assert([sys shouldEnableSystemGestureWithType:1]);ready=YES;
 assert(![sys shouldEnableSystemGestureWithType:1]);assert(![fluid gestureRecognizerShouldBegin:nil]);assert(![fluid gestureRecognizer:nil shouldReceiveTouch:nil]);
 lockedFixture=YES;assert([sys shouldEnableSystemGestureWithType:1]);assert([fluid gestureRecognizerShouldBegin:nil]);lockedFixture=NO;
 frontFixture=@"com.apple.mobilesafari";assert([sys shouldEnableSystemGestureWithType:1]);frontFixture=@"com.mac.virtual";assert([fluid gestureRecognizerShouldBegin:nil]);frontFixture=@"com.mac.virtual.independent27";
 [settings release];settings=[@{@"SystemGestureSuppression":@NO,@"MultitaskingGestureSuppression":@YES}copy];assert([sys shouldEnableSystemGestureWithType:1]);assert(![fluid gestureRecognizerShouldBegin:nil]);
 unlink(marker);assert([fluid gestureRecognizerShouldBegin:nil]);
 assert(originalCalls==7);[sys release];[fluid release];
 puts("PASS: native fallback, foreground identity, lock, startup, independent switches, marker lifetime; host fixtures only");
}return 0;}
