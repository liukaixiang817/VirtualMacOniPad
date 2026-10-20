/* Local source-only fixture: actual Mac IOSurface and libc++ argument lifetime;
 * the original VZ framework, VM, presenter and CPU are never executed. */
#define VM27_DISPLAY_FIXTURE_V1 1
#include "vm27_genuine_display_observer_v1.mm"
#include <cstdio>
#include <cstdlib>
namespace VzCore { namespace Hardware {
struct FrameUpdate { IOSurfaceRef surface; bool hasSurface; };
}}
static unsigned checks=0,removedAccessor=0,removedPresenter=0,deletedUpdates=0;
static bool removalFails=false;
#define CHECK(x) do { ++checks; if(!(x)) {fprintf(stderr,"check %u failed: %s:%d %s\n",checks,__FILE__,__LINE__,#x);abort();} } while(0)
static void RemoveAccessor(id owner,id observer) {
    CHECK(owner!=nil && observer!=nil);++removedAccessor;
    if(removalFails)@throw [NSException exceptionWithName:@"FixtureDetachFailure" reason:@"Exact local detach failure" userInfo:nil];
}
static void RemovePresenter(id owner,id observer) {CHECK(owner!=nil && observer!=nil);++removedPresenter;}
@interface VM27GenuineDisplayObserverV1 (LocalFixtureOnlyV1)
- (instancetype)initLocalFixtureWithVM:(id)vm consumer:(void (^)(IOSurfaceRef,uint64_t))consumer;
- (BOOL)localRetainedFailure;
@end
@implementation VM27GenuineDisplayObserverV1 (LocalFixtureOnlyV1)
- (instancetype)initLocalFixtureWithVM:(id)vm consumer:(void (^)(IOSurfaceRef,uint64_t))consumer {
    if(!(self=[super init]))return nil;
    _vm=vm;_accessor=[NSObject new];_presenter=[NSObject new];
    _consumer=[consumer copy];_failure=^(NSError *){};
    _functions.removeAccessorObserver=RemoveAccessor;_functions.removePresenterObserver=RemovePresenter;
    _accessorQueue=dispatch_queue_create("fixture.real-serial-accessor",DISPATCH_QUEUE_SERIAL);
    _presenterQueue=dispatch_queue_create("fixture.real-serial-presenter",DISPATCH_QUEUE_SERIAL);
    _bridgeQueue=dispatch_queue_create("fixture.real-serial-bridge",DISPATCH_QUEUE_SERIAL);
    _accessorAttached=YES;_presenterAttached=YES;_closed.store(false);_sequence.store(0);
    return self;
}
- (BOOL)localRetainedFailure {return _retainedFailure==self;}
@end
static std::shared_ptr<const VzCore::Hardware::FrameUpdate> Update(IOSurfaceRef surface,bool has) {
    auto *p=new VzCore::Hardware::FrameUpdate{surface,has};
    return {p,[](const VzCore::Hardware::FrameUpdate *v){++deletedUpdates;delete v;}};
}
int main(int argc,char **argv) { @autoreleasepool {
    size_t row=IOSurfaceAlignProperty(kIOSurfaceBytesPerRow,8);
    size_t allocation=IOSurfaceAlignProperty(kIOSurfaceAllocSize,row*2);
    NSDictionary *properties=@{(id)kIOSurfaceWidth:@2,(id)kIOSurfaceHeight:@2,
        (id)kIOSurfaceBytesPerRow:@(row),(id)kIOSurfaceAllocSize:@(allocation),(id)kIOSurfaceBytesPerElement:@4,
        (id)kIOSurfacePixelFormat:@(UINT32_C(0x42475241))};
    BOOL requestSurface=argc==2 && !strcmp(argv[1],"--actual-mac-surface");
    fprintf(stderr,"fixture stage=begin actualSurfaceRequested=%d\n",requestSurface);
    IOSurfaceRef surface=requestSurface?IOSurfaceCreate((__bridge CFDictionaryRef)properties):NULL;
    if(requestSurface)CHECK(surface!=NULL);
    if(surface)CHECK(CFGetTypeID(surface)==IOSurfaceGetTypeID());
    Method m=class_getInstanceMethod(VM27GenuineDisplayObserverV1.class,@selector(presenter:didUpdateFrame:));
    CHECK(m!=NULL);
    CHECK(!strcmp(method_getTypeEncoding(m),"v40@0:8@16{shared_ptr<const VzCore::Hardware::FrameUpdate>=^{FrameUpdate}^{__shared_weak_count}}24"));
    NSError *error=nil;CHECK(!VM27GenuineDisplayProfileAvailableV1([NSObject new],&error));CHECK(error!=nil);
    __block unsigned consumed=0;__block uint64_t previous=0;
    VM27GenuineDisplayObserverV1 *observer=[[VM27GenuineDisplayObserverV1 alloc]
        initLocalFixtureWithVM:[NSObject new] consumer:^(IOSurfaceRef actual,uint64_t sequence){
            CHECK(NSThread.isMainThread);CHECK(actual==surface);CHECK(sequence==previous+1);
            previous=sequence;++consumed;
        }];
    auto frame=Update(surface,true);auto empty=Update(surface,false);auto noSurface=Update(NULL,true);
    [observer presenter:nil didUpdateFrame:empty];[observer presenter:nil didUpdateFrame:noSurface];
    for(unsigned i=0;i<3;++i)[observer presenter:nil didUpdateFrame:frame];
    CHECK(consumed==0);if(surface)CHECK(IOSurfaceGetUseCount(surface)==3);
    dispatch_async(dispatch_get_main_queue(),^{
        CHECK(consumed==(surface?3u:0u));if(surface)CHECK(IOSurfaceGetUseCount(surface)==0);
        [observer closeWithCompletion:^(NSError *e){
            CHECK(e==nil);CHECK(removedAccessor==1);CHECK(removedPresenter==1);
            [observer presenter:nil didUpdateFrame:Update(surface,true)];
            CHECK(consumed==(surface?3u:0u));if(surface)CHECK(IOSurfaceGetUseCount(surface)==0);
            removalFails=true;NSObject *vm=[NSObject new];__weak NSObject *weakVM=vm;
            VM27GenuineDisplayObserverV1 *failed=[[VM27GenuineDisplayObserverV1 alloc]
                initLocalFixtureWithVM:vm consumer:^(IOSurfaceRef,uint64_t){}];vm=nil;
            [failed closeWithCompletion:^(NSError *actualError){
                CHECK(actualError!=nil);CHECK([failed localRetainedFailure]);CHECK(weakVM!=nil);
                CHECK(removedAccessor==2 && removedPresenter==1);
                removalFails=false;
                [failed closeWithCompletion:^(NSError *retryError){
                    CHECK(retryError==nil);CHECK(![failed localRetainedFailure]);CHECK(weakVM==nil);
                    CHECK(removedAccessor==3 && removedPresenter==2);CHECK(deletedUpdates>=1);
                    if(surface)CFRelease(surface);
                    printf("{\"passed\":true,\"checks\":%u,\"actualMacIOSurface\":%s,\"originalVZExecuted\":false,\"deviceOperations\":0}\n",checks,surface?"true":"false");
                    exit(0);
                }];
            }];
        }];
    });
    /* The source uses the actual dispatch main queue; no synthetic NSThread
     * executor stands in for that queue. */
    CFRunLoopRun();
    return 2;
} }
