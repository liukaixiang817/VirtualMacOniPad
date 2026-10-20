#import "vm27_genuine_display_completion_v3.h"
#import "vm27_genuine_cursor_consumer_v1.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <CommonCrypto/CommonDigest.h>
#include <ptrauth.h>
#include <atomic>
#include <memory>
#include <cstring>
#include <exception>
#include "vm27_genuine_display_profile_v2.inc"

#include <errno.h>
#include <stdio.h>
/* Each process emits at most two lines per independent stage. Saturation,
 * rather than a wrapping fetch_add, makes that a lifetime bound. No object
 * description, payload copy, queue wait or guest/native operation is added. */
static std::atomic<unsigned> VM27ObserverStageTraceBudgetV1[12]{};
static bool VM27ObserverStageTraceReserveV1(unsigned stage) {
    if(stage>=12)return false;
    unsigned value=VM27ObserverStageTraceBudgetV1[stage].load(std::memory_order_relaxed);
    while(value<2) {
        if(VM27ObserverStageTraceBudgetV1[stage].compare_exchange_weak(value,value+1,
            std::memory_order_relaxed,std::memory_order_relaxed))return true;
    }
    return false;
}
/* Save errno before even evaluating diagnostic arguments. Each emitted line
 * is one stdio call; suppressed stages evaluate no diagnostic arguments. */
#define VM27ObserverStageTraceV1(stage, ...) do { \
    const int vm27_trace_saved_errno=errno; \
    if(VM27ObserverStageTraceReserveV1(stage))fprintf(stderr,__VA_ARGS__); \
    errno=vm27_trace_saved_errno; \
} while(0)

#if defined(VM27_DISPLAY_FIXTURE_V1) && defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error "Display fixture hooks are forbidden in device builds"
#endif
namespace VzCore { namespace Hardware { struct FrameUpdate; struct CursorUpdate;
struct HostDisplayUpdate { unsigned int display_id; int display_mode; }; }}
static_assert(sizeof(std::shared_ptr<const VzCore::Hardware::FrameUpdate>)==16,
    "Original AArch64 libc++ shared_ptr object is two words");
struct DisplayRequestV1 {
    uint32_t device,display;
    uint64_t protection;
    uint8_t hasProtection,reserved[7];
    uint32_t flags,padding;
};
static_assert(sizeof(DisplayRequestV1)==32 && offsetof(DisplayRequestV1,flags)==24,
    "Original presenter registration argument layout");
struct DisplayFunctionsV1 {
    id (*createAccessor)(id,uint64_t);
    void (*addAccessorObserver)(id,id);
    void (*removeAccessorObserver)(id,id);
    void (*addPresenterObserver)(id,const DisplayRequestV1 *,id);
    void (*removePresenterObserver)(id,id);
    void (*frameConsumed)(id,id);
};
static NSError *DisplayErrorV1(NSString *text) {
    return [NSError errorWithDomain:@"VM27GenuineDisplay" code:1
        userInfo:@{NSLocalizedDescriptionKey:text}];
}
static BOOL DisplayFailV1(NSError **out,NSString *text) {
    if(out)*out=DisplayErrorV1(text);return NO;
}
static NSError *DisplayInvokeV1(dispatch_block_t block) {
    try {
        @try {block();return nil;}
        @catch(NSException *exception) {return DisplayErrorV1(exception.reason?:@"Original display helper raised an exception.");}
    } catch(const std::exception &exception) {
        return DisplayErrorV1([NSString stringWithUTF8String:exception.what()]);
    } catch(...) {return DisplayErrorV1(@"Original display helper raised an unknown C++ exception.");}
}
/* Exceptions must be caught on the actual execution queue. Unwinding through
 * libdispatch's dispatch_sync client boundary terminates the process. */
static void DisplaySyncV1(dispatch_queue_t queue,dispatch_block_t block) {
    __block NSError *failure=nil;
    dispatch_sync(queue,^{failure=DisplayInvokeV1(block);});
    if(failure)@throw [NSException exceptionWithName:@"VM27ActualDisplayOperationFailed"
        reason:failure.localizedDescription userInfo:nil];
}
static BOOL DisplayClassV1(id object,const char *name,size_t size) {
    Class expected=objc_getClass(name);
    return object && expected && [object isKindOfClass:expected] &&
        class_getInstanceSize(expected)==size;
}
static Ivar DisplayIvarV1(Class cls,const char *name,const char *type,
    ptrdiff_t offset) {
    Ivar iv=class_getInstanceVariable(cls,name);
    return iv && ivar_getOffset(iv)==offset &&
        !strcmp(ivar_getTypeEncoding(iv),type)?iv:NULL;
}
static uintptr_t DisplayWordV1(id object,Ivar iv) {
    uintptr_t word=0;
    memcpy(&word,(const uint8_t *)(__bridge const void *)object+ivar_getOffset(iv),8);
    return word;
}
template<class T> static T DisplayFunctionV1(const uint8_t *base,size_t rva) {
    void *p=(void *)(base+rva);
#if __has_feature(ptrauth_calls)
    p=ptrauth_sign_unauthenticated(p,ptrauth_key_function_pointer,0);
#endif
    return reinterpret_cast<T>(p);
}
static BOOL DisplayResolveV1(id vm,DisplayFunctionsV1 *out,NSError **error) {
    if(![NSThread isMainThread])return DisplayFailV1(error,@"Display attachment must run on the actual VM main control queue.");
    Class vmClass=objc_getClass("VZVirtualMachine");
    if(!vmClass || class_getInstanceSize(vmClass)!=384 ||
       (vm && !DisplayClassV1(vm,"VZVirtualMachine",384)))return DisplayFailV1(error,@"An actual VZ27 virtual machine is required.");
    Method m=class_getInstanceMethod(objc_getClass("VZVirtualMachine"),sel_registerName("initWithConfiguration:queue:"));
    if(!m || strcmp(method_getTypeEncoding(m),"@32@0:8@16@24"))return DisplayFailV1(error,@"VZ27 VM queue initializer ABI differs.");
    Dl_info info={};const void *imp=(const void *)ptrauth_strip((void *)method_getImplementation(m),ptrauth_key_function_pointer);
    if(!dladdr(imp,&info) || !info.dli_fbase)return DisplayFailV1(error,@"VZ27 original method image is unavailable.");
    const uint8_t *base=(const uint8_t *)info.dli_fbase;
    const mach_header_64 *header=(const mach_header_64 *)base;
    if(header->magic!=MH_MAGIC_64 || header->sizeofcmds>1048576 || header->ncmds>4096 ||
       (const uint8_t *)imp!=base+0x14cd04)return DisplayFailV1(error,@"VZ27 method does not belong to the selected original image.");
    bool uuid=false;size_t cursor=sizeof(*header),end=cursor+header->sizeofcmds;
    for(uint32_t i=0;i<header->ncmds;++i) {
        if(cursor+sizeof(load_command)>end)return DisplayFailV1(error,@"Invalid VZ27 load-command range.");
        const load_command *lc=(const load_command *)(base+cursor);
        if(lc->cmdsize<8 || cursor+lc->cmdsize>end)return DisplayFailV1(error,@"Invalid VZ27 load-command size.");
        if(lc->cmd==LC_UUID) {
            if(lc->cmdsize!=sizeof(uuid_command) || uuid)return DisplayFailV1(error,@"Invalid VZ27 UUID command.");
            uuid=!memcmp(((const uuid_command *)lc)->uuid,VM27DisplayUUIDV1,16);
        }
        cursor+=lc->cmdsize;
    }
    if(!uuid || cursor!=end)return DisplayFailV1(error,@"VZ27 UUID is outside the frozen display profile.");
    for(const auto &p:VM27DisplayCodeProfilesV1) {
        uint8_t actual[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(base+p.rva,(CC_LONG)p.bytes,actual);
        if(memcmp(actual,p.sha256,sizeof(actual)))return DisplayFailV1(error,@"VZ27 presenter/accessor code differs from the selected source candidate.");
    }
    if(!DisplayIvarV1(vmClass,"_accessorManager","@\"_VZVirtualMachineAccessorManager\"",216))
        return DisplayFailV1(error,@"VZ27 accessor manager ownership metadata differs.");
    if(vm) {
        if(![vm respondsToSelector:sel_registerName("queue")])return DisplayFailV1(error,@"VZ27 VM has no actual control queue.");
        id queue=((id(*)(id,SEL))objc_msgSend)(vm,sel_registerName("queue"));
        if(queue!=(id)dispatch_get_main_queue())return DisplayFailV1(error,@"This UIKit profile requires the actual VM main control queue.");
    }
    *out={DisplayFunctionV1<decltype(out->createAccessor)>(base,0x12e2cc),
        DisplayFunctionV1<decltype(out->addAccessorObserver)>(base,0x11d6b0),
        DisplayFunctionV1<decltype(out->removeAccessorObserver)>(base,0x11d9b8),
        DisplayFunctionV1<decltype(out->addPresenterObserver)>(base,0x230530),
        DisplayFunctionV1<decltype(out->removePresenterObserver)>(base,0x2302b4),
        DisplayFunctionV1<decltype(out->frameConsumed)>(base,0x230440)};
    return YES;
}
BOOL VM27GenuineDisplayProfileAvailableV1(id vm,NSError **error) {
    if(!vm)return DisplayFailV1(error,@"An actual virtual machine is required.");
    DisplayFunctionsV1 functions={};return DisplayResolveV1(vm,&functions,error);
}
BOOL VM27GenuineDisplayClassProfileAvailableV1(NSError **error) {
    DisplayFunctionsV1 functions={};return DisplayResolveV1(nil,&functions,error);
}
@interface VM27GenuineDisplayObserverV1 () {
    id _vm,_display,_accessor,_presenter;
    VM27GenuineDisplayObserverV1 *_retainedFailure;
    DisplayFunctionsV1 _functions;
    DisplayRequestV1 _request;
    dispatch_queue_t _accessorQueue,_bridgeQueue,_presenterQueue;
    std::atomic<bool> _closed;
    std::atomic<uint64_t> _sequence,_emptySequence;
    id _pendingFramePresenter;
    uint64_t _pendingFrameSequence,_lastConsumedSequence,_lastEmptyConsumedSequence;
    BOOL _pendingFrameEmpty;
    void (^_emptyConsumer)(uint64_t);
    VM27GenuineCursorConsumerV1 _cursorConsumerV1;
    unsigned _cursorLogsV1;
    unsigned _cursorLatencyLogsV5;
    unsigned _completionLogs;
    BOOL _accessorAttached,_presenterAttached;
    void (^_consumer)(IOSurfaceRef,uint64_t);
    void (^_failure)(NSError *);
}
- (void)report:(NSString *)text;
- (void)markConsumedSequence:(uint64_t)sequence empty:(BOOL)empty;
@end
@implementation VM27GenuineDisplayObserverV1
- (instancetype)initWithVirtualMachine:(id)vm graphicsDisplay:(id)display
    frameConsumer:(void (^)(IOSurfaceRef,uint64_t))consumer
    failureHandler:(void (^)(NSError *))failure error:(NSError **)error {
    if(!(self=[super init]))return nil;
    if(!consumer || !failure || !DisplayResolveV1(vm,&_functions,error))return nil;
    Class dc=objc_getClass("VZGraphicsDisplay");
    if(!DisplayClassV1(display,"VZGraphicsDisplay",160)) {
        DisplayFailV1(error,@"An actual VZ27 graphics display is required.");return nil;
    }
    Ivar device=DisplayIvarV1(dc,"_graphicsDeviceIndex","Q",32);
    Ivar index=DisplayIvarV1(dc,"_framebufferIndex","Q",40);
    if(!device || !index) {DisplayFailV1(error,@"VZ27 display identity metadata differs.");return nil;}
    uint64_t d=DisplayWordV1(display,device),i=DisplayWordV1(display,index);
    if(d>UINT32_MAX || i>UINT32_MAX) {
        DisplayFailV1(error,@"The actual display identity is outside the original presenter ABI.");return nil;
    }
    id manager=object_getIvar(vm,DisplayIvarV1(object_getClass(vm),"_accessorManager","@\"_VZVirtualMachineAccessorManager\"",216));
    if(!DisplayClassV1(manager,"_VZVirtualMachineAccessorManager",256)) {
        DisplayFailV1(error,@"The actual VM has not published an accessor manager.");return nil;
    }
    NSError *creationError=DisplayInvokeV1(^{self->_accessor=self->_functions.createAccessor(manager,3);});
    if(creationError) {if(error)*error=creationError;return nil;}
    if(!DisplayClassV1(_accessor,"_VZVirtualMachineAccessor",232) ||
       ![_accessor respondsToSelector:sel_registerName("queue")]) {
        DisplayFailV1(error,@"Actual accessor creation did not supply the original accessor queue.");return nil;
    }
    _accessorQueue=(dispatch_queue_t)((id(*)(id,SEL))objc_msgSend)(_accessor,sel_registerName("queue"));
    if(!_accessorQueue) {DisplayFailV1(error,@"The actual accessor queue is unavailable.");return nil;}
    _vm=vm;_display=display;_consumer=[consumer copy];_failure=[failure copy];
    _request={uint32_t(d),uint32_t(i),0,0,{0},0x1e,0};
    _bridgeQueue=dispatch_queue_create("VM27.actual-display-bridge",DISPATCH_QUEUE_SERIAL);
    _closed.store(false);_sequence.store(0);_emptySequence.store(0);
    dispatch_async(_accessorQueue,^{
        if(self->_closed.load())return;
        self->_accessorAttached=YES;
        VM27ObserverStageTraceV1(0,"[Independent27DisplayObserverTraceV1] stage=accessor-register-begin\n");
        NSError *failure=DisplayInvokeV1(^{self->_functions.addAccessorObserver(self->_accessor,self);});
        VM27ObserverStageTraceV1(1,"[Independent27DisplayObserverTraceV1] stage=accessor-register-return errorPresent=%u\n",failure?1u:0u);
        if(failure)[self report:failure.localizedDescription];
    });
    return self;
}
- (void)report:(NSString *)text {
    NSError *error=DisplayErrorV1(text);
    dispatch_async(dispatch_get_main_queue(),^{self->_failure(error);});
}
/* This selector is the actual original accessor callback, not an invented
 * framebuffer callback. Bridge work never waits for the UIKit main queue. */
- (void)virtualMachineAccessor:(id)accessor associateWithDisplayPresenter:(id)presenter {
    VM27ObserverStageTraceV1(2,"[Independent27DisplayObserverTraceV1] stage=presenter-association accessorMatches=%u presenterPresent=%u\n",accessor==_accessor?1u:0u,presenter?1u:0u);
    if(accessor!=_accessor || _closed.load())return;
    dispatch_async(_bridgeQueue,^{
        if(self->_closed.load() || self->_presenter==presenter)return;
        VM27ObserverStageTraceV1(3,"[Independent27DisplayObserverTraceV1] stage=presenter-bridge-active presenterPresent=%u\n",presenter?1u:0u);
        @try {
            self->_pendingFrameSequence=0;self->_pendingFramePresenter=nil;
            if(self->_presenterAttached) {
                DisplaySyncV1(self->_presenterQueue,^{self->_functions.removePresenterObserver(self->_presenter,self);});
                self->_presenterAttached=NO;
            }
            self->_presenter=nil;self->_presenterQueue=nil;
            if(!presenter)return;
            Class pc=objc_getClass("_VZDisplayPresenter");
            Ivar qi=DisplayIvarV1(pc,"_queue","{DispatchQueue=\"_object\"^{OpaqueId}}",96);
            if(!DisplayClassV1(presenter,"_VZDisplayPresenter",104) || !qi) {
                [self report:@"Actual presenter ownership metadata differs."];return;
            }
            uintptr_t rawQueue=DisplayWordV1(presenter,qi);
            if(!rawQueue) {[self report:@"The actual presenter queue is unavailable."];return;}
            self->_presenter=presenter;
            self->_presenterQueue=(dispatch_queue_t)(__bridge id)(void *)rawQueue;
            DisplaySyncV1(self->_presenterQueue,^{
                self->_presenterAttached=YES;
                VM27ObserverStageTraceV1(4,"[Independent27DisplayObserverTraceV1] stage=presenter-register-begin device=%u display=%u flags=%u\n",self->_request.device,self->_request.display,self->_request.flags);
                self->_functions.addPresenterObserver(self->_presenter,&self->_request,self);
                VM27ObserverStageTraceV1(5,"[Independent27DisplayObserverTraceV1] stage=presenter-register-return\n");
            });
        } @catch(NSException *exception) {
            self->_retainedFailure=self;
            [self report:exception.reason?:@"Actual presenter reattachment failed; VM retained."];
        }
    });
}
/* Original producer passes a real nontrivial libc++ shared_ptr by value through
 * x3. The original renderer checks FrameUpdate optional engagement at +8 and
 * retains the actual IOSurface object at +0. No old FrameUpdate layout is used. */
- (void)presenter:(id)presenter didUpdateFrame:
    (std::shared_ptr<const VzCore::Hardware::FrameUpdate>)update {
    VM27ObserverStageTraceV1(6,"[Independent27DisplayObserverTraceV1] stage=frame-callback-entry updatePresent=%u\n",update?1u:0u);
    if(_closed.load() || !update)return;
    const uint8_t *bytes=(const uint8_t *)update.get();
    uint8_t engaged=0;uintptr_t raw=0;memcpy(&engaged,bytes+8,1);
    VM27ObserverStageTraceV1(7,"[Independent27DisplayObserverTraceV1] stage=frame-optional engaged=%u\n",(unsigned)engaged);
    if(engaged!=0 && engaged!=1) {[self report:@"Actual frame optional engagement is outside its original profile."];return;}
    BOOL empty=engaged==0;IOSurfaceRef surface=NULL;
    if(!empty) {
        memcpy(&raw,bytes,8);
        VM27ObserverStageTraceV1(8,"[Independent27DisplayObserverTraceV1] stage=frame-raw-surface rawPresent=%u\n",raw?1u:0u);
        // Original44e4c also routes an engaged null surface to its clear path.
        if(!raw)empty=YES;
        else {
            surface=(IOSurfaceRef)(void *)raw;
            if(CFGetTypeID(surface)!=IOSurfaceGetTypeID()) {
                [self report:@"Actual frame payload is outside this IOSurface display profile."];return;
            }
            CFRetain(surface);IOSurfaceIncrementUseCount(surface);
        }
    }
    uint64_t sequence=empty?_emptySequence.fetch_add(1)+1:_sequence.fetch_add(1)+1;
    VM27ObserverStageTraceV1(9,"[Independent27DisplayObserverTraceV1] stage=frame-accepted sequence=%llu empty=%u\n",(unsigned long long)sequence,empty?1u:0u);
    // The original shared_ptr remains caller-managed and is not captured.
    // Serialize pending identity with original presenter association/detach.
    dispatch_async(_bridgeQueue,^{
        if(self->_closed.load() || !self->_presenterAttached || self->_presenter!=presenter) {
            if(surface) {IOSurfaceDecrementUseCount(surface);CFRelease(surface);}return;
        }
        if(!sequence || self->_pendingFrameSequence) {
            if(surface) {IOSurfaceDecrementUseCount(surface);CFRelease(surface);}
            [self report:@"The original presenter supplied an overlapping frame readiness identity."];return;
        }
        self->_pendingFramePresenter=presenter;self->_pendingFrameSequence=sequence;self->_pendingFrameEmpty=empty;
        dispatch_async(dispatch_get_main_queue(),^{
            if(!self->_closed.load()) {
                VM27ObserverStageTraceV1(10,"[Independent27DisplayObserverTraceV1] stage=frame-main-delivery sequence=%llu empty=%u\n",(unsigned long long)sequence,empty?1u:0u);
                if(empty) {
                    if(self->_emptyConsumer)self->_emptyConsumer(sequence);
                    else [self report:@"An original empty display update has no actual clear consumer."];
                }else self->_consumer(surface,sequence);
            }
            if(surface) {IOSurfaceDecrementUseCount(surface);CFRelease(surface);}
        });
    });
}
- (void)setEmptyFrameConsumer:(void (^)(uint64_t))consumer {
    if(!NSThread.isMainThread || _closed.load() || !consumer)return;
    _emptyConsumer=[consumer copy];
}
- (void)markConsumedSequence:(uint64_t)sequence {[self markConsumedSequence:sequence empty:NO];}
- (void)markEmptyConsumedSequence:(uint64_t)sequence {[self markConsumedSequence:sequence empty:YES];}
- (void)markConsumedSequence:(uint64_t)sequence empty:(BOOL)empty {
    if(!NSThread.isMainThread || !sequence || _closed.load())return;
    dispatch_async(_bridgeQueue,^{
        if(self->_closed.load() || !self->_presenterAttached || !self->_pendingFramePresenter ||
           self->_pendingFramePresenter!=self->_presenter || sequence!=self->_pendingFrameSequence ||
           empty!=self->_pendingFrameEmpty)return;
        uint64_t last=empty?self->_lastEmptyConsumedSequence:self->_lastConsumedSequence;
        if(sequence<=last)return;
        // Original 48c78 supplies exactly (presenter, registered observer).
        // Helper230440 retains both and enqueues readiness on presenter+60.
        NSError *error=DisplayInvokeV1(^{self->_functions.frameConsumed(self->_presenter,self);});
        if(error) {self->_retainedFailure=self;[self report:error.localizedDescription];return;}
        if(empty)self->_lastEmptyConsumedSequence=sequence;else self->_lastConsumedSequence=sequence;
        self->_pendingFrameSequence=0;self->_pendingFramePresenter=nil;
        if(self->_completionLogs<8) {
            ++self->_completionLogs;int savedErrno=errno;
            fprintf(stderr,"[Independent27DisplayObserverV3] consumed sequence=%llu empty=%u originalReadyHelperReturned=1 readyQueueExecutionNotClaimed=1 registeredConsumerMatched=1\n",(unsigned long long)sequence,empty?1u:0u);
            errno=savedErrno;
        }
    });
}
- (void)setGenuineCursorConsumerV1:(VM27GenuineCursorConsumerV1)consumer {
    if(NSThread.isMainThread && !_closed.load())_cursorConsumerV1=[consumer copy];
}
- (void)presenter:(id)presenter didUpdateCursor:
    (std::shared_ptr<const VzCore::Hardware::CursorUpdate>)update {
    if(_closed.load() || !update)return;
    const double received=NSProcessInfo.processInfo.systemUptime;
    /* Original27 helper 0x46b68 reads CursorUpdate +0x30 position,
     * +0x28 changed, optional +0x20 engagement, +0 pixels, +8/+12
     * geometry, +16 bytes/pixel and +24/+28 hotspot. Its CGImageCreate
     * uses 0x2004. Read only the actual callback's shared-owned payload;
     * never reinterpret a macOS13 frame or borrow pixels past this call. */
    const uint8_t *raw=(const uint8_t *)update.get();
    uint8_t changed=0,present=0;uint32_t x=0,y=0,w=0,h=0,bpp=0,hx=0,hy=0;
    memcpy(&changed,raw+40,1);memcpy(&x,raw+48,4);memcpy(&y,raw+52,4);
    if(changed>1)return;
    UIImage *image=nil;
    if(changed) {
        memcpy(&present,raw+32,1);if(present>1)return;
        if(present) {
            uintptr_t pixels=0;memcpy(&pixels,raw,8);
            memcpy(&w,raw+8,4);memcpy(&h,raw+12,4);memcpy(&bpp,raw+16,4);
            memcpy(&hx,raw+24,4);memcpy(&hy,raw+28,4);
            if(!pixels || !w || !h || w>512 || h>512 || bpp!=4 || hx>=w || hy>=h)return;
            const size_t row=(size_t)w*4,total=row*h;
            CFDataRef data=CFDataCreate(kCFAllocatorDefault,(const UInt8 *)pixels,total);
            CGDataProviderRef provider=data?CGDataProviderCreateWithCFData(data):NULL;
            CGColorSpaceRef color=CGColorSpaceCreateDeviceRGB();
            CGImageRef cg=provider && color?CGImageCreate(w,h,8,32,row,color,
                (CGBitmapInfo)0x2004,provider,NULL,false,kCGRenderingIntentDefault):NULL;
            if(cg)image=[[UIImage alloc] initWithCGImage:cg];
            if(cg)CGImageRelease(cg);if(color)CGColorSpaceRelease(color);
            if(provider)CGDataProviderRelease(provider);if(data)CFRelease(data);
            if(!image)return;
        }
    }
    dispatch_async(_bridgeQueue,^{
        if(self->_closed.load() || !self->_presenterAttached || self->_presenter!=presenter)return;
        dispatch_async(dispatch_get_main_queue(),^{
            if(self->_closed.load() || !self->_cursorConsumerV1)return;
            self->_cursorConsumerV1(image,changed!=0,CGPointMake(x,y),CGPointMake(hx,hy));
            if(self->_cursorLatencyLogsV5<64) {
                ++self->_cursorLatencyLogsV5;const int saved=errno;
                const double delivered=NSProcessInfo.processInfo.systemUptime;
                fprintf(stderr,"[Independent27CursorLatencyV1] callback=%.6f delivered=%.6f position=%u,%u dispatchMS=%.3f actualGuestCursorOnly=1\n",received,delivered,x,y,(delivered-received)*1000);
                errno=saved;
            }
            if(self->_cursorLogsV1<4) {
                ++self->_cursorLogsV1;
                fprintf(stderr,"[Independent27CursorV1] actualCursorDelivered=1 imageChanged=%u imagePresent=%u size=%ux%u position=%u,%u\n",changed,present,w,h,x,y);
            }
        });
    });
}
- (void)presenter:(id)presenter didUpdateHostDisplay:
    (VzCore::Hardware::HostDisplayUpdate)update {(void)presenter;(void)update;}
- (void)presenter:(id)presenter didUpdateContentHeadroom:(double)value {
    (void)presenter;(void)value; /* First source profile uses ordinary BGRA. */
}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(![NSThread isMainThread] || !completion) {
        [self report:@"Display close requires the actual VM main control queue and a completion."];return;
    }
    _closed.store(true);
    dispatch_async(_bridgeQueue,^{
        self->_pendingFrameSequence=0;self->_pendingFramePresenter=nil;
        NSError *error=nil;
        @try {
            DisplaySyncV1(self->_accessorQueue,^{
                if(self->_accessorAttached) {
                    self->_functions.removeAccessorObserver(self->_accessor,self);
                    self->_accessorAttached=NO;
                }
            });
            if(self->_presenterAttached) {
                DisplaySyncV1(self->_presenterQueue,^{self->_functions.removePresenterObserver(self->_presenter,self);});
                self->_presenterAttached=NO;
            }
            self->_presenter=nil;self->_presenterQueue=nil;
        } @catch(NSException *exception) {
            self->_retainedFailure=self;
            error=DisplayErrorV1(exception.reason?:@"Actual display detach failed; VM retained.");
        }
        dispatch_async(dispatch_get_main_queue(),^{
            if(!error) {self->_accessor=nil;self->_display=nil;self->_vm=nil;self->_retainedFailure=nil;}
            completion(error);
        });
    });
}
@end
