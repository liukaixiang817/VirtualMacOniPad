#import "vm27_uikit_guest_display_v1.h"
#import "vm27_uikit_vm_attestation_v2.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <unistd.h>
#include <stdio.h>

#include <errno.h>
#include <atomic>
/* Each process emits at most two lines per independent stage. Saturation,
 * rather than a wrapping fetch_add, makes that a lifetime bound. No object
 * description, payload copy, queue wait or guest/native operation is added. */
static std::atomic<unsigned> VM27BitmapStageTraceBudgetV1[11]{};
static bool VM27BitmapStageTraceReserveV1(unsigned stage) {
    if(stage>=11)return false;
    unsigned value=VM27BitmapStageTraceBudgetV1[stage].load(std::memory_order_relaxed);
    while(value<2) {
        if(VM27BitmapStageTraceBudgetV1[stage].compare_exchange_weak(value,value+1,
            std::memory_order_relaxed,std::memory_order_relaxed))return true;
    }
    return false;
}
/* Save errno before even evaluating diagnostic arguments. Each emitted line
 * is one stdio call; suppressed stages evaluate no diagnostic arguments. */
#define VM27BitmapStageTraceV1(stage, ...) do { \
    const int vm27_trace_saved_errno=errno; \
    if(VM27BitmapStageTraceReserveV1(stage))fprintf(stderr,__VA_ARGS__); \
    errno=vm27_trace_saved_errno; \
} while(0)

@interface NSObject (VM27OriginalVMQueueInitializerV1)
- (instancetype)initWithConfiguration:(id)configuration queue:(dispatch_queue_t)queue;
@end
static NSError *UIKitDisplayErrorV1(NSString *text) {
    return [NSError errorWithDomain:@"VM27UIKitGuestDisplay" code:1
        userInfo:@{NSLocalizedDescriptionKey:text}];
}
static __weak id ActualFactoryVMV2;
static Class ActualFactoryOriginalClassV2,ActualFactoryReturnedISAV2;
static pid_t ActualFactoryPIDV2;
static IMP ActualFactoryInitializerV2;
static BOOL FactoryErrorV2(NSError **error,NSString *text) {
    if(error)*error=UIKitDisplayErrorV1(text);return NO;
}
static BOOL FactoryClassChainV2(Class actual,Class original) {
    /* Only a constructor-attested object can reach this bounded ancestry
     * check. Names or isKindOfClass alone never enroll a VM. */
    for(unsigned depth=0;actual && depth<8;depth++) {
        if(actual==original)return YES;
        Class next=class_getSuperclass(actual);if(next==actual)return NO;actual=next;
    }
    return NO;
}
BOOL VM27UIKitActualVirtualMachineAttestedV2(id vm,Class original,NSError **error) {
    if(!NSThread.isMainThread || !vm || !original || ActualFactoryPIDV2!=getpid())
        return FactoryErrorV2(error,@"The actual UIKit factory owner must be checked on its original main queue.");
    id owner=ActualFactoryVMV2;
    Class actual=object_getClass(vm);
    Method initializer=class_getInstanceMethod(original,sel_registerName("initWithConfiguration:queue:"));
    if(!owner || owner!=vm || ActualFactoryOriginalClassV2!=original || actual!=ActualFactoryReturnedISAV2 ||
       !FactoryClassChainV2(actual,original) || class_getInstanceSize(original)!=384 || class_getInstanceSize(actual)!=384 ||
       !initializer || method_getImplementation(initializer)!=ActualFactoryInitializerV2)
        return FactoryErrorV2(error,@"The VM is not the exact live object and ISA produced by the genuine UIKit factory.");
    if(!VM27GenuineDisplayProfileAvailableV1(vm,error))return NO;
    fprintf(stderr,"[Independent27] genuine-vm-factory-attestation accepted=1 pid=%d object=%p original=%p actual=%p name=%s\n",
        (int)getpid(),(__bridge void *)vm,(__bridge void *)original,(__bridge void *)actual,class_getName(actual));
    return YES;
}
id VM27UIKitCreateActualVirtualMachineV1(id configuration,NSError **error) {
    if(!NSThread.isMainThread || !configuration || !VM27GenuineDisplayClassProfileAvailableV1(error))return nil;
    if(ActualFactoryPIDV2 && ActualFactoryPIDV2!=getpid()) {
        FactoryErrorV2(error,@"An inherited UIKit factory requires a fresh App process.");return nil;
    }
    id prior=ActualFactoryVMV2;
    if(prior) {FactoryErrorV2(error,@"A live UIKit factory VM must be released before another creation.");return nil;}
    Class cls=objc_getClass("VZVirtualMachine");
    Method initializer=class_getInstanceMethod(cls,sel_registerName("initWithConfiguration:queue:"));
    if(!cls || !initializer || class_getInstanceSize(cls)!=384) {
        FactoryErrorV2(error,@"The genuine UIKit VM allocation class is unavailable.");return nil;
    }
    IMP originalInitializer=method_getImplementation(initializer);
    id allocated=[cls alloc];
    if(!allocated || object_getClass(allocated)!=cls) {
        FactoryErrorV2(error,@"The genuine VM allocation did not return the original class.");return nil;
    }
    const void *allocatedIdentity=(__bridge const void *)allocated;
    id vm=[allocated initWithConfiguration:configuration queue:dispatch_get_main_queue()];
    Class actual=vm?object_getClass(vm):Nil;
    if(!vm || (__bridge const void *)vm!=allocatedIdentity || !FactoryClassChainV2(actual,cls) || class_getInstanceSize(actual)!=384 ||
       method_getImplementation(initializer)!=originalInitializer) {
        FactoryErrorV2(error,@"The original VM constructor did not preserve its allocation, class ancestry or genuine profile.");
        return nil;
    }
    if(!VM27GenuineDisplayProfileAvailableV1(vm,error))return nil;
    /* Publish only after genuine original allocation/init/profile succeeded.
     * The weak owner prevents address reuse and does not keep a stopped VM
     * alive after its existing runtime/display owners release it. */
    ActualFactoryOriginalClassV2=cls;ActualFactoryReturnedISAV2=actual;
    ActualFactoryInitializerV2=originalInitializer;ActualFactoryPIDV2=getpid();ActualFactoryVMV2=vm;
    fprintf(stderr,"[Independent27] genuine-vm-factory-created pid=%d allocation=%p object=%p original=%p actual=%p name=%s superName=%s actualImage=%s\n",
        (int)getpid(),allocatedIdentity,(__bridge void *)vm,(__bridge void *)cls,(__bridge void *)actual,
        class_getName(actual),class_getSuperclass(actual)?class_getName(class_getSuperclass(actual)):"(nil)",
        class_getImageName(actual)?class_getImageName(actual):"(none)");
    return vm;
}
/* Same public V1 display ABI, with a CPU BGRA snapshot backend. A Core
 * Animation transaction completion is not a Metal/GPU completion or physical
 * screen visibility. Original VZ FrameUpdate/IOSurface production is unchanged. */
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/CATransaction.h>
#include <stdint.h>

static NSError *BitmapErrorV4(NSString *stage,NSString *reason) {
    return [NSError errorWithDomain:@"VM27UIKitBitmapDisplayV4" code:1
        userInfo:@{NSLocalizedDescriptionKey:reason,@"stage":stage}];
}
static CGImageRef CopyBitmapImageV4(IOSurfaceRef surface,size_t *widthOut,size_t *heightOut,
    BOOL *changedOut,BOOL *unlockUnresolvedOut,NSError **errorOut) {
    *widthOut=0;*heightOut=0;*changedOut=NO;*unlockUnresolvedOut=NO;
    if(!surface || CFGetTypeID(surface)!=IOSurfaceGetTypeID()) {
        *errorOut=BitmapErrorV4(@"surface-type",@"The original display did not supply a genuine IOSurface.");return NULL;
    }
    uint32_t beforeSeed=0,afterSeed=0;
    kern_return_t lock=IOSurfaceLock(surface,kIOSurfaceLockReadOnly,&beforeSeed);
    if(lock!=KERN_SUCCESS) {
        *errorOut=BitmapErrorV4(@"surface-lock",[NSString stringWithFormat:@"Actual IOSurfaceLock failed (%d).",lock]);return NULL;
    }
    const size_t maximumCopy=64*1024*1024;
    size_t width=IOSurfaceGetWidth(surface),height=IOSurfaceGetHeight(surface);
    size_t row=IOSurfaceGetBytesPerRow(surface),allocation=IOSurfaceGetAllocSize(surface);
    size_t element=IOSurfaceGetBytesPerElement(surface),planes=IOSurfaceGetPlaneCount(surface);
    OSType format=IOSurfaceGetPixelFormat(surface);
    const void *base=IOSurfaceGetBaseAddress(surface);
    BOOL valid=width>0 && height>0 && width<=8192 && height<=8192 &&
        planes==0 && element==4 && format==UINT32_C(0x42475241) &&
        width<=SIZE_MAX/4 && row>=width*4 && row<=maximumCopy &&
        height<=maximumCopy/row && allocation>=row*height && base &&
        (uintptr_t)base<=UINTPTR_MAX-row*height;
    CFDataRef data=NULL;
    NSError *failure=nil;
    if(!valid) {
        failure=BitmapErrorV4(@"surface-profile",@"The actual surface is outside the bounded opaque BGRA bitmap profile.");
    } else {
        /* CFDataCreate copies the real bytes while CPU access is locked; no
         * provider refers to the surface after unlocking. Row padding is kept. */
        data=CFDataCreate(kCFAllocatorDefault,(const UInt8 *)base,(CFIndex)(row*height));
        if(!data)failure=BitmapErrorV4(@"data-copy",@"The bounded actual IOSurface byte copy could not be allocated.");
        if(width!=IOSurfaceGetWidth(surface) || height!=IOSurfaceGetHeight(surface) ||
           row!=IOSurfaceGetBytesPerRow(surface) || allocation!=IOSurfaceGetAllocSize(surface) ||
           element!=IOSurfaceGetBytesPerElement(surface) || planes!=IOSurfaceGetPlaneCount(surface) ||
           format!=IOSurfaceGetPixelFormat(surface) || base!=IOSurfaceGetBaseAddress(surface))
            failure=BitmapErrorV4(@"surface-metadata",@"The actual IOSurface geometry changed during its copy.");
    }
    uint32_t copiedSeed=IOSurfaceGetSeed(surface);
    kern_return_t unlock=IOSurfaceUnlock(surface,kIOSurfaceLockReadOnly,&afterSeed);
    if(unlock!=KERN_SUCCESS) {
        if(data)CFRelease(data);
        *unlockUnresolvedOut=YES;
        *errorOut=BitmapErrorV4(@"surface-unlock",[NSString stringWithFormat:@"Actual IOSurfaceUnlock failed (%d); the surface owner is retained.",unlock]);
        return NULL;
    }
    if(failure) {if(data)CFRelease(data);*errorOut=failure;return NULL;}
    /* IOSurface's lock is a CPU access boundary, not a GPU mutex. A reported
     * mutation is dropped, never published as a completed snapshot. */
    if(beforeSeed!=copiedSeed || beforeSeed!=afterSeed) {
        CFRelease(data);*changedOut=YES;return NULL;
    }
    CGColorSpaceRef color=CGColorSpaceCreateDeviceRGB();
    if(!color) {CFRelease(data);*errorOut=BitmapErrorV4(@"color-space",@"The actual RGB color space could not be created.");return NULL;}
    CGDataProviderRef provider=CGDataProviderCreateWithCFData(data);
    CFRelease(data);
    if(!provider) {CGColorSpaceRelease(color);*errorOut=BitmapErrorV4(@"data-provider",@"The actual copied bitmap provider could not be created.");return NULL;}
    /* Opaque little-endian XRGB is BGRA byte order with the A byte ignored. */
    CGBitmapInfo info=(CGBitmapInfo)(kCGBitmapByteOrder32Little|kCGImageAlphaNoneSkipFirst);
    CGImageRef image=CGImageCreate(width,height,8,32,row,color,info,provider,NULL,true,kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);CGColorSpaceRelease(color);
    if(!image) {*errorOut=BitmapErrorV4(@"image-create",@"CoreGraphics rejected the actual copied BGRA image.");return NULL;}
    *widthOut=width;*heightOut=height;return image;
}

@interface VM27UIKitBitmapDisplayV4 : UIView {
    IOSurfaceRef _latest,_unlockUnresolvedSurface;
    uint64_t _sequence,_submittedSequence,_completedSequence;
    BOOL _closed,_inFlight,_failed,_drawScheduled;
    dispatch_queue_t _copyQueue;
    dispatch_group_t _copyGroup;
    NSError *_unlockError;
    VM27UIKitBitmapDisplayV4 *_retainedFailure;
}
@property(nonatomic,copy) void (^failure)(NSError *);
- (void)consumeSurface:(IOSurfaceRef)surface sequence:(uint64_t)sequence;
- (void)closeWithCompletion:(void (^)(NSError *))completion;
@end
@implementation VM27UIKitBitmapDisplayV4
- (instancetype)initWithFrame:(CGRect)frame {
    if(!(self=[super initWithFrame:frame])) {
        fprintf(stderr,"[Independent27DisplayV4] failed=init-super pid=%d\n",(int)getpid());return nil;
    }
    _copyQueue=dispatch_queue_create("VM27.actual-iosurface-bitmap-copy",DISPATCH_QUEUE_SERIAL);
    _copyGroup=dispatch_group_create();
    if(!_copyQueue || !_copyGroup) {
        fprintf(stderr,"[Independent27DisplayV4] failed=copy-queue-construction pid=%d\n",(int)getpid());return nil;
    }
    self.backgroundColor=UIColor.blackColor;self.opaque=YES;self.clipsToBounds=YES;
    /* Match the original full-bounds display and input normalization. Aspect
     * fit needs a separate, genuinely calibrated viewport contract. */
    self.layer.contentsGravity=kCAGravityResize;
    self.layer.contentsScale=self.traitCollection.displayScale;
    return self;
}
- (void)dealloc {
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);}
    /* An unlock failure takes an explicit self-retained unresolved path and
     * cannot reach dealloc as though CPU access had been released. */
}
- (void)didMoveToWindow {
    [super didMoveToWindow];
    VM27BitmapStageTraceV1(9,"[Independent27DisplayBitmapTraceV1] stage=did-move-window windowPresent=%u\n",self.window?1u:0u);
    [self schedulePendingBitmap];
}
- (void)fail:(NSError *)error {
    if(_failed)return;
    _failed=YES;
    fprintf(stderr,"[Independent27DisplayV4] failed=%s reason=%s\n",
        [error.userInfo[@"stage"] UTF8String]?:"bitmap-copy",error.localizedDescription.UTF8String?:"Actual bitmap display failed.");
    if(!_closed && self.failure)self.failure(error);
}
- (void)consumeSurface:(IOSurfaceRef)surface sequence:(uint64_t)sequence {
    if(!NSThread.isMainThread || _closed || _failed)return;
    VM27BitmapStageTraceV1(0,"[Independent27DisplayBitmapTraceV1] stage=consume-main-context sequence=%llu surfacePresent=%u\n",(unsigned long long)sequence,surface?1u:0u);
    if(!surface || CFGetTypeID(surface)!=IOSurfaceGetTypeID() || !sequence || sequence<=_sequence) {
        [self fail:BitmapErrorV4(@"surface-admission",@"The genuine surface or frame sequence is invalid.")];return;
    }
    CFRetain(surface);IOSurfaceIncrementUseCount(surface);
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);}
    _latest=surface;_sequence=sequence;
    VM27BitmapStageTraceV1(1,"[Independent27DisplayBitmapTraceV1] stage=consume-accepted sequence=%llu\n",(unsigned long long)sequence);
    [self schedulePendingBitmap];
}
- (void)schedulePendingBitmap {
    if(_closed || _failed || _drawScheduled)return;
    _drawScheduled=YES;
    /* Coalesce real frames and cap this first CPU path near ten copies/sec. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),dispatch_get_main_queue(),^{
        self->_drawScheduled=NO;[self copyPendingBitmap];
    });
}
- (void)copyPendingBitmap {
    /* Read window only under the original short-circuit conditions, once. */
    BOOL windowKnown=!_closed && !_failed && !_inFlight && _latest;
    BOOL windowPresent=windowKnown ? self.window!=nil : NO;
    VM27BitmapStageTraceV1(_latest?3u:2u,"[Independent27DisplayBitmapTraceV1] stage=copy-gate sequence=%llu submitted=%llu latestPresent=%u closed=%u failed=%u inFlight=%u windowKnown=%u windowPresent=%u\n",
        (unsigned long long)_sequence,(unsigned long long)_submittedSequence,_latest?1u:0u,_closed?1u:0u,_failed?1u:0u,_inFlight?1u:0u,windowKnown?1u:0u,windowPresent?1u:0u);
    if(_closed || _failed || _inFlight || !_latest || !windowPresent || _submittedSequence==_sequence)return;
    IOSurfaceRef surface=_latest;CFRetain(surface);IOSurfaceIncrementUseCount(surface);
    uint64_t sequence=_sequence;_submittedSequence=sequence;_inFlight=YES;
    dispatch_group_enter(_copyGroup);
    dispatch_async(_copyQueue,^{
        size_t width=0,height=0;BOOL changed=NO,unresolved=NO;NSError *failure=nil;
        VM27BitmapStageTraceV1(4,"[Independent27DisplayBitmapTraceV1] stage=copy-begin sequence=%llu\n",(unsigned long long)sequence);
        CGImageRef image=CopyBitmapImageV4(surface,&width,&height,&changed,&unresolved,&failure);
        VM27BitmapStageTraceV1(5,"[Independent27DisplayBitmapTraceV1] stage=copy-return sequence=%llu imagePresent=%u changed=%u unlockUnresolved=%u errorPresent=%u width=%zu height=%zu\n",(unsigned long long)sequence,image?1u:0u,changed?1u:0u,unresolved?1u:0u,failure?1u:0u,width,height);
        if(!unresolved) {IOSurfaceDecrementUseCount(surface);CFRelease(surface);}
        dispatch_async(dispatch_get_main_queue(),^{
            @try {
                if(unresolved) {
                    self->_unlockUnresolvedSurface=surface;self->_unlockError=failure;
                    self->_retainedFailure=self;
                }
                if(failure) {[self fail:failure];self->_inFlight=NO;return;}
                if(self->_closed || self->_failed) {self->_inFlight=NO;return;}
                if(changed) {
                    fprintf(stderr,"[Independent27DisplayV4] dropped=seed-changed frame=%llu\n",(unsigned long long)sequence);
                    self->_inFlight=NO;[self schedulePendingBitmap];return;
                }
                if(!image) {[self fail:BitmapErrorV4(@"empty-snapshot",@"No actual copied bitmap image was produced.")];self->_inFlight=NO;return;}
                __block BOOL transactionReturned=NO;
                BOOL transactionBegun=NO;
                @try {
                    [CATransaction begin];transactionBegun=YES;
                    [CATransaction setDisableActions:YES];
                    [CATransaction setCompletionBlock:^{
                        /* A no-animation completion can be immediate. Defer
                         * its accounting until commit actually returned. */
                        dispatch_async(dispatch_get_main_queue(),^{
                            VM27BitmapStageTraceV1(8,"[Independent27DisplayBitmapTraceV1] stage=completion-main sequence=%llu commitReturned=%u closed=%u failed=%u\n",(unsigned long long)sequence,transactionReturned?1u:0u,self->_closed?1u:0u,self->_failed?1u:0u);
                            self->_inFlight=NO;
                            if(transactionReturned && !self->_closed && !self->_failed) {
                                self->_completedSequence=sequence;
                                fprintf(stderr,"[Independent27Display] completed actual IOSurface bitmap frame=%llu size=%zux%zu backend=cpu-bitmap\n",
                                    (unsigned long long)sequence,width,height);
                                [self schedulePendingBitmap];
                            }
                        });
                    }];
                    VM27BitmapStageTraceV1(6,"[Independent27DisplayBitmapTraceV1] stage=publish-begin sequence=%llu\n",(unsigned long long)sequence);
                    self.layer.contents=(__bridge id)image;
                    [CATransaction commit];transactionBegun=NO;transactionReturned=YES;
                    VM27BitmapStageTraceV1(7,"[Independent27DisplayBitmapTraceV1] stage=commit-return sequence=%llu\n",(unsigned long long)sequence);
                } @catch(NSException *exception) {
                    if(transactionBegun) {
                        @try {[CATransaction setCompletionBlock:nil];[CATransaction commit];}
                        @catch(NSException *ignored) {(void)ignored;}
                    }
                    [self fail:BitmapErrorV4(@"image-publish",exception.reason?:@"The actual image transaction failed.")];
                    self->_inFlight=NO;
                }
            } @catch(NSException *exception) {
                self->_inFlight=NO;
                [self fail:BitmapErrorV4(@"bitmap-delivery",exception.reason?:@"The copied image delivery failed.")];
            } @finally {
                if(image)CGImageRelease(image);
                /* The completion queue never waits synchronously for copy. */
                dispatch_group_leave(self->_copyGroup);
            }
        });
    });
}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(!NSThread.isMainThread || !completion)return;
    _closed=YES;
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);_latest=NULL;}
    dispatch_group_notify(_copyGroup,dispatch_get_main_queue(),^{
        if(self->_unlockUnresolvedSurface) {
            self->_retainedFailure=self;
            completion(self->_unlockError?:BitmapErrorV4(@"unresolved-close",@"Actual IOSurface CPU access remains unresolved."));return;
        }
        BOOL transactionBegun=NO;
        @try {
            [CATransaction begin];transactionBegun=YES;
            [CATransaction setDisableActions:YES];self.layer.contents=nil;
            [CATransaction commit];transactionBegun=NO;
        } @catch(NSException *exception) {
            if(transactionBegun) {
                @try {[CATransaction setCompletionBlock:nil];[CATransaction commit];}
                @catch(NSException *ignored) {(void)ignored;}
            }
            self->_retainedFailure=self;
            NSError *error=BitmapErrorV4(@"bitmap-close",exception.reason?:@"The actual bitmap layer could not be cleared.");
            [self fail:error];completion(error);return;
        }
        completion(nil);
    });
}
@end

@interface VM27UIKitGuestDisplayV1 () {
    id _actualVM;
    VM27GenuineDisplayObserverV1 *_observer;
    VM27UIKitBitmapDisplayV4 *_bitmapView;
    VM27UIKitGuestDisplayV1 *_retainedFailure;
}
@end
@implementation VM27UIKitGuestDisplayV1
- (instancetype)initWithVirtualMachine:(id)vm container:(UIView *)container
    failureHandler:(void (^)(NSError *))failure error:(NSError **)error {
    if(!(self=[super init]))return nil;
    if(!NSThread.isMainThread || !container || !failure) {
        fprintf(stderr,"[Independent27DisplayV4] failed=attachment-profile pid=%d\n",(int)getpid());
        if(error)*error=UIKitDisplayErrorV1(@"Display attachment requires an actual UIKit container on main.");return nil;
    }
    if(!VM27GenuineDisplayProfileAvailableV1(vm,error)) {
        fprintf(stderr,"[Independent27DisplayV4] failed=genuine-vm-profile pid=%d\n",(int)getpid());return nil;
    }
    id graphics=((id(*)(id,SEL))objc_msgSend)(vm,sel_registerName("graphicsDevices"));
    id device=[graphics firstObject];
    if(!device || ![device respondsToSelector:sel_registerName("displays")]) {
        fprintf(stderr,"[Independent27DisplayV4] failed=graphics-device pid=%d\n",(int)getpid());
        if(error)*error=UIKitDisplayErrorV1(@"Actual VM has no graphics display device.");return nil;
    }
    id displays=((id(*)(id,SEL))objc_msgSend)(device,sel_registerName("displays"));
    id display=[displays firstObject];
    _bitmapView=[[VM27UIKitBitmapDisplayV4 alloc] initWithFrame:container.bounds];
    if(!_bitmapView) {
        fprintf(stderr,"[Independent27DisplayV4] failed=bitmap-view-construction pid=%d\n",(int)getpid());
        if(error)*error=UIKitDisplayErrorV1(@"The actual CPU bitmap view could not be constructed.");return nil;
    }
    _bitmapView.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    _bitmapView.failure=[failure copy];_actualVM=vm;
    __weak VM27UIKitGuestDisplayV1 *weakSelf=self;
    _observer=[[VM27GenuineDisplayObserverV1 alloc] initWithVirtualMachine:vm graphicsDisplay:display
        frameConsumer:^(IOSurfaceRef surface,uint64_t sequence) {
            VM27UIKitGuestDisplayV1 *owner=weakSelf;
            if(owner)[owner->_bitmapView consumeSurface:surface sequence:sequence];
        } failureHandler:failure error:error];
    if(!_observer) {
        fprintf(stderr,"[Independent27DisplayV4] failed=genuine-observer pid=%d\n",(int)getpid());return nil;
    }
    [container insertSubview:_bitmapView atIndex:0];
    VM27BitmapStageTraceV1(10,"[Independent27DisplayBitmapTraceV1] stage=attachment-return bitmapWindowPresent=%u\n",_bitmapView.window?1u:0u);
    return self;
}
- (UIView *)view {return _bitmapView;}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(!NSThread.isMainThread || !completion)return;
    [_observer closeWithCompletion:^(NSError *error) {
        if(error) {self->_retainedFailure=self;completion(error);return;}
        [self->_bitmapView closeWithCompletion:^(NSError *bitmapError) {
            if(bitmapError) {self->_retainedFailure=self;completion(bitmapError);return;}
            [self->_bitmapView removeFromSuperview];
            self->_observer=nil;self->_actualVM=nil;self->_retainedFailure=nil;completion(nil);
        }];
    }];
}
@end
