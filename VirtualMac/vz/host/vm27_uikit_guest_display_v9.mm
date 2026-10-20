#import "vm27_uikit_guest_display_native_v9.h"
#import "vm27_genuine_display_completion_v3.h"
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
/* Inspect the first four immutable copies and powers of two through 16384.
 * The counter saturates, so at most 16 bounded summaries occur per process.
 * Active BGRA pixels exclude row padding and alpha; no source pixels change. */
static std::atomic<unsigned> VM27BitmapRGBBudgetV8{0};
static void VM27BitmapRGBSummaryV8(CFDataRef data,size_t width,size_t height,size_t row,OSType format) {
    const int saved=errno;unsigned ordinal=VM27BitmapRGBBudgetV8.load(std::memory_order_relaxed);
    while(ordinal<16384 && !VM27BitmapRGBBudgetV8.compare_exchange_weak(ordinal,ordinal+1,std::memory_order_relaxed)){}
    if(ordinal>=16384)return;
    const unsigned snapshot=ordinal+1;
    if(snapshot>4 && (snapshot & (snapshot-1)))return;
    CFIndex length=CFDataGetLength(data);const UInt8 *bytes=CFDataGetBytePtr(data);
    bool known=bytes && length>=0 && width>0 && height>0 && width<=8192 && height<=8192 && row>=width*4 && row<=64*1024*1024 &&
        height<=64*1024*1024/row && (size_t)length==row*height;
    uint64_t nonzero=0,sumR=0,sumG=0,sumB=0;unsigned maxR=0,maxG=0,maxB=0;
    if(known)for(size_t y=0;y<height;++y)for(size_t x=0;x<width;++x) {
        const UInt8 *p=bytes+y*row+x*4;unsigned b=p[0],g=p[1],r=p[2];
        nonzero+=(r|g|b)!=0;sumR+=r;sumG+=g;sumB+=b;
        if(r>maxR)maxR=r;if(g>maxG)maxG=g;if(b>maxB)maxB=b;
    }
    fprintf(stderr,"[Independent27BitmapRGBV8] snapshotOrdinal=%u known=%u width=%zu height=%zu row=%zu format=0x%x copiedBytes=%ld activePixels=%zu examinedPixels=%zu nonzeroRGBPixels=%llu sumR=%llu sumG=%llu sumB=%llu maxR=%u maxG=%u maxB=%u alphaAndPaddingExcluded=1 scanAllActivePixels=1 scanByteBound=67108864 pixelDump=0 physicalVisibilityNotClaimed=1\n",
        ordinal+1,known?1u:0u,width,height,row,(unsigned)format,(long)length,width*height,known?width*height:0,
        (unsigned long long)nonzero,(unsigned long long)sumR,(unsigned long long)sumG,(unsigned long long)sumB,maxR,maxG,maxB);
    errno=saved;
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
    VM27BitmapRGBSummaryV8(data,width,height,row,format);
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

/* Optional native IOSurface comparison. These leases hold real incoming
 * surfaces; no CPU map, pixel copy, Metal command or event signal is added. */
@interface VM27NativeSurfaceLeaseV9 : NSObject {
    IOSurfaceRef _surface;
}
@property(nonatomic,readonly) IOSurfaceRef surface;
@property(nonatomic,readonly) size_t width;
@property(nonatomic,readonly) size_t height;
- (instancetype)initWithSurface:(IOSurfaceRef)surface error:(NSError **)error;
@end
@implementation VM27NativeSurfaceLeaseV9
- (instancetype)initWithSurface:(IOSurfaceRef)surface error:(NSError **)error {
    if(!(self=[super init]))return nil;
    if(!surface || CFGetTypeID(surface)!=IOSurfaceGetTypeID()) {
        if(error)*error=BitmapErrorV4(@"native-surface-type",@"Native presentation requires the original genuine IOSurface.");return nil;
    }
    size_t w=IOSurfaceGetWidth(surface),h=IOSurfaceGetHeight(surface);
    size_t row=IOSurfaceGetBytesPerRow(surface),allocation=IOSurfaceGetAllocSize(surface);
    const size_t bound=64*1024*1024;
    if(!w || !h || w>8192 || h>8192 || IOSurfaceGetPlaneCount(surface)!=0 ||
       IOSurfaceGetBytesPerElement(surface)!=4 || IOSurfaceGetPixelFormat(surface)!=UINT32_C(0x42475241) ||
       w>SIZE_MAX/4 || row<w*4 || row>bound || h>bound/row || allocation<row*h) {
        if(error)*error=BitmapErrorV4(@"native-surface-profile",@"The actual native surface is outside the same bounded BGRA geometry profile.");return nil;
    }
    CFRetain(surface);IOSurfaceIncrementUseCount(surface);_surface=surface;_width=w;_height=h;
    return self;
}
- (IOSurfaceRef)surface {return _surface;}
- (void)dealloc {if(_surface){IOSurfaceDecrementUseCount(_surface);CFRelease(_surface);}}
@end
/* A transaction owns both sides of replacement until its real CA completion.
 * settled is main-thread-only and prevents a queued completion after an
 * exception from accounting/releasing the dispatch group a second time. */
@interface VM27NativeLayerTransactionV9 : NSObject
@property(nonatomic,strong) VM27NativeSurfaceLeaseV9 *before;
@property(nonatomic,strong) VM27NativeSurfaceLeaseV9 *after;
@property(nonatomic) BOOL commitReturned;
@property(nonatomic) BOOL settled;
@end
@implementation VM27NativeLayerTransactionV9
@end

@interface VM27UIKitBitmapDisplayV4 : UIView {
    IOSurfaceRef _latest,_unlockUnresolvedSurface;
    uint64_t _sequence,_submittedSequence,_completedSequence,_emptySequence;
    BOOL _closed,_inFlight,_failed,_drawScheduled;
    dispatch_queue_t _copyQueue;
    dispatch_group_t _copyGroup;
    NSError *_unlockError;
    VM27UIKitBitmapDisplayV4 *_retainedFailure;
    BOOL _nativeModeV9,_nativeUnresolvedV9;
    unsigned _nativeCompletedV9;
    VM27NativeSurfaceLeaseV9 *_nativeFrontV9;
    VM27NativeLayerTransactionV9 *_nativeTransactionV9;
}
@property(nonatomic,copy) void (^failure)(NSError *);
@property(nonatomic,copy) void (^frameConsumed)(uint64_t);
@property(nonatomic,copy) void (^emptyConsumed)(uint64_t);
- (void)consumeSurface:(IOSurfaceRef)surface sequence:(uint64_t)sequence;
- (BOOL)tryEnableNativeIOSurfaceLayerV9:(NSError **)error;
- (void)presentPendingNativeSurfaceV9;
- (void)consumeNativeEmptySequenceV9:(uint64_t)sequence;
- (void)closeNativeWithCompletionV9:(void (^)(NSError *))completion;
- (void)consumeEmptySequence:(uint64_t)sequence;
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
/* Admission does not touch layer contents. A pending timer may subsequently
 * choose this mode; no copy/CA transaction may already be in flight. */
- (BOOL)tryEnableNativeIOSurfaceLayerV9:(NSError **)error {
    if(!NSThread.isMainThread || _closed || _failed || _inFlight || _nativeModeV9 || _nativeUnresolvedV9) {
        if(error)*error=BitmapErrorV4(@"native-mode-busy",@"Native comparison requires an open idle display and one unused mode change.");return NO;
    }
    _nativeModeV9=YES;
    /* Re-present the real latest surface if the CPU frame was already ACKed.
     * The native completion only ACKs a strictly newer actual sequence. */
    _submittedSequence=0;
    fprintf(stderr,"[Independent27DisplayNativeV9] modeAccepted=1 backend=iosurface-layer defaultCPUWasPreserved=1 actualVisibilityNotClaimed=1\n");
    [self schedulePendingBitmap];return YES;
}
- (void)submitNativeSurfaceV9:(IOSurfaceRef)surface sequence:(uint64_t)sequence
    empty:(BOOL)empty closeCompletion:(void (^)(NSError *))closeCompletion {
    if(!NSThread.isMainThread || !_nativeModeV9 || _inFlight || _nativeUnresolvedV9 ||
       (!closeCompletion && (_closed || _failed)))return;
    NSError *error=nil;
    VM27NativeSurfaceLeaseV9 *next=surface?[[VM27NativeSurfaceLeaseV9 alloc] initWithSurface:surface error:&error]:nil;
    if((!empty && !next) || error) {
        [self fail:error?:BitmapErrorV4(@"native-surface-missing",@"A real nonempty native frame requires a validated IOSurface.")];return;
    }
    VM27NativeLayerTransactionV9 *ticket=[VM27NativeLayerTransactionV9 new];
    if(!ticket) {
        NSError *failure=BitmapErrorV4(@"native-ticket-allocation",@"The real native transaction lease could not be allocated.");
        [self fail:failure];if(closeCompletion)closeCompletion(failure);return;
    }
    ticket.before=_nativeFrontV9;ticket.after=next;_nativeTransactionV9=ticket;
    _inFlight=YES;if(!empty)_submittedSequence=sequence;
    dispatch_group_enter(_copyGroup);
    BOOL begun=NO;
    @try {
        [CATransaction begin];begun=YES;[CATransaction setDisableActions:YES];
        [CATransaction setCompletionBlock:^{
            dispatch_async(dispatch_get_main_queue(),^{
                if(ticket.settled)return;
                ticket.settled=YES;self->_inFlight=NO;
                NSError *completionError=nil;
                if(!ticket.commitReturned) {
                    self->_nativeUnresolvedV9=YES;self->_retainedFailure=self;
                    completionError=BitmapErrorV4(@"native-completion-order",@"The native transaction did not establish a returned commit.");
                    [self fail:completionError];
                } else {
                    /* _nativeFrontV9 protects the current layer surface. Drop
                     * the previous lease only after actual CA completion. */
                    self->_nativeTransactionV9=nil;
                }
                dispatch_group_leave(self->_copyGroup);
                if(closeCompletion) {closeCompletion(completionError);return;}
                if(completionError || self->_closed || self->_failed)return;
                if(empty) {
                    fprintf(stderr,"[Independent27DisplayNativeV9] clearCompleted=1 emptySequence=%llu backend=iosurface-layer GPUCompletionNotClaimed=1\n",(unsigned long long)sequence);
                    if(self.emptyConsumed)self.emptyConsumed(sequence);
                } else {
                    BOOL acknowledge=sequence>self->_completedSequence;
                    if(acknowledge)self->_completedSequence=sequence;
                    if(self->_nativeCompletedV9<16384) {
                        unsigned ordinal=++self->_nativeCompletedV9;
                        if(ordinal<=4 || !(ordinal&(ordinal-1)))
                            fprintf(stderr,"[Independent27DisplayNativeV9] frameTransactionCompleted=1 ordinal=%u sequence=%llu size=%zux%zu backend=iosurface-layer originalSequenceACK=%u GPUCompletionOrPhysicalVisibilityNotClaimed=1\n",
                                ordinal,(unsigned long long)sequence,next.width,next.height,acknowledge?1u:0u);
                    }
                    if(acknowledge && self.frameConsumed)self.frameConsumed(sequence);
                    [self schedulePendingBitmap];
                }
            });
        }];
        self.layer.contents=surface?(__bridge id)surface:nil;
        [CATransaction commit];begun=NO;ticket.commitReturned=YES;
        _nativeFrontV9=next;
    } @catch(NSException *exception) {
        /* A partial transaction is unresolved, not a successful drain. Keep
         * both leases and the owner even if removing the completion fails. */
        ticket.settled=YES;
        if(begun) {
            @try {[CATransaction setCompletionBlock:nil];[CATransaction commit];}
            @catch(NSException *ignored){(void)ignored;}
        }
        _nativeUnresolvedV9=YES;_retainedFailure=self;_inFlight=NO;
        NSError *failure=BitmapErrorV4(@"native-layer-transaction",exception.reason?:@"The actual native layer transaction raised an exception.");
        dispatch_group_leave(_copyGroup);[self fail:failure];
        if(closeCompletion)closeCompletion(failure);
    }
}
- (void)consumeNativeEmptySequenceV9:(uint64_t)sequence {
    if(!NSThread.isMainThread || _closed || _failed)return;
    if(!sequence || sequence<=_emptySequence || _inFlight) {
        [self fail:BitmapErrorV4(@"native-empty-admission",@"The original empty update has an invalid or overlapping native clear sequence.")];return;
    }
    _emptySequence=sequence;
    if(_latest){IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);_latest=NULL;}
    [self submitNativeSurfaceV9:NULL sequence:sequence empty:YES closeCompletion:nil];
}
- (void)presentPendingNativeSurfaceV9 {
    if(_closed || _failed || _inFlight || !_latest || !self.window || _submittedSequence==_sequence)return;
    [self submitNativeSurfaceV9:_latest sequence:_sequence empty:NO closeCompletion:nil];
}
- (void)closeNativeWithCompletionV9:(void (^)(NSError *))completion {
    _closed=YES;
    if(_latest){IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);_latest=NULL;}
    dispatch_group_notify(_copyGroup,dispatch_get_main_queue(),^{
        if(self->_nativeUnresolvedV9) {
            self->_retainedFailure=self;
            completion(BitmapErrorV4(@"native-unresolved-close",@"An actual native surface transaction remains unresolved; its surface leases are retained."));return;
        }
        /* This clear has its own group entry and real CA completion. The
         * display owner is not released while its front surface is pending. */
        [self submitNativeSurfaceV9:NULL sequence:0 empty:YES closeCompletion:completion];
    });
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
- (void)consumeEmptySequence:(uint64_t)sequence {
    if(_nativeModeV9){[self consumeNativeEmptySequenceV9:sequence];return;}
    if(!NSThread.isMainThread || _closed || _failed)return;
    if(!sequence || sequence<=_emptySequence || _inFlight) {
        [self fail:BitmapErrorV4(@"empty-admission",@"The original empty update has an invalid or overlapping clear sequence.")];return;
    }
    _emptySequence=sequence;_inFlight=YES;
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);_latest=NULL;}
    __block BOOL transactionReturned=NO;BOOL transactionBegun=NO;
    @try {
        [CATransaction begin];transactionBegun=YES;[CATransaction setDisableActions:YES];
        [CATransaction setCompletionBlock:^{
            dispatch_async(dispatch_get_main_queue(),^{
                self->_inFlight=NO;
                if(transactionReturned && !self->_closed && !self->_failed) {
                    int savedErrno=errno;
                    fprintf(stderr,"[Independent27DisplayBitmapV6] clear-completed emptySequence=%llu commitReturned=1 bitmapFrameNotCounted=1\n",(unsigned long long)sequence);
                    errno=savedErrno;
                    if(self.emptyConsumed)self.emptyConsumed(sequence);
                }
            });
        }];
        self.layer.contents=nil;
        [CATransaction commit];transactionBegun=NO;transactionReturned=YES;
    } @catch(NSException *exception) {
        if(transactionBegun) {
            @try {[CATransaction setCompletionBlock:nil];[CATransaction commit];}
            @catch(NSException *ignored) {(void)ignored;}
        }
        _inFlight=NO;[self fail:BitmapErrorV4(@"empty-publish",exception.reason?:@"Actual empty frame clearing failed.")];
    }
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
    if(_nativeModeV9){[self presentPendingNativeSurfaceV9];return;}
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
                    self->_submittedSequence=0;self->_inFlight=NO;[self schedulePendingBitmap];return;
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
                                if(self.frameConsumed)self.frameConsumed(sequence);
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
    if(_nativeModeV9){[self closeNativeWithCompletionV9:completion];return;}
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
    BOOL _nativeDisplayClosingV9;
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
    _bitmapView.frameConsumed=^(uint64_t sequence) {
        VM27UIKitGuestDisplayV1 *owner=weakSelf;
        if(owner)[owner->_observer markConsumedSequence:sequence];
    };
    _bitmapView.emptyConsumed=^(uint64_t sequence) {
        VM27UIKitGuestDisplayV1 *owner=weakSelf;
        if(owner)[owner->_observer markEmptyConsumedSequence:sequence];
    };
    [_observer setEmptyFrameConsumer:^(uint64_t sequence) {
        VM27UIKitGuestDisplayV1 *owner=weakSelf;
        if(owner)[owner->_bitmapView consumeEmptySequence:sequence];
    }];
    [container insertSubview:_bitmapView atIndex:0];
    VM27BitmapStageTraceV1(10,"[Independent27DisplayBitmapTraceV1] stage=attachment-return bitmapWindowPresent=%u\n",_bitmapView.window?1u:0u);
    return self;
}
- (UIView *)view {return _bitmapView;}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(!NSThread.isMainThread || !completion)return;
    _nativeDisplayClosingV9=YES;
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

@implementation VM27UIKitGuestDisplayV1 (VM27NativeIOSurfaceLayerV9)
- (BOOL)vm27_tryEnableNativeIOSurfaceLayerV9ForVirtualMachine:(id)vm error:(NSError **)error {
    static BOOL acceptedInProcess=NO; /* Original main queue only. */
    if(!NSThread.isMainThread || acceptedInProcess || _nativeDisplayClosingV9 || !vm ||
       _actualVM!=vm || !_observer || !_bitmapView ||
       ![vm respondsToSelector:sel_registerName("state")] ||
       ((NSInteger(*)(id,SEL))objc_msgSend)(vm,sel_registerName("state"))!=1) {
        if(error)*error=UIKitDisplayErrorV1(@"Native surface comparison requires this exact running display owner and an unused process mode change.");return NO;
    }
    if(![_bitmapView tryEnableNativeIOSurfaceLayerV9:error])return NO;
    acceptedInProcess=YES;return YES;
}
@end
