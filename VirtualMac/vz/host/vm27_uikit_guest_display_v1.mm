#import "vm27_uikit_guest_display_v1.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <objc/runtime.h>
#import <objc/message.h>
@interface NSObject (VM27OriginalVMQueueInitializerV1)
- (instancetype)initWithConfiguration:(id)configuration queue:(dispatch_queue_t)queue;
@end
static NSError *UIKitDisplayErrorV1(NSString *text) {
    return [NSError errorWithDomain:@"VM27UIKitGuestDisplay" code:1
        userInfo:@{NSLocalizedDescriptionKey:text}];
}
id VM27UIKitCreateActualVirtualMachineV1(id configuration,NSError **error) {
    if(!configuration || !VM27GenuineDisplayClassProfileAvailableV1(error))return nil;
    Class cls=objc_getClass("VZVirtualMachine");
    id vm=[[cls alloc] initWithConfiguration:configuration queue:dispatch_get_main_queue()];
    if(!VM27GenuineDisplayProfileAvailableV1(vm,error))return nil;
    return vm;
}
@interface VM27UIKitMetalDisplayV1 : UIView {
    id<MTLDevice> _device;
    id<MTLCommandQueue> _commands;
    IOSurfaceRef _latest;
    uint64_t _sequence,_submittedSequence,_completedSequence;
    BOOL _closed,_inFlight,_failed;
    dispatch_group_t _gpuGroup;
    CADisplayLink *_retry;
}
@property(nonatomic,copy) void (^failure)(NSError *);
- (void)consumeSurface:(IOSurfaceRef)surface sequence:(uint64_t)sequence;
- (void)closeWithCompletion:(void (^)(void))completion;
@end
@implementation VM27UIKitMetalDisplayV1
+ (Class)layerClass {return CAMetalLayer.class;}
- (instancetype)initWithFrame:(CGRect)frame {
    if(!(self=[super initWithFrame:frame]))return nil;
    _device=MTLCreateSystemDefaultDevice();_commands=[_device newCommandQueue];
    if(!_device || !_commands)return nil;
    _gpuGroup=dispatch_group_create();self.backgroundColor=UIColor.blackColor;
    CAMetalLayer *layer=(CAMetalLayer *)self.layer;
    layer.device=_device;layer.pixelFormat=MTLPixelFormatBGRA8Unorm;
    layer.framebufferOnly=YES;layer.opaque=YES;layer.contentsScale=self.traitCollection.displayScale;
    return self;
}
- (void)dealloc {
    [_retry invalidate];
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);}
}
- (void)didMoveToWindow {[super didMoveToWindow];[self drawPendingFrame];}
- (void)layoutSubviews {[super layoutSubviews];self.layer.frame=self.bounds;}
- (void)fail:(NSString *)text {
    _failed=YES;[_retry invalidate];_retry=nil;
    if(self.failure)self.failure(UIKitDisplayErrorV1(text));
}
- (void)consumeSurface:(IOSurfaceRef)surface sequence:(uint64_t)sequence {
    if(![NSThread isMainThread] || _closed || _failed)return;
    if(!surface || CFGetTypeID(surface)!=IOSurfaceGetTypeID()) {
        [self fail:@"The genuine display frame is not an IOSurface."];return;
    }
    CFRetain(surface);IOSurfaceIncrementUseCount(surface);
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);}
    _latest=surface;_sequence=sequence;[self drawPendingFrame];
}
- (void)retryFrame:(CADisplayLink *)sender {(void)sender;[self drawPendingFrame];}
- (void)drawPendingFrame {
    if(_closed || _failed || _inFlight || !_latest || !self.window ||
       _submittedSequence==_sequence)return;
    size_t width=IOSurfaceGetWidth(_latest),height=IOSurfaceGetHeight(_latest);
    if(!width || !height || width>8192 || height>8192 ||
       IOSurfaceGetPlaneCount(_latest)!=0 || IOSurfaceGetBytesPerElement(_latest)!=4 ||
       IOSurfaceGetPixelFormat(_latest)!=UINT32_C(0x42475241)) {
        [self fail:@"The actual frame format is outside the first ordinary BGRA UIKit display profile."];return;
    }
    CAMetalLayer *layer=(CAMetalLayer *)self.layer;layer.drawableSize=CGSizeMake(width,height);
    id<CAMetalDrawable> drawable=[layer nextDrawable];
    if(!drawable) {
        if(!_retry) {_retry=[CADisplayLink displayLinkWithTarget:self selector:@selector(retryFrame:)];
            [_retry addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];}
        return;
    }
    [_retry invalidate];_retry=nil;
    MTLTextureDescriptor *descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:
        MTLPixelFormatBGRA8Unorm width:width height:height mipmapped:NO];
    descriptor.usage=MTLTextureUsageShaderRead;descriptor.storageMode=MTLStorageModeShared;
    id<MTLTexture> source=[_device newTextureWithDescriptor:descriptor iosurface:_latest plane:0];
    id<MTLCommandBuffer> command=[_commands commandBuffer];
    id<MTLBlitCommandEncoder> blit=[command blitCommandEncoder];
    if(!source || !command || !blit || drawable.texture.width!=width ||
       drawable.texture.height!=height) {
        [self fail:@"Metal could not create an actual IOSurface display copy."];return;
    }
    [blit copyFromTexture:source sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0,0,0)
        sourceSize:MTLSizeMake(width,height,1) toTexture:drawable.texture destinationSlice:0
        destinationLevel:0 destinationOrigin:MTLOriginMake(0,0,0)];
    [blit endEncoding];
    IOSurfaceRef submitted=_latest;CFRetain(submitted);IOSurfaceIncrementUseCount(submitted);
    uint64_t sequence=_sequence;_submittedSequence=sequence;_inFlight=YES;
    dispatch_group_enter(_gpuGroup);
    [command addCompletedHandler:^(id<MTLCommandBuffer> done) {
        BOOL success=done.status==MTLCommandBufferStatusCompleted;
        NSString *failure=done.error.localizedDescription?:@"Actual Metal command failed.";
        IOSurfaceDecrementUseCount(submitted);CFRelease(submitted);
        dispatch_async(dispatch_get_main_queue(),^{
            self->_inFlight=NO;
            if(success) {
                self->_completedSequence=sequence;
                fprintf(stderr,"[Independent27Display] completed actual IOSurface frame=%llu size=%zux%zu\n",
                    (unsigned long long)sequence,width,height);
                [self drawPendingFrame];
            } else if(!self->_closed) [self fail:failure];
        });
        dispatch_group_leave(self->_gpuGroup);
    }];
    [command presentDrawable:drawable];[command commit];
}
- (void)closeWithCompletion:(void (^)(void))completion {
    NSAssert(NSThread.isMainThread,@"UIKit display close requires main");
    _closed=YES;[_retry invalidate];_retry=nil;
    if(_latest) {IOSurfaceDecrementUseCount(_latest);CFRelease(_latest);_latest=NULL;}
    dispatch_group_notify(_gpuGroup,dispatch_get_main_queue(),completion);
}
@end
@interface VM27UIKitGuestDisplayV1 () {
    id _actualVM;
    VM27GenuineDisplayObserverV1 *_observer;
    VM27UIKitMetalDisplayV1 *_metalView;
    VM27UIKitGuestDisplayV1 *_retainedFailure;
}
@end
@implementation VM27UIKitGuestDisplayV1
- (instancetype)initWithVirtualMachine:(id)vm container:(UIView *)container
    failureHandler:(void (^)(NSError *))failure error:(NSError **)error {
    if(!(self=[super init]))return nil;
    if(!NSThread.isMainThread || !container || !failure) {
        if(error)*error=UIKitDisplayErrorV1(@"Display attachment requires an actual UIKit container on main.");return nil;
    }
    if(!VM27GenuineDisplayProfileAvailableV1(vm,error))return nil;
    id graphics=((id(*)(id,SEL))objc_msgSend)(vm,sel_registerName("graphicsDevices"));
    id device=[graphics firstObject];
    if(!device || ![device respondsToSelector:sel_registerName("displays")]) {
        if(error)*error=UIKitDisplayErrorV1(@"Actual VM has no graphics display device.");return nil;
    }
    id displays=((id(*)(id,SEL))objc_msgSend)(device,sel_registerName("displays"));
    id display=[displays firstObject];
    _metalView=[[VM27UIKitMetalDisplayV1 alloc] initWithFrame:container.bounds];
    if(!_metalView) {if(error)*error=UIKitDisplayErrorV1(@"An actual Metal device/command queue is unavailable.");return nil;}
    _metalView.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    _metalView.failure=[failure copy];_actualVM=vm;
    __weak VM27UIKitGuestDisplayV1 *weakSelf=self;
    _observer=[[VM27GenuineDisplayObserverV1 alloc] initWithVirtualMachine:vm graphicsDisplay:display
        frameConsumer:^(IOSurfaceRef surface,uint64_t sequence) {
            VM27UIKitGuestDisplayV1 *owner=weakSelf;
            if(owner)[owner->_metalView consumeSurface:surface sequence:sequence];
        } failureHandler:failure error:error];
    if(!_observer)return nil;
    [container insertSubview:_metalView atIndex:0];
    return self;
}
- (UIView *)view {return _metalView;}
- (void)closeWithCompletion:(void (^)(NSError *))completion {
    if(!NSThread.isMainThread || !completion)return;
    [_observer closeWithCompletion:^(NSError *error) {
        if(error) {self->_retainedFailure=self;completion(error);return;}
        [self->_metalView closeWithCompletion:^{
            [self->_metalView removeFromSuperview];
            self->_observer=nil;self->_actualVM=nil;self->_retainedFailure=nil;completion(nil);
        }];
    }];
}
@end
