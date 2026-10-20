#import "vm27_uikit_guest_display_v1.h"
#import "vm27_uikit_vm_attestation_v2.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <unistd.h>
#include <stdio.h>
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
    const void *allocatedIdentityV3=(__bridge const void *)self;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=enter pid=%d self=%p class=%s main=%d\n",
        (int)getpid(),allocatedIdentityV3,class_getName(object_getClass(self)),(int)NSThread.isMainThread);
    self=[super initWithFrame:frame];
    Class superResultClassV3=self?object_getClass(self):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=super-result allocation=%p self=%p class=%s image=%s\n",
        allocatedIdentityV3,(__bridge void *)self,superResultClassV3?class_getName(superResultClassV3):"(nil)",
        superResultClassV3 && class_getImageName(superResultClassV3)?class_getImageName(superResultClassV3):"(none)");
    if(!self) {
        fprintf(stderr,"[Independent27DisplayCtorV3] failed=super-init nil=1 pid=%d\n",(int)getpid());
        return nil;
    }
    _device=MTLCreateSystemDefaultDevice();
    Class deviceClassV3=_device?object_getClass(_device):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=device result=%p class=%s image=%s\n",
        (__bridge void *)_device,deviceClassV3?class_getName(deviceClassV3):"(nil)",
        deviceClassV3 && class_getImageName(deviceClassV3)?class_getImageName(deviceClassV3):"(none)");
    _commands=[_device newCommandQueue];
    Class commandClassV3=_commands?object_getClass(_commands):Nil;
    fprintf(stderr,"[Independent27DisplayCtorV3] phase=queue result=%p class=%s image=%s\n",
        (__bridge void *)_commands,commandClassV3?class_getName(commandClassV3):"(nil)",
        commandClassV3 && class_getImageName(commandClassV3)?class_getImageName(commandClassV3):"(none)");
    if(!_device || !_commands) {
        fprintf(stderr,"[Independent27DisplayCtorV3] failed=%s nil=1\n",!_device?"native-default-device":"native-command-queue");
        return nil;
    }
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
