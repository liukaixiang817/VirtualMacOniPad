#import "VM27HostCamera.h"
#import "VM27CameraWire.h"
#import <AVFoundation/AVFoundation.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

@protocol VM27CameraSocket <NSObject>
- (NSArray *)socketDevices;
- (NSInteger)state;
- (void)connectToPort:(uint32_t)port completionHandler:(void (^)(id, NSError *))completion;
- (int)fileDescriptor;
- (void)close;
@end

@interface VM27CameraConnection : NSObject
@property(nonatomic, strong) id<VM27CameraSocket> native;
@property(nonatomic) int fd;
@end

@implementation VM27CameraConnection
- (void)dealloc { close(_fd); }
@end

@interface VM27HostCamera () <AVCaptureVideoDataOutputSampleBufferDelegate>
@end

@implementation VM27HostCamera {
    __weak id<VM27CameraSocket> _vm;
    VM27CameraConnection *_connection;
    dispatch_source_t _tick;
    dispatch_queue_t _captureQueue;
    dispatch_queue_t _wireQueue;
    AVCaptureSession *_captureSession;
    AVCaptureVideoDataOutput *_output;
    NSData *_latest;
    VM27CameraPacket _packet;
    uint64_t _latestTime;
    uint64_t _generation;
    uint64_t _captureGeneration;
    uint64_t _nextConnectionTime;
    BOOL _eligible;
    BOOL _requested;
    BOOL _connecting;
    BOOL _demand;
    BOOL _invalidated;
}

- (instancetype)initWithVirtualMachine:(id)virtualMachine profile:(VM27CameraProfile)profile {
    self = [super init];
    if (!self) return nil;
    _vm = virtualMachine;
    _profile = profile;
    _frontCamera = YES;
    _captureQueue = dispatch_queue_create("com.virtualmac.camera.capture", DISPATCH_QUEUE_SERIAL);
    _wireQueue = dispatch_queue_create("com.virtualmac.camera.vsock", DISPATCH_QUEUE_SERIAL);
    _tick = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(_tick, DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC, 50 * NSEC_PER_MSEC);
    __weak VM27HostCamera *weakSelf = self;
    dispatch_source_set_event_handler(_tick, ^{ [weakSelf tick]; });
    dispatch_resume(_tick);
    return self;
}

- (BOOL)sharingRequested { @synchronized(self) { return _requested; } }

- (void)requestSharing:(BOOL)enabled completion:(void (^)(BOOL))completion {
    if (!enabled) { [self updateRequest:NO]; completion(YES); return; }
    __weak VM27HostCamera *weakSelf = self;
    [AVCaptureDevice requestAccessForMediaType:AVMediaTypeVideo completionHandler:^(BOOL granted) {
        dispatch_async(dispatch_get_main_queue(), ^{
            VM27HostCamera *self = weakSelf;
            if (!self || self->_invalidated) return;
            [self updateRequest:granted];
            completion(granted);
        });
    }];
}

- (void)updateRequest:(BOOL)requested {
    @synchronized(self) { _requested = requested; [self clearFrame]; }
    if (!requested) [self disconnect];
    [self refreshCapture];
}

- (void)setProfile:(VM27CameraProfile)profile {
    if (!VM27CameraDimensions(profile).width) return;
    @synchronized(self) {
        if (_profile == profile) return;
        _profile = profile;
        [self clearFrame];
    }
    [self refreshCapture];
}

- (void)setFrontCamera:(BOOL)frontCamera {
    @synchronized(self) { _frontCamera = frontCamera; [self clearFrame]; }
    [self refreshCapture];
}

- (void)setMirrored:(BOOL)mirrored {
    @synchronized(self) { _mirrored = mirrored; [self clearFrame]; }
    [self refreshCapture];
}

- (void)clearFrame {
    ++_generation;
    _latest = nil;
    _latestTime = 0;
}

- (void)setEligible:(BOOL)eligible {
    @synchronized(self) {
        if (_eligible == eligible) return;
        _eligible = eligible;
        if (!eligible) _demand = NO;
        [self clearFrame];
    }
    if (!eligible) [self disconnect];
    [self refreshCapture];
    if (eligible) [self tick];
}

- (void)invalidate {
    _invalidated = YES;
    [self setEligible:NO];
    if (_tick) dispatch_source_cancel(_tick);
    _tick = nil;
}

- (void)disconnect {
    VM27CameraConnection *connection;
    @synchronized(self) {
        connection = _connection;
        if (!connection) return;
        _connection = nil;
        _demand = NO;
        [self clearFrame];
    }
    shutdown(connection.fd, SHUT_RDWR);
    [connection.native close];
    [self refreshCapture];
}

- (void)tick {
    id<VM27CameraSocket> vm = _vm;
    if (_invalidated || !_eligible || !vm || [vm state] != 1) {
        [self disconnect];
        return;
    }
    if (_connection || _connecting) return;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (now < _nextConnectionTime) return;
    _nextConnectionTime = now + NSEC_PER_SEC;
    id<VM27CameraSocket> device = [vm.socketDevices firstObject];
    if (![device respondsToSelector:@selector(connectToPort:completionHandler:)]) return;
    _connecting = YES;
    __weak VM27HostCamera *weakSelf = self;
    __weak id<VM27CameraSocket> expectedVM = vm;
    [device connectToPort:VM27_CAMERA_VSOCK_PORT completionHandler:^(id<VM27CameraSocket> native, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            VM27HostCamera *self = weakSelf;
            if (!self) { [native close]; return; }
            self->_connecting = NO;
            if (!native) return;
            id<VM27CameraSocket> vm = expectedVM;
            if (error || self->_invalidated || !self->_eligible || self->_vm != vm || vm.state != 1) {
                [native close];
                return;
            }
            int descriptor = fcntl(native.fileDescriptor, F_DUPFD_CLOEXEC, 0);
            int one = 1;
            if (descriptor < 0 || setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) {
                if (descriptor >= 0) close(descriptor);
                [native close];
                return;
            }
            VM27CameraConnection *connection = [VM27CameraConnection new];
            connection.fd = descriptor;
            connection.native = native;
            @synchronized(self) { self->_connection = connection; }
            dispatch_async(self->_wireQueue, ^{ [self serve:connection]; });
        });
    }];
}

- (void)serve:(VM27CameraConnection *)connection {
    for (;;) {
        @autoreleasepool {
            VM27CameraPacket request = {0};
            if (VM27CameraRead(connection.fd, &request, NULL, 0) || request.kind != VM27CameraDemand) break;
            NSData *bytes = nil;
            VM27CameraPacket reply;
            BOOL changed = NO;
            @synchronized(self) {
                if (_connection != connection) break;
                if (_demand != request.enabled) {
                    _demand = request.enabled;
                    [self clearFrame];
                    changed = YES;
                }
                BOOL enabled = _eligible && _requested;
                reply = (VM27CameraPacket){.kind = VM27CameraState, .profile = _profile, .enabled = enabled};
                uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
                if (enabled && request.enabled && request.profile == _profile && _latest && now - _latestTime < 200 * NSEC_PER_MSEC) {
                    reply = _packet;
                    bytes = _latest;
                }
            }
            if (changed) [self refreshCapture];
            if (VM27CameraWrite(connection.fd, reply, bytes.bytes)) break;
        }
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_connection != connection) return;
        [self disconnect];
    });
}

- (void)refreshCapture {
    dispatch_async(_captureQueue, ^{ [self rebuildCapture]; });
}

- (void)rebuildCapture {
    uint64_t generation;
    VM27CameraProfile profile;
    BOOL active, front;
    @synchronized(self) {
        generation = _generation;
        active = _eligible && _requested && _demand;
        front = _frontCamera;
        profile = _profile;
    }
    if (_captureGeneration == generation && _captureSession.running == active) return;
    [_output setSampleBufferDelegate:nil queue:NULL];
    [_captureSession stopRunning];
    _captureSession = nil;
    _output = nil;
    if (!active) return;

    AVCaptureDevice *device = [AVCaptureDevice defaultDeviceWithDeviceType:AVCaptureDeviceTypeBuiltInWideAngleCamera
        mediaType:AVMediaTypeVideo position:front ? AVCaptureDevicePositionFront : AVCaptureDevicePositionBack];
    NSError *error = nil;
    AVCaptureDeviceInput *input = device ? [AVCaptureDeviceInput deviceInputWithDevice:device error:&error] : nil;
    if (!input) return;
    AVCaptureSession *session = [AVCaptureSession new];
    NSString *preset = profile == VM27CameraProfile480p ? AVCaptureSessionPreset640x480 :
        profile == VM27CameraProfile720p ? AVCaptureSessionPreset1280x720 : AVCaptureSessionPreset1920x1080;
    [session beginConfiguration];
    if ([session canSetSessionPreset:preset]) session.sessionPreset = preset;
    AVCaptureVideoDataOutput *output = [AVCaptureVideoDataOutput new];
    output.alwaysDiscardsLateVideoFrames = YES;
    output.videoSettings = @{(__bridge NSString *)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)};
    if (![session canAddInput:input] || ![session canAddOutput:output]) { [session commitConfiguration]; return; }
    [session addInput:input];
    [session addOutput:output];
    AVCaptureConnection *connection = [output connectionWithMediaType:AVMediaTypeVideo];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (connection.isVideoOrientationSupported) connection.videoOrientation = AVCaptureVideoOrientationLandscapeRight;
#pragma clang diagnostic pop
    if (connection.isVideoMirroringSupported) {
        connection.automaticallyAdjustsVideoMirroring = NO;
        connection.videoMirrored = NO;
    }
    [session commitConfiguration];
    [output setSampleBufferDelegate:self queue:_captureQueue];
    _captureGeneration = generation;
    _captureSession = session;
    _output = output;
    [session startRunning];
}

- (void)captureOutput:(AVCaptureOutput *)output didOutputSampleBuffer:(CMSampleBufferRef)sample
        fromConnection:(AVCaptureConnection *)connection {
    (void)connection;
    if (output != _output) return;
    VM27CameraProfile profile;
    BOOL mirrored;
    uint64_t generation = _captureGeneration;
    @synchronized(self) {
        if (!_eligible || !_requested || !_demand || generation != _generation) return;
        profile = _profile;
        mirrored = _mirrored;
    }
    CVPixelBufferRef pixels = CMSampleBufferGetImageBuffer(sample);
    if (!pixels) return;
    NSData *bytes = nil;
    VM27CameraPacket packet = {.kind = VM27CameraJPEG, .profile = profile, .enabled = 1};
    if (profile == VM27CameraProfile480p) {
        size_t width = CVPixelBufferGetWidth(pixels), height = CVPixelBufferGetHeight(pixels);
        if (CVPixelBufferGetPixelFormatType(pixels) != kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
            CVPixelBufferGetPlaneCount(pixels) != 2 || width < 2 || height < 2 || width > 1920 || height > 1920 ||
            ((width | height) & 1) || CVPixelBufferGetBytesPerRowOfPlane(pixels, 0) < width ||
            CVPixelBufferGetBytesPerRowOfPlane(pixels, 1) < width ||
            CVPixelBufferGetHeightOfPlane(pixels, 0) != height || CVPixelBufferGetHeightOfPlane(pixels, 1) != height / 2 ||
            CVPixelBufferLockBaseAddress(pixels, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) return;
        NSMutableData *packed = [NSMutableData dataWithLength:width * height * 3 / 2];
        uint8_t *destination = packed.mutableBytes;
        for (size_t plane = 0; plane < 2; plane++) {
            const uint8_t *source = CVPixelBufferGetBaseAddressOfPlane(pixels, plane);
            NSUInteger stride = CVPixelBufferGetBytesPerRowOfPlane(pixels, plane);
            for (size_t row = 0; row < (plane ? height / 2 : height); row++, destination += width)
                memcpy(destination, source + row * stride, width);
        }
        CVPixelBufferUnlockBaseAddress(pixels, kCVPixelBufferLock_ReadOnly);
        packet.kind = VM27CameraNV12;
        packet.width = (uint16_t)width;
        packet.height = (uint16_t)height;
        packet.mirrored = mirrored;
        bytes = packed;
    } else {
        CMVideoDimensions dimensions = VM27CameraDimensions(profile);
        packet.width = dimensions.width;
        packet.height = dimensions.height;
        bytes = VM27CameraEncodeNV12JPEG(pixels, profile, mirrored);
    }
    if (!bytes.length) return;
    packet.length = (uint32_t)bytes.length;
    @synchronized(self) {
        if (_generation != generation) return;
        _latest = bytes;
        _packet = packet;
        _latestTime = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    }
}
@end
