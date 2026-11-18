#import "VM27CameraUSBHost.h"
#import "VM27CameraFrame.h"
#import "VM27CameraWire.h"
#include "VM27RadioFirstBootPolicyV1.h"

#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/vsock.h>
#include <unistd.h>

@interface VM27GuestCamera : NSObject
- (BOOL)selectProfile:(VM27CameraProfile)profile;
- (void)serve:(int)descriptor;
- (void)stop;
@end

@implementation VM27GuestCamera {
    HvUsbCamera *_device;
    VM27CameraUSBHost *_host;
    CIContext *_encoder;
    NSData *_black720;
    NSData *_black1080;
    VM27CameraProfile _profile;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _device = calloc(1, sizeof(*_device));
    if (!_device) return nil;
    hv_usb_camera_init(_device);
    return self;
}

- (void)dealloc {
    [self stop];
    if (_device) { hv_usb_camera_destroy(_device); free(_device); }
}

- (void)stop {
    if (!_device) return;
    hv_usb_camera_enable(_device, 0);
    [_host stop];
    _host = nil;
}

- (BOOL)selectProfile:(VM27CameraProfile)profile {
    if (_host && profile == _profile) return YES;
    NSData *black = nil;
    if (profile != VM27CameraProfile480p) {
        if (!_encoder) _encoder = [CIContext contextWithOptions:@{kCIContextUseSoftwareRenderer: @YES}];
        CIImage *image = [[CIImage imageWithColor:CIColor.blackColor] imageByCroppingToRect:CGRectMake(0, 0, 640, 480)];
        if (profile == VM27CameraProfile720p) {
            if (!_black720) _black720 = VM27CameraEncodeJPEG(_encoder, image, profile, NO);
            black = _black720;
        } else {
            if (!_black1080) _black1080 = VM27CameraEncodeJPEG(_encoder, image, profile, NO);
            black = _black1080;
        }
    }
    if (hv_usb_camera_set_profile(_device, profile, black.bytes, black.length)) return NO;
    BOOL wasConnected = _host != nil;
    [self stop];
    if (wasConnected) usleep(300000);
    hv_usb_camera_apply_profile(_device);
    _profile = profile;
    _host = [[VM27CameraUSBHost alloc] initWithDevice:_device];
    NSError *error = nil;
    if ([_host startWithError:&error]) {
        CMVideoDimensions dimensions = VM27CameraDimensions(profile);
        fprintf(stderr, "VirtualMac Camera USB mode %dx%d\n", dimensions.width, dimensions.height);
        return YES;
    }
    fprintf(stderr, "VirtualMac Camera controller unavailable: %s\n", error.localizedDescription.UTF8String ?: "unknown");
    _host = nil;
    return NO;
}

- (void)serve:(int)descriptor {
    int one = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) return;
    uint8_t *payload = malloc(VM27_CAMERA_MAX_PACKET);
    if (!payload) return;
    uint64_t lastFrame = 0;
    for (;;) {
        @autoreleasepool {
            uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
            BOOL requested = hv_usb_camera_requested(_device, now);
            VM27CameraPacket request = {.kind = VM27CameraDemand, .profile = _profile, .enabled = requested};
            VM27CameraPacket response = {0};
            if (VM27CameraWrite(descriptor, request, NULL) ||
                VM27CameraRead(descriptor, &response, payload, VM27_CAMERA_MAX_PACKET) ||
                response.kind == VM27CameraDemand) break;
            if (response.profile != _profile || !_host) {
                lastFrame = 0;
                if (response.kind != VM27CameraState || ![self selectProfile:(VM27CameraProfile)response.profile]) break;
            }
            if (response.kind == VM27CameraState) {
                if (!response.enabled || !lastFrame || now - lastFrame > 200 * NSEC_PER_MSEC) hv_usb_camera_enable(_device, 0);
            } else if (requested) {
                hv_usb_camera_enable(_device, 1);
                if (response.kind == VM27CameraNV12) {
                    size_t lumaBytes = (size_t)response.width * response.height;
                    hv_usb_camera_nv12(_device, payload, response.width, payload + lumaBytes, response.width,
                                       response.width, response.height, response.mirrored);
                } else hv_usb_camera_jpeg(_device, payload, response.length, response.profile);
                lastFrame = now;
            }
            usleep(requested ? 30000 : 120000);
        }
    }
    hv_usb_camera_enable(_device, 0);
    memset_s(payload, VM27_CAMERA_MAX_PACKET, 0, VM27_CAMERA_MAX_PACKET);
    free(payload);
}
@end

int main(void) {
    @autoreleasepool {
        int virtualMachine = 0;
        size_t size = sizeof(virtualMachine);
        if (geteuid() || sysctlbyname("kern.hv_vmm_present", &virtualMachine, &size, NULL, 0) || !virtualMachine) return 77;
        // The existing Wi-Fi/Bluetooth owner authorization is the only guest
        // policy transition. Until its reboot, there is nothing to activate.
        uint32_t csr = 0;
        int (*getConfiguration)(uint32_t *) = dlsym(RTLD_DEFAULT, "csr_get_active_config");
        if (!getConfiguration || getConfiguration(&csr) ||
            (csr & VM27_RADIO_CSR_REQUIRED_V1) != VM27_RADIO_CSR_REQUIRED_V1) return 0;

        VM27GuestCamera *camera = [VM27GuestCamera new];
        if (![camera selectProfile:VM27CameraProfile480p]) return 69;
        int listener = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (listener < 0) { [camera stop]; return 69; }
        struct sockaddr_vm address = {.svm_len = sizeof(address), .svm_family = AF_VSOCK,
            .svm_port = VM27_CAMERA_VSOCK_PORT, .svm_cid = VMADDR_CID_ANY};
        if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) {
            close(listener);
            [camera stop];
            return 69;
        }
        for (;;) {
            struct sockaddr_vm peer = {0};
            socklen_t length = sizeof(peer);
            int descriptor = accept(listener, (struct sockaddr *)&peer, &length);
            if (descriptor < 0) {
                if (errno == EINTR) continue;
                break;
            }
            @autoreleasepool {
                if (length == sizeof(peer) && peer.svm_family == AF_VSOCK && peer.svm_cid == VMADDR_CID_HOST)
                    [camera serve:descriptor];
                close(descriptor);
            }
        }
        close(listener);
        [camera stop];
        return 69;
    }
}
