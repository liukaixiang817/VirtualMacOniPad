#import <CoreImage/CoreImage.h>
#import <CoreMedia/CoreMedia.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(uint8_t, VM27CameraProfile) {
    VM27CameraProfile480p,
    VM27CameraProfile720p,
    VM27CameraProfile1080p,
};

// Keep a single bound for the encoder and the receiver, including 1080p.
enum { VM27CameraMaxJPEGBytes = 1920 * 1080 * 2 };

CMVideoDimensions VM27CameraDimensions(VM27CameraProfile profile);

NSData * _Nullable VM27CameraEncodeJPEG(CIContext *context, CIImage *image,
                                        VM27CameraProfile profile, BOOL mirrored);
NSData * _Nullable VM27CameraEncodeNV12JPEG(CVPixelBufferRef _Nullable pixels,
                                            VM27CameraProfile profile, BOOL mirrored);

// An empty JPEG represents a closed or unavailable camera. Unsupported JPEG
// dimensions are discarded, including a frame from a previous profile.
CVPixelBufferRef _Nullable VM27CameraCreateOutput(CIContext *context, NSData * _Nullable jpeg,
                                                  VM27CameraProfile profile) CF_RETURNS_RETAINED;

NS_ASSUME_NONNULL_END
