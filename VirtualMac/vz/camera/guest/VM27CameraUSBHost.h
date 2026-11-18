#import <Foundation/Foundation.h>
#import "usb_camera.h"

NS_ASSUME_NONNULL_BEGIN

// A single UVC device on one software USB port in the macOS guest.
@interface VM27CameraUSBHost : NSObject
- (instancetype)initWithDevice:(HvUsbCamera *)camera;
- (BOOL)startWithError:(NSError **)error;
- (void)stop;
@end

NS_ASSUME_NONNULL_END
