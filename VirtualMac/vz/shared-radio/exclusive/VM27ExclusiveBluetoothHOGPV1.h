#import <Foundation/Foundation.h>

// Guest-side HID over the guest's own native GATT connection. This class never
// pairs devices. It only reconnects peers that are already bonded in macOS.
@interface VM27ExclusiveBluetoothHOGPV1 : NSObject
@property(nonatomic,copy) void (^statusHandler)(NSDictionary *status);
@property(nonatomic,readonly,getter=isClosed) BOOL closed;
// Preserve a bonded connection while the system's native HID profile owns
// input. Used to verify and avoid duplicate fallback/native input devices.
@property(nonatomic) BOOL nativeHIDOnly;
- (instancetype)initWithIdentifier:(NSUUID *)identifier;
- (void)start;
- (void)invalidate;
@end
