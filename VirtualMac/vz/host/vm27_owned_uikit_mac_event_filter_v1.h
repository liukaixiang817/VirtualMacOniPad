#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
typedef struct __IOHIDEvent *VM27OwnedIOHIDEventRefV1;
/* A real named object for the explicitly disabled Mac host event monitor.
 * Ordinary UIKit key/pointer packet senders remain original VZ methods.
 * Calls into this monitor never return fabricated HID reports. */
__attribute__((visibility("default")))
@interface VM27OwnedUIKitMacEventFilterV1 : NSObject
+ (BOOL)isEnabled;
+ (BOOL)hasEventTranslators;
- (NSArray *)getHIDReportsFromHIDEvent:(VM27OwnedIOHIDEventRefV1)event;
- (NSArray *)getHIDReportsFromNSEvent:(id)event;
- (void)updateCoordinateTransform:(CGRect)rect isFlipped:(BOOL)flipped;
@end
