#import <Foundation/Foundation.h>
@interface VM27SharedBluetoothHostV1 : NSObject
- (NSDictionary *)start;
// Initializes the guest virtual transport without any CoreBluetooth RF client.
- (NSDictionary *)startExclusiveControllerLifecycle;
- (void)adoptNativePeerFD:(int)fd closed:(void (^)(void))closed;
- (void)probeAcceptanceMouseGATTWithCompletion:(void (^)(NSDictionary *))completion;
- (void)invalidate;
@end
