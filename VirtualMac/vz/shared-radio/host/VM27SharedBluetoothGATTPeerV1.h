#import <Foundation/Foundation.h>

// One native guest connection owns one actual CoreBluetooth connection.
// Attribute IDs are connection-local opaque tokens, independent of UUID and
// device name. Repeated services/characteristics remain distinct.
@interface VM27SharedBluetoothGATTPeerV1 : NSObject
@property(nonatomic,copy) void (^notificationHandler)(NSDictionary *event);
@property(nonatomic,copy) void (^pairingChallengeHandler)(NSDictionary *challenge);
- (instancetype)initWithIdentifier:(NSUUID *)identifier
    newPairingPermission:(BOOL (^)(void))permission;
- (void)connectWithCompletion:(void (^)(NSDictionary *result))completion;
// Reconnect only after the native guest pairing agent confirms an existing
// bond. No connection or pairing request is sent for an unpaired peer.
- (void)connectBondedWithCompletion:(void (^)(NSDictionary *result))completion;
- (void)performOperation:(NSDictionary *)operation
    completion:(void (^)(NSDictionary *result))completion;
- (void)invalidate;
@end
