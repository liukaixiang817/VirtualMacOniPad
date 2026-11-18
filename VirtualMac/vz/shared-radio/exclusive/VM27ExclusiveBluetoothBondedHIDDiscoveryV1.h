#import <Foundation/Foundation.h>
// Finds genuine, already-bonded HID peers in the guest's own Bluetooth stack.
// It never connects, requests pairing, or approves a pairing challenge.
@interface VM27ExclusiveBluetoothBondedHIDDiscoveryV1 : NSObject
@property(nonatomic,copy) void (^identifiersChanged)(NSSet<NSUUID *> *identifiers);
- (instancetype)initWithKnownHIDIdentifiers:(NSSet<NSUUID *> *)identifiers;
- (void)start;
- (void)invalidate;
@end
