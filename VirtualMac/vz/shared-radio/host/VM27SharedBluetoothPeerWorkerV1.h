#import <Foundation/Foundation.h>
// A guest-local protocol worker uses a fixed private NAT-to-Unix endpoint.
// Physical pairing permission remains in the host's native-connection owner.
@interface VM27SharedBluetoothPeerWorkerV1 : NSObject
@property(nonatomic,copy) void (^messageHandler)(NSDictionary *message);
@property(nonatomic,copy) void (^disconnectionHandler)(void);
@property(nonatomic,readonly) BOOL connected;
- (BOOL)start;
- (void)adoptOwnedFD:(int)fd closed:(void (^)(void))closed;
- (BOOL)sendMessage:(NSDictionary *)message;
- (void)invalidate;
@end
