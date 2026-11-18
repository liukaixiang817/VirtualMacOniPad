#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
/* One instance per VM connection. Operations execute on the main run loop.
 * Shared Wi-Fi attachment uses the host's existing authenticated association;
 * guest power/disconnect never powers down or disconnects the iPad radio. */
@interface VM27SharedRadioHostV1 : NSObject
- (void)request:(NSDictionary *)request completion:(void (^)(NSDictionary *reply))completion;
- (void)adoptBluetoothPeerFD:(int)fd closed:(void (^)(void))closed;
- (void)invalidate;
@end
NS_ASSUME_NONNULL_END
