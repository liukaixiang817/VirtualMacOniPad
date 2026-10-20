#import <Foundation/Foundation.h>
#include "modern_input_packet_v2.h"

NS_ASSUME_NONNULL_BEGIN
/* Own copied packet lifetime. The owner is retained until this lease drains. */
@interface VM27InputPacketLeaseV2 : NSObject
- (const VM27InputPacket * _Nullable)packet;
- (BOOL)isCurrent;
/* Atomic admission under the queue's mutex. Close waits for the synchronous
 * sink. The sink must be bounded and must not reenter this queue/lease, close
 * its session, or wait synchronously for the receiving UIKit thread. */
- (VM27InputResult)deliverToSink:(VM27InputDelivery _Nullable)sink context:(void * _Nullable)context;
- (instancetype)init NS_UNAVAILABLE;
@end
NS_ASSUME_NONNULL_END
