#import "modern_input_packet_lease_private_v2.h"

#if !__has_feature(objc_arc)
#error Own copied input lease requires ARC.
#endif

@interface VM27InputPacketLeaseV2 ()
- (instancetype)initWithOwner:(id)owner lease:(VM27InputLease *)lease;
@end

typedef struct { VM27InputDelivery sink; void *context; } VM27OwnDeliveryV2;
static VM27InputResult protected_delivery(const VM27InputPacket *packet, void *opaque)
{
    VM27OwnDeliveryV2 *delivery = opaque;
    @try { return delivery->sink(packet, delivery->context); }
    @catch (NSException *exception) { (void)exception; return VM27InputInvalid; }
}

@implementation VM27InputPacketLeaseV2 {
    id _owner;
    VM27InputLease *_lease;
}
- (instancetype)initWithOwner:(id)owner lease:(VM27InputLease *)lease
{
    self = [super init];
    if (self) { _owner = owner; _lease = lease; }
    return self;
}
- (const VM27InputPacket *)packet { return vm27_input_lease_packet(_lease); }
- (BOOL)isCurrent { return vm27_input_lease_is_current(_lease); }
- (VM27InputResult)deliverToSink:(VM27InputDelivery)sink context:(void *)context
{
    if (!sink) return VM27InputInvalid;
    VM27OwnDeliveryV2 delivery = { sink, context };
    return vm27_input_lease_deliver(_lease, protected_delivery, &delivery);
}
- (void)dealloc { vm27_input_lease_release(&_lease); }
@end

VM27InputPacketLeaseV2 *vm27_input_objc_lease_take_v2(id owner, VM27InputLease **lease)
{
    if (!owner || !lease || !*lease) return nil;
    VM27InputPacketLeaseV2 *wrapper = [[VM27InputPacketLeaseV2 alloc] initWithOwner:owner lease:*lease];
    if (wrapper) *lease = NULL;
    return wrapper;
}
