#import "modern_processed_scroll_sink_v1.h"
@implementation VM27NativeProcessedScrollSinkV1 {
    id<VM27NativeProcessedScrollReceiverV1> _receiver;
}
- (instancetype)initWithReceiver:(id<VM27NativeProcessedScrollReceiverV1>)receiver {
    if (!receiver) return nil;
    self = [super init];
    if (self) _receiver = receiver;
    return self;
}
- (VM27InputResult)consumeCopiedInputPacket:(const VM27InputPacket *)packet {
    CFTypeRef event = NULL;
    VM27InputResult result = vm27_processed_scroll_create_owned(packet, &event);
    if (result != VM27InputOK) return result;
    @try {
        result = [_receiver consumeNativeProcessedScroll:event epoch:packet->owner_epoch
            sequence:packet->event_sequence coordinates:packet->coordinate_generation];
    } @catch (NSException *exception) {
        (void)exception;
        result = VM27InputInvalid;
    } @finally {
        vm27_processed_scroll_release_owned(&event);
    }
    return result;
}
@end
