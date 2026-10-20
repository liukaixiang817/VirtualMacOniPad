#import <Foundation/Foundation.h>
#include "vm27_no_mac_packet_port_v1.h"

static __attribute__((noreturn)) void unavailable(NSString *capability) {
    @throw [NSException exceptionWithName:@"VM27IndependentCapabilityUnavailable"
        reason:@"macOS WindowServer CG packets are unavailable in the independent UIKit profile; use its copied input values and genuine VZ input sender"
        userInfo:@{@"capability": capability, @"profile": @"independentUIKit"}];
}
void VM27RejectPacketV1(const void *allocator, const void *borrowedData) {
    (void)allocator;
    (void)borrowedData;
    unavailable(@"macOSCGPacketIngress");
}
void VM27RejectMacKeyV1(const void *source, uint16_t key, bool down) {
    (void)source;
    (void)key;
    (void)down;
    unavailable(@"macOSCGKeyboardPacket");
}
void VM27RejectFieldV1(const void *borrowedEvent, uint32_t field) {
    (void)borrowedEvent;
    (void)field;
    unavailable(@"macOSCGIntegerField");
}
