#import "vm27_no_mac_event_init_port_v1.h"
_Noreturn void VM27NoMacEventV1(__attribute__((ns_consumed)) id ownedSelf,
    SEL command, __unsafe_unretained id borrowedEvent) {
    (void)command;
    (void)borrowedEvent;
    /* ARC owns exactly the caller's allocated initializer self. Release it
     * before building the diagnostic, including allocation-failure paths. */
    ownedSelf = nil;
    @throw [NSException exceptionWithName:@"VM27IndependentCapabilityUnavailable"
        reason:@"macOS CG event initialization is unavailable in the independent UIKit profile; use its owned values and genuine six-argument VZ scroll initializer"
        userInfo:@{@"capability": @"macOSCGEventInitializer", @"profile": @"independentUIKit"}];
}
