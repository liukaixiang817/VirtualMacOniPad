#import <Foundation/Foundation.h>
#import "vm27_no_mac_cursor_port_v1.h"

_Noreturn void VM27NoMacV1(void) {
    @throw [NSException exceptionWithName:@"VM27IndependentCapabilityUnavailable"
        reason:@"macOS host-cursor coupling is unavailable in the independent UIKit profile; use its owned UIKit input session"
        userInfo:@{@"capability": @"macOSHostCursor", @"profile": @"independentUIKit"}];
}
