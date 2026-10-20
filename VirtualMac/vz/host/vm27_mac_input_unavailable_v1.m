#import <Foundation/Foundation.h>
#include "vm27_mac_input_unavailable_v1.h"

/* The selected profile has a separate, actual UIKit ingress. Entering a
 * copied MacView-only path is an explicit unavailable capability. In
 * particular, a nonoptional Swift metadata accessor cannot return nil. */
static __attribute__((noreturn)) void Unavailable(NSString *entry) {
    @throw [NSException exceptionWithName:@"VM27UnsupportedMacInputProfile"
        reason:[NSString stringWithFormat:
            @"%@ requires the unavailable macOS MacView input profile; use the owned UIKit ingress", entry]
        userInfo:nil];
}
void VM27MacInputUnavailableV1(void) { Unavailable(@"NSTouch metadata"); }
double VM27MacDoubleUnavailableV1(const void *event, int32_t field) {
    (void)event; (void)field;
    Unavailable(@"SLEventGetDoubleValueField");
}
int64_t VM27MacIntegerUnavailableV1(const void *event, int32_t field) {
    (void)event; (void)field;
    Unavailable(@"SLEventGetIntegerValueField");
}
