#import "vm27_display_services_unavailable_v1.h"
#include <errno.h>

@implementation VM27DSClientV1
- (void)doesNotRecognizeSelector:(SEL)selector {
    [NSException raise:@"VM27UnavailableDisplayServices"
                format:@"Mac physical display service %@ is unavailable in the own UIKit profile",
                       NSStringFromSelector(selector)];
}
@end

int32_t VM27PluginUnavailableV1(const char *path, uint64_t flags,
                              const void *requirement) {
    if (!path || !path[0] || flags != UINT64_C(2) || !requirement)
        return EINVAL;
    return ENOTSUP;
}

/* Adapted from vm27_mac_display_unavailable_v1.m: preserve actual pointer /
 * float calling conventions and raise rather than publishing a fake value. */
static __attribute__((noreturn)) void UnavailableMacDisplayQueryV1(
    NSString *entry, uint32_t displayID) {
    @throw [NSException exceptionWithName:@"VM27UnsupportedMacDisplayProfile"
        reason:[NSString stringWithFormat:@"%@ requires unavailable Mac display ID %u",
                                           entry, displayID]
        userInfo:nil];
}
struct CGColorSpace *VM27CGUnavailableV1(uint32_t displayID) {
    UnavailableMacDisplayQueryV1(@"CGDisplayCopyColorSpace", displayID);
}
float VM27HeadroomUnavailableV1(uint32_t displayID) {
    UnavailableMacDisplayQueryV1(@"SLSDisplayGetPotentialHeadroom", displayID);
}
