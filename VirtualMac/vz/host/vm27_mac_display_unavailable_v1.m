#import <Foundation/Foundation.h>
#include "vm27_mac_display_unavailable_v1.h"

static __attribute__((noreturn)) void Unsupported(NSString *entry,uint32_t displayID) {
    @throw [NSException exceptionWithName:@"VM27UnsupportedMacDisplayProfile"
        reason:[NSString stringWithFormat:
            @"%@ requires a macOS display ID (%u); this owned UIKit profile has no Mac display service",
            entry,displayID] userInfo:nil];
}
struct CGColorSpace *VM27MacDisplayColorSpaceUnavailableV1(uint32_t displayID) {
    Unsupported(@"CGDisplayCopyColorSpace",displayID);
}
float VM27MacDisplayHeadroomUnavailableV1(uint32_t displayID) {
    Unsupported(@"SLSDisplayGetPotentialHeadroom",displayID);
}
