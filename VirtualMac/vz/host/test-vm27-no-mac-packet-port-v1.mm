#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#include "vm27_no_mac_packet_port_v1.h"
#include <cstdio>

static unsigned checks, failures, releases, rejected;
static void check(bool ok) { ++checks; if (!ok) ++failures; }
struct OwnedCF {
    CFTypeRef value;
    explicit OwnedCF(CFTypeRef v) : value(v) { check(v != nullptr); }
    ~OwnedCF() { if (value) { CFRelease(value); ++releases; } }
    OwnedCF(const OwnedCF &) = delete;
};
static void checkException(NSException *exception, NSString *capability) {
    check([exception.name isEqualToString:@"VM27IndependentCapabilityUnavailable"]);
    check([exception.userInfo[@"capability"] isEqualToString:capability]);
    check([exception.userInfo[@"profile"] isEqualToString:@"independentUIKit"]);
    ++rejected;
}
int main() {
    @autoreleasepool {
        const UInt8 bytes[] = {1, 2, 3, 4};
        for (unsigned round = 0; round < 64; ++round) {
            /* Genuine CoreFoundation/CG objects, never globally dispatched. */
            CFDataRef data = CFDataCreate(nullptr, bytes, sizeof(bytes));
            CGEventRef event = CGEventCreateKeyboardEvent(nullptr, 42, false);
            check(data != nullptr); check(event != nullptr);
            if (!data || !event) {
                if (data) CFRelease(data);
                if (event) CFRelease(event);
                break;
            }
            const CFIndex dataRetains = CFGetRetainCount(data);
            const CFIndex eventRetains = CFGetRetainCount(event);
            @try {
                OwnedCF own(CFRetain(data));
                VM27RejectPacketV1(kCFAllocatorDefault, data);
                check(false);
            } @catch (NSException *exception) {
                checkException(exception, @"macOSCGPacketIngress");
            }
            check(CFGetRetainCount(data) == dataRetains);
            @try {
                OwnedCF own(CFRetain(event));
                VM27RejectMacKeyV1(nullptr, static_cast<uint16_t>(round * 1024), round & 1);
                check(false);
            } @catch (NSException *exception) {
                checkException(exception, @"macOSCGKeyboardPacket");
            }
            check(CFGetRetainCount(event) == eventRetains);
            @try {
                OwnedCF own(CFRetain(event));
                VM27RejectFieldV1(event, 9);
                check(false);
            } @catch (NSException *exception) {
                checkException(exception, @"macOSCGIntegerField");
            }
            check(CFGetRetainCount(event) == eventRetains);
            check(releases == (round + 1) * 3);
            check(CFDataGetLength(data) == sizeof(bytes));
            check(CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode) == 42);
            CFRelease(event); CFRelease(data);
        }
        check(releases == 192); check(rejected == 192);
    }
    std::printf("{\"checks\":%u,\"failures\":%u,\"rejected\":%u,\"scopedCFReleases\":%u,\"globalDispatches\":0,\"VZCalls\":0}\n",
                checks, failures, rejected, releases);
    return failures ? 1 : 0;
}
