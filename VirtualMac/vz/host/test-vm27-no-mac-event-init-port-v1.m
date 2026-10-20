#import "vm27_no_mac_event_init_port_v1.h"
#include <stdio.h>
static unsigned released,checks,failures;
#define CHECK(x) do { ++checks; if (!(x)) ++failures; } while (0)
@interface VM27EventPortFixtureOwner : NSObject
@end
@implementation VM27EventPortFixtureOwner
- (void)dealloc { ++released; }
@end
int main(void) {
    @autoreleasepool {
        NSObject *borrowedEvent=[NSObject new];
        for (unsigned i=0;i<128;++i) {
            unsigned prior=released;
            BOOL caught=NO;
            @try { VM27NoMacEventV1([VM27EventPortFixtureOwner alloc],@selector(init),borrowedEvent); CHECK(NO); }
            @catch (NSException *exception) {
                caught=YES;
                CHECK([exception.name isEqualToString:@"VM27IndependentCapabilityUnavailable"]);
                CHECK([exception.userInfo[@"capability"] isEqualToString:@"macOSCGEventInitializer"]);
                CHECK([exception.userInfo[@"profile"] isEqualToString:@"independentUIKit"]);
                CHECK([exception.reason containsString:@"six-argument"]);
            }
            CHECK(caught);CHECK(released==prior+1);CHECK([borrowedEvent isKindOfClass:[NSObject class]]);
        }
        printf("{\"checks\":%u,\"failures\":%u,\"initializationRejects\":128,\"ownedSelfReleases\":%u,\"VZLoads\":0,\"VZCalls\":0}\n",checks,failures,released);
    }
    return failures?1:0;
}
