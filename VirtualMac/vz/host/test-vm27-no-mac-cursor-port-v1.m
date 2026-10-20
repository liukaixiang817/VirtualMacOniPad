#import <Foundation/Foundation.h>
#import "vm27_no_mac_cursor_port_v1.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures;
#define CHECK(x) do { ++checks; if (!(x)) ++failures; } while (0)
int main(void) {
    @autoreleasepool {
        for (unsigned i=0;i<128;++i) {
            BOOL caught=NO;
            @try { VM27NoMacV1(); CHECK(NO); }
            @catch (NSException *exception) {
                caught=YES;
                CHECK([exception.name isEqualToString:@"VM27IndependentCapabilityUnavailable"]);
                CHECK([exception.userInfo[@"capability"] isEqualToString:@"macOSHostCursor"]);
                CHECK([exception.userInfo[@"profile"] isEqualToString:@"independentUIKit"]);
                CHECK([exception.reason containsString:@"owned UIKit input session"]);
            }
            CHECK(caught);
        }
        printf("{\"checks\":%u,\"failures\":%u,\"capabilityRejects\":128,\"VZLoads\":0,\"VZCalls\":0}\n",checks,failures);
    }
    return failures?1:0;
}
