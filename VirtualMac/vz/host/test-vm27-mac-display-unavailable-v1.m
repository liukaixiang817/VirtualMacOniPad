#import <Foundation/Foundation.h>
#include "vm27_mac_display_unavailable_v1.h"
#include <stdio.h>
int main(void) {
    unsigned calls=0,caught=0,failures=0;
    @autoreleasepool {
        for(unsigned i=0;i<2;++i) {
            @try {
                ++calls;
                if(i==0) (void)VM27MacDisplayColorSpaceUnavailableV1(UINT32_MAX);
                else (void)VM27MacDisplayHeadroomUnavailableV1(1);
                ++failures;
            } @catch(NSException *error) {
                ++caught;
                if(![error.name isEqualToString:@"VM27UnsupportedMacDisplayProfile"] ||
                   ![error.reason containsString:i==0?@"CGDisplayCopyColorSpace":@"SLSDisplayGetPotentialHeadroom"])
                    ++failures;
            }
        }
    }
    printf("{\"calls\":%u,\"caught\":%u,\"failures\":%u,\"originalVMMExecuted\":false,\"deviceOperations\":0}\n",calls,caught,failures);
    return failures?1:0;
}
