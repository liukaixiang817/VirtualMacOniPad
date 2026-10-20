#import <Foundation/Foundation.h>
#include "vm27_mac_input_unavailable_v1.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    unsigned calls = 0, caught = 0, failures = 0;
    @autoreleasepool {
        /* An invalid non-null pointer must not be dereferenced. Each ABI
         * shape throws the exact unavailable exception and never returns. */
        for (unsigned i = 0; i != 3; ++i) {
            const char *entries[] = {"NSTouch metadata", "SLEventGetDoubleValueField", "SLEventGetIntegerValueField"};
            @try {
                ++calls;
                if (i == 0) VM27MacInputUnavailableV1();
                else if (i == 1) (void)VM27MacDoubleUnavailableV1((void *)(uintptr_t)1, INT32_MIN);
                else (void)VM27MacIntegerUnavailableV1((void *)(uintptr_t)1, INT32_MAX);
                ++failures;
            } @catch (NSException *e) {
                ++caught;
                if (![e.name isEqualToString:@"VM27UnsupportedMacInputProfile"] ||
                    ![e.reason containsString:[NSString stringWithUTF8String:entries[i]]]) ++failures;
            }
        }
    }
    printf("{\"calls\":%u,\"caught\":%u,\"failures\":%u,\"originalUHKExecuted\":false,\"deviceOperations\":0}\n",calls,caught,failures);
    return failures ? 1 : 0;
}
