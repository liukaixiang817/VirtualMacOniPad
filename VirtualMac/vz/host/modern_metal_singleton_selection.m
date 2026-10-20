// Source contract for the two-branch, application-private VZ iOS port.
// The owned array has the documented iOS Metal shape: zero or one native
// default device. Device selection in that domain is independent of the Mac
// catalog's power/removability preference. No device properties are fabricated.
#import <Foundation/Foundation.h>
#include <stdint.h>

id vm27_metal_select_singleton_owned_array(NSArray *ownedDevices, uint32_t preference)
    __attribute__((ns_returns_not_retained));
id vm27_metal_select_singleton_owned_array(NSArray *ownedDevices, uint32_t preference) {
    (void)preference;
    id selected = nil;
    @try {
        NSUInteger count = [ownedDevices count];
        if (count > 1) {
            @throw [NSException exceptionWithName:NSInvalidArgumentException
                reason:@"The iOS singleton Metal selection contract requires at most one device."
                userInfo:nil];
        }
        if (count == 1) selected = [[ownedDevices objectAtIndex:0] retain];
    } @finally {
        // Consume the +1 collection. The independently retained original
        // device remains alive; the C ABI returns it with the original +0 rule.
        [ownedDevices release];
    }
    return [selected autorelease];
}
