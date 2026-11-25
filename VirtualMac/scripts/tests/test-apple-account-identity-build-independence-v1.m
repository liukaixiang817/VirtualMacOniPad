#import <Foundation/Foundation.h>
#import "VMAppleAccountProfileV1.h"

#define REQUIRE(test, message) do { if (!(test)) { fprintf(stderr, "%s\n", message); return 1; } } while (0)
int main(void) {
    @autoreleasepool {
        NSMutableSet *identities = [NSMutableSet set];
        // Later entries deliberately have no audited kernel table entry.
        NSArray *builds = @[@"24G90", @"25G83", @"26A5416b", @"26B123", @"26B131", @"27A999", @"99Z123", @"100A1"];
        for (NSString *build in builds) {
            NSError *error = nil;
            NSDictionary *profile = VMAppleAccountMakeProfileV1(build, &error);
            REQUIRE(profile != nil && error == nil, "a valid restore build must receive an identity independently of kernel coverage");
            REQUIRE(VMAppleAccountProfileValidV1(profile), "generated identity failed its format contract");
            REQUIRE([profile[@"GuestBuild"] isEqual:build], "actual restore build was replaced");
            REQUIRE(![identities containsObject:profile[@"UUID"]], "independent new Macs reused an identity");
            [identities addObject:profile[@"UUID"]];
        }
        for (NSString *bad in @[@"", @"../26B131", @"26B131/", @"not-a-build", @"26B131\n", @"9999A123"])
            REQUIRE(!VMAppleAccountSupportsBuildV1(bad), "invalid build identifier accepted");
        printf("PASS: 8 known/future builds receive independent identities; malformed builds rejected\n");
    }
    return 0;
}
