#import "vm27_owned_vz_localization_v1.h"
#include <stdio.h>

static unsigned checks;
static void Check(BOOL value) {
    ++checks;
    if (!value) [NSException raise:@"VM27LocalizationFixtureFailure"
                             format:@"Actual Foundation check %u failed", checks];
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 2) return 64;
        NSString *path = [NSString stringWithUTF8String:argv[1]];
        NSBundle *actualBundle = [NSBundle bundleWithPath:path];
        Check(actualBundle != nil);
        NSString *key = [@"Internal Virtualization " stringByAppendingString:@"error."];
        NSString *missing = [@"Failure reason " stringByAppendingString:@"not translated."];
        NSString *fallback = VM27OwnedVZLocalizedStringOrEnglishKeyV1(nil, key);
        Check(fallback == key);
        Check([fallback isEqualToString:@"Internal Virtualization error."]);
        NSString *translated = VM27OwnedVZLocalizedStringOrEnglishKeyV1(actualBundle, key);
        Check([translated isEqualToString:@"Verified real resource translation"]);
        Check([VM27OwnedVZLocalizedStringOrEnglishKeyV1(actualBundle, missing)
               isEqualToString:missing]);
        NSDictionary *details = @{NSLocalizedFailureErrorKey: fallback,
                                   NSLocalizedFailureReasonErrorKey: missing};
        NSError *actualError = [NSError errorWithDomain:@"VM27FixtureOriginalError"
                                                  code:1 userInfo:details];
        Check(actualError.code == 1);
        Check([actualError.userInfo[NSLocalizedFailureReasonErrorKey] isEqual:missing]);
        BOOL rejectedKey = NO;
        @try { (void)VM27OwnedVZLocalizedStringOrEnglishKeyV1(nil, nil); }
        @catch (NSException *error) { rejectedKey = [error.name isEqual:NSInvalidArgumentException]; }
        Check(rejectedKey);
        BOOL rejectedBundle = NO;
        @try { (void)VM27OwnedVZLocalizedStringOrEnglishKeyV1((NSBundle *)(id)key, key); }
        @catch (NSException *error) { rejectedBundle = [error.name isEqual:NSInvalidArgumentException]; }
        Check(rejectedBundle);
        NSString *held;
        @autoreleasepool {
            NSString *temporary = [@"Original " stringByAppendingString:@"key ownership"];
            held = VM27OwnedVZLocalizedStringOrEnglishKeyV1(nil, temporary);
        }
        Check([held isEqualToString:@"Original key ownership"]);
        printf("actualFoundationChecks=%u nativeBundleResource=1 originalErrorCode=1\n", checks);
    }
    return 0;
}
