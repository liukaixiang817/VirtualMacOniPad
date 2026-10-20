#import "vm27_owned_vz_localization_v1.h"
#include <stdio.h>

NSString *VM27OwnedVZLocalizedStringOrEnglishKeyV1(
    NSBundle *actualBundle, NSString *originalKey) {
    if (!originalKey || ![originalKey isKindOfClass:[NSString class]]) {
        [NSException raise:NSInvalidArgumentException
                    format:@"Own VZ presentation requires the original NSString key"];
    }
    if (actualBundle && ![actualBundle isKindOfClass:[NSBundle class]]) {
        [NSException raise:NSInvalidArgumentException
                    format:@"Own VZ presentation requires the actual NSBundle or nil"];
    }
    /* Keep the actual native bundle lookup and message semantics. Any real
     * translation exception propagates to the original caller's unwind path. */
    NSString *translation = actualBundle
        ? [actualBundle localizedStringForKey:originalKey value:nil table:nil]
        : nil;
    if (translation) {
        if (![translation isKindOfClass:[NSString class]]) {
            [NSException raise:NSInvalidArgumentException
                        format:@"Actual VZ translation did not return NSString"];
        }
        return translation;
    }
    fprintf(stderr, "[VM27OwnedVZLocalizationV1] bundleAvailable=%d localizationDeferred=1 returnedOriginalEnglishKey=1 errorSemanticsUnchanged=1\n",
            actualBundle != nil);
    return originalKey;
}
