#ifndef VM27_OWNED_VZ_LOCALIZATION_V1_H
#define VM27_OWNED_VZ_LOCALIZATION_V1_H
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Own presentation API for the selected parent VZ localizer call. The actual
 * cached bundle and retained English key are supplied by the original caller.
 * A missing translation resource changes neither its error code nor reason.
 * This returns +0, matching the original retain-autorelease caller sequence. */
__attribute__((visibility("default"), ns_returns_not_retained))
NSString * _Nonnull VM27OwnedVZLocalizedStringOrEnglishKeyV1(
    NSBundle * _Nullable actualBundle, NSString * _Nullable originalKey);
#ifdef __cplusplus
}
#endif
#endif
