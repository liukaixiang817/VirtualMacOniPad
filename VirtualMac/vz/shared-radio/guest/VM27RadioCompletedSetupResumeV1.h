#pragma once
#import <Foundation/Foundation.h>

// loginwindow can retain the already-finished first-run assistant in its
// per-host Resume list. Keep every other app and every unknown row intact.
static inline NSArray *VM27RadioPrunedSetupResumeV1(id value, NSUInteger *removed) {
    if (removed) *removed = 0;
    if (![value isKindOfClass:NSArray.class] || [value count] > 64) return nil;
    NSMutableArray *result = [NSMutableArray array];
    for (id row in value) {
        BOOL setup = [row isKindOfClass:NSDictionary.class] &&
            [row[@"BundleID"] isKindOfClass:NSString.class] &&
            [row[@"BundleID"] caseInsensitiveCompare:@"com.apple.SetupAssistant"] == NSOrderedSame &&
            [row[@"Path"] isEqual:@"/System/Library/CoreServices/Setup Assistant.app"];
        if (setup) { if (removed) ++*removed; }
        else [result addObject:row];
    }
    return result;
}

static inline BOOL VM27RadioSetupPreferencesCompletedV1(NSDictionary *preferences, NSString *build) {
    return [preferences[@"LastSeenBuddyBuildVersion"] isEqual:build] &&
        [preferences[@"DidSeeCloudSetup"] isEqual:@YES] &&
        [preferences[@"MiniBuddyShouldLaunchToResumeSetup"] isEqual:@NO];
}
