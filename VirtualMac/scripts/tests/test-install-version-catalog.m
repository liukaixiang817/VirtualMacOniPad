#import <Foundation/Foundation.h>
#import "VZRestoreCatalog.h"
#include <assert.h>

int main(void)
{
    @autoreleasepool {
        NSArray *offline = VZRestoreCatalog.bundledImages;
        NSArray *recommendations = [VZRestoreCatalog recommendedImagesFromImages:offline];
        assert(recommendations.count == 3);
        NSArray *expected = @[@"24G90", @"25G83", @"26B123"];
        for (NSUInteger i = 0; i < expected.count; i++) {
            NSDictionary *row = recommendations[i];
            assert([row[@"build"] isEqual:expected[i]]);
            assert([VZRestoreCatalog isVerifiedAppleAccountImage:row]);
            assert([row[@"url"] hasPrefix:@"https://updates.cdn-apple.com/"]);
            assert([row[@"downloadSize"] unsignedLongLongValue] > 1000000000ULL);
        }
        // A future, unverified release is still a choice. It must not replace
        // the recommended build or inherit the verified-account label.
        NSDictionary *future = @{@"name":@"macOS 27.2.1", @"version":@"27.2.1",
            @"build":@"26B999", @"group":@"goldengate", @"channel":@"regular",
            @"url":@"https://example.invalid/future.ipsw"};
        NSMutableDictionary *conflict = [[recommendations[0] mutableCopy] autorelease];
        conflict[@"url"] = @"https://example.invalid/unverified-replacement.ipsw";
        NSArray *merged = [VZRestoreCatalog imagesByMergingImages:@[future, conflict]
                                             withBundledImages:offline];
        assert([merged containsObject:future]);
        assert(![VZRestoreCatalog isVerifiedAppleAccountImage:future]);
        assert([[VZRestoreCatalog displayNameForImage:future compact:NO] containsString:@"27.2.1"]);
        assert([[VZRestoreCatalog recommendedImageFromImages:merged][@"build"] isEqual:@"24G90"]);
        NSArray *again = [VZRestoreCatalog recommendedImagesFromImages:merged];
        assert(again.count == 3 && [again[0][@"url"] isEqual:recommendations[0][@"url"]]);
        NSMutableSet *builds = [NSMutableSet set];
        for (NSDictionary *row in merged) {
            NSString *build = row[@"build"];
            if (!build.length) continue;
            assert(![builds containsObject:build]);
            [builds addObject:build];
        }
        assert([VZRestoreCatalog recommendedImagesFromImages:@[future]].count == 0);
        puts("PASS: offline recommendations, version visibility, verified labels, pinned URLs and merged build uniqueness");
    }
}
