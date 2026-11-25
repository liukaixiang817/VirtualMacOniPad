#import <Foundation/Foundation.h>
#import "VZRestoreCatalog.h"

#define REQUIRE(test, message) do { if (!(test)) { fprintf(stderr, "%s\n", message); return 1; } } while (0)
int main(int argc, char **argv) {
    @autoreleasepool {
        REQUIRE(argc == 2, "actual Apple catalog fixture required");
        NSData *actual = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
        NSArray *latest = [VZRestoreCatalog imagesFromAppleCatalogData:actual error:NULL];
        REQUIRE(latest.count > 0, "official VirtualMac catalog must produce restore images");
        REQUIRE([latest[0][@"build"] isEqual:@"26B131"], "actual current Apple build missing");

        NSDictionary *restore = @{ @"BuildVersion":@"27A999", @"ProductVersion":@"28.1",
            @"FirmwareURL":@"https://updates.cdn-apple.com/test/UniversalMac_28.1_27A999_Restore.ipsw" };
        NSDictionary *fixture = @{ @"MobileDeviceSoftwareVersionsByVersion":@{
            @"1":@{ @"MobileDeviceSoftwareVersions":@{
                @"VirtualMac3,1":@{ @"27A999":@{ @"Restore":restore } } } } } };
        NSData *futureData = [NSPropertyListSerialization dataWithPropertyList:fixture
            format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        NSArray *future = [VZRestoreCatalog imagesFromAppleCatalogData:futureData error:NULL];
        REQUIRE(future.count == 1, "new VirtualMac product and future OS must remain discoverable");
        REQUIRE([VZRestoreCatalog majorVersionForImage:future[0]] == 28, "future major must parse without a marketing-name entry");
        REQUIRE(![VZRestoreCatalog isUnsupportedImage:future[0]], "future release must not be hidden by a hardcoded maximum");
        NSArray *merged = [VZRestoreCatalog imagesByMergingImages:future withBundledImages:latest];
        REQUIRE(merged.count == latest.count + 1, "offline/history choices must survive a live update");
        NSArray *groups = [VZRestoreCatalog orderedGroupsForImages:merged];
        REQUIRE([groups.firstObject isEqual:future[0][@"group"]], "new major must sort before old known release names");
        NSArray *offline = [VZRestoreCatalog imagesByMergingImages:@[] withBundledImages:latest];
        REQUIRE(offline.count >= latest.count, "offline fallback must preserve known images");
        printf("PASS: official live catalog, future product/major, group ordering, merging and offline fallback\n");
    }
    return 0;
}
