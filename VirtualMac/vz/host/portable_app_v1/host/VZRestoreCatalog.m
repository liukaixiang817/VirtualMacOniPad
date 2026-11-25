#import "VZRestoreCatalog.h"

static NSString * const VZCatalogURL =
    @"https://api.virtualbuddy.app/v2/restore/mac?apiKey=15A25D48-4A34-4EE4-A293-C22B0DE1B54E";
static NSString * const VZAppleCatalogURL =
    @"https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml";

static NSArray<NSDictionary *> *VZVerifiedRestoreImages(void)
{
    static NSArray *images;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = [NSBundle.mainBundle pathForResource:@"RecommendedRestoreImages" ofType:@"plist"];
        NSDictionary *catalog = path ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
        NSArray *rows = [catalog[@"Images"] isKindOfClass:NSArray.class] ? catalog[@"Images"] : @[];
        images = [rows copy];
    });
    return images;
}

static NSString *VZRestoreString(id value)
{
    return [value isKindOfClass:NSString.class] ? value : @"";
}

// Keep every release identity in one table. Catalog grouping, user-facing
// names, restore-image inference, installer artwork, and library wallpaper
// selection must all resolve through these records so a newly supported
// macOS release cannot acquire conflicting names in different screens.
static NSArray<NSDictionary *> *VZMacOSReleaseIdentities(void)
{
    static NSArray *identities;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        identities = [@[
            @{ @"major": @12, @"group": @"monterey",
               @"marketing": @"Monterey", @"artwork": @"monterey",
               @"aliases": @[@"monterey"] },
            @{ @"major": @13, @"group": @"ventura",
               @"marketing": @"Ventura", @"artwork": @"ventura",
               @"aliases": @[@"ventura"] },
            @{ @"major": @14, @"group": @"sonoma",
               @"marketing": @"Sonoma", @"artwork": @"sonoma",
               @"aliases": @[@"sonoma"] },
            @{ @"major": @15, @"group": @"sequoia",
               @"marketing": @"Sequoia", @"artwork": @"sequoia",
               @"aliases": @[@"sequoia"] },
            @{ @"major": @26, @"group": @"tahoe",
               @"marketing": @"Tahoe", @"artwork": @"tahoe",
               @"aliases": @[@"tahoe"] },
            @{ @"major": @27, @"group": @"goldengate",
               @"marketing": @"Golden Gate", @"artwork": @"golden-gate",
               @"aliases": @[@"golden gate", @"golden-gate",
                                @"goldengate"] },
        ] retain];
    });
    return identities;
}

static NSDictionary *VZMacOSIdentityForMajor(NSInteger major)
{
    for (NSDictionary *identity in VZMacOSReleaseIdentities())
        if ([identity[@"major"] integerValue] == major)
            return identity;
    return nil;
}

static NSDictionary *VZMacOSIdentityForGroup(NSString *group)
{
    NSString *lower = group.lowercaseString;
    for (NSDictionary *identity in VZMacOSReleaseIdentities()) {
        if ([identity[@"group"] isEqualToString:lower])
            return identity;
        for (NSString *alias in identity[@"aliases"])
            if ([alias isEqualToString:lower])
                return identity;
    }
    return nil;
}

static NSDictionary *VZMacOSIdentityInText(NSString *text)
{
    NSString *lower = text.lowercaseString;
    for (NSDictionary *identity in VZMacOSReleaseIdentities())
        for (NSString *alias in identity[@"aliases"])
            if ([lower containsString:alias])
                return identity;
    return nil;
}

static NSString *VZRestoreVersionFromText(NSString *text)
{
    NSRegularExpression *expression = [NSRegularExpression
        regularExpressionWithPattern:@"[0-9]+(?:\\.[0-9]+){0,2}"
        options:0 error:nil];
    NSTextCheckingResult *match = [expression firstMatchInString:text
        options:0 range:NSMakeRange(0, text.length)];
    return match ? [text substringWithRange:match.range] : @"";
}

static NSInteger VZRestoreMajorVersionFromText(NSString *text)
{
    NSDictionary *identity = VZMacOSIdentityInText(text);
    if (identity)
        return [identity[@"major"] integerValue];
    NSString *version = VZRestoreVersionFromText(text);
    NSScanner *scanner = [NSScanner scannerWithString:version];
    NSInteger major = 0;
    if (![scanner scanInteger:&major] || major < 10)
        return 0;
    return major;
}

static NSDictionary *VZMacOSIdentityForImage(NSDictionary *image)
{
    NSDictionary *identity = VZMacOSIdentityForGroup(
        VZRestoreString(image[@"group"]));
    if (identity)
        return identity;
    NSInteger major = VZRestoreMajorVersionFromText(
        VZRestoreString(image[@"version"]));
    if (major == 0)
        major = VZRestoreMajorVersionFromText(VZRestoreString(image[@"name"]));
    return VZMacOSIdentityForMajor(major);
}

@implementation VZRestoreCatalog

+ (NSArray *)imagesFromData:(NSData *)data error:(NSError **)error
{
    if (!data.length) return nil;
    NSDictionary *root = [NSJSONSerialization JSONObjectWithData:data options:0 error:error];
    NSArray *images = [root isKindOfClass:NSDictionary.class]
        ? root[@"restoreImages"] : nil;
    if (![images isKindOfClass:NSArray.class])
        return nil;
    NSMutableArray *normalized = [NSMutableArray array];
    for (id candidate in images) {
        if (![candidate isKindOfClass:NSDictionary.class])
            continue;
        NSMutableDictionary *image = [NSMutableDictionary
            dictionaryWithDictionary:candidate];
        NSString *urlString = VZRestoreString(image[@"url"]);
        NSURL *url = [NSURL URLWithString:urlString];
        if (!url.host.length ||
            !([url.scheme.lowercaseString isEqualToString:@"https"] ||
              [url.scheme.lowercaseString isEqualToString:@"http"]))
            continue;
        NSString *name = VZRestoreString(image[@"name"]);
        NSString *version = VZRestoreString(image[@"version"]);
        if (!version.length)
            version = VZRestoreVersionFromText(name);
        NSString *group = VZRestoreString(image[@"group"]).lowercaseString;
        NSDictionary *groupIdentity = VZMacOSIdentityForGroup(group);
        if (groupIdentity) {
            group = groupIdentity[@"group"];
        } else if (!group.length) {
            NSInteger major = VZRestoreMajorVersionFromText(version);
            NSDictionary *identity = VZMacOSIdentityForMajor(major);
            group = identity[@"group"] ?: (major > 0
                ? [NSString stringWithFormat:@"macos-%ld", (long)major]
                : @"unknown");
        }
        NSString *channel = VZRestoreString(image[@"channel"]).lowercaseString;
        if (![channel isEqualToString:@"regular"] &&
            ![channel isEqualToString:@"devbeta"])
            channel = [channel containsString:@"beta"] ? @"devbeta" : @"regular";
        if (!name.length)
            name = version.length ? [NSString stringWithFormat:@"macOS %@", version]
                                  : url.lastPathComponent;
        image[@"url"] = url.absoluteString;
        image[@"name"] = name ?: @"macOS";
        image[@"version"] = version ?: @"";
        image[@"group"] = group;
        image[@"channel"] = channel;
        image[@"build"] = VZRestoreString(image[@"build"]);
        image[@"downloadSize"] = @([image[@"downloadSize"] longLongValue]);
        [normalized addObject:image];
    }
    return normalized;
}

+ (NSArray<NSDictionary *> *)imagesFromAppleCatalogData:(NSData *)data error:(NSError **)error
{
    if (!data.length || data.length > 16 * 1024 * 1024) return nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:NULL error:error];
    if (![plist isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *versions = plist[@"MobileDeviceSoftwareVersionsByVersion"];
    if (![versions isKindOfClass:NSDictionary.class]) return nil;
    NSMutableArray *rows = [NSMutableArray array];
    for (id version in versions.allValues) {
        if (![version isKindOfClass:NSDictionary.class]) continue;
        NSDictionary *devices = version[@"MobileDeviceSoftwareVersions"];
        if (![devices isKindOfClass:NSDictionary.class]) continue;
        for (NSString *product in devices) {
            if (![product isKindOfClass:NSString.class] || ![product hasPrefix:@"VirtualMac"] ||
                ![devices[product] isKindOfClass:NSDictionary.class]) continue;
            for (id build in [devices[product] allValues]) {
                if (![build isKindOfClass:NSDictionary.class]) continue;
                id restore = build[@"Restore"];
                if (![restore isKindOfClass:NSDictionary.class]) continue;
                NSURL *url = [NSURL URLWithString:VZRestoreString(restore[@"FirmwareURL"])];
                NSString *host = url.host.lowercaseString;
                NSString *os = VZRestoreString(restore[@"ProductVersion"]);
                NSString *number = VZRestoreString(restore[@"BuildVersion"]);
                if (![url.scheme.lowercaseString isEqualToString:@"https"] ||
                    !([host hasSuffix:@".apple.com"] || [host hasSuffix:@".cdn-apple.com"]) ||
                    ![url.path.pathExtension.lowercaseString isEqualToString:@"ipsw"] ||
                    !os.length || !number.length) continue;
                [rows addObject:@{ @"name":[@"macOS " stringByAppendingString:os],
                    @"version":os, @"build":number, @"url":url.absoluteString,
                    @"channel":@"regular", @"catalogSource":@"apple" }];
            }
        }
    }
    NSData *normalized = [NSJSONSerialization dataWithJSONObject:@{ @"restoreImages":rows }
        options:0 error:error];
    return normalized ? [self imagesFromData:normalized error:error] : nil;
}

+ (void)loadWithCompletion:(void (^)(NSArray<NSDictionary *> *, NSError *))completion
{
    dispatch_group_t group = dispatch_group_create();
    NSMutableDictionary *responses = [NSMutableDictionary dictionary];
    NSMutableArray *errors = [NSMutableArray array];
    NSArray *sources = @[VZCatalogURL, VZAppleCatalogURL];
    for (NSUInteger index = 0; index < sources.count; ++index) {
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
            [NSURL URLWithString:sources[index]]
            cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData timeoutInterval:30];
        [request setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
        dispatch_group_enter(group);
        [[[NSURLSession sharedSession] dataTaskWithRequest:request
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSError *parseError = nil;
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
                ? [(NSHTTPURLResponse *)response statusCode] : 0;
            NSArray *images = nil;
            if (!error && status == 200 && data.length <= 16 * 1024 * 1024)
                images = index == 1 ? [self imagesFromAppleCatalogData:data error:&parseError]
                                    : [self imagesFromData:data error:&parseError];
            @synchronized (responses) {
                if (images.count) responses[@(index)] = images;
                else [errors addObject:error ?: parseError ?: [NSError
                    errorWithDomain:@"VZRestoreCatalog" code:status
                    userInfo:@{NSLocalizedDescriptionKey:@"The online restore catalog is unavailable."}]];
            }
            dispatch_group_leave(group);
        }] resume];
    }
    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        NSMutableArray *online = [NSMutableArray array];
        [online addObjectsFromArray:responses[@0] ?: @[]];
        [online addObjectsFromArray:responses[@1] ?: @[]];
        NSArray *result = [self imagesByMergingImages:online withBundledImages:self.bundledImages];
        completion(result, online.count ? nil : errors.firstObject);
        dispatch_release(group);
    });
}

+ (NSArray<NSDictionary *> *)bundledImages
{
    NSString *path = [NSBundle.mainBundle pathForResource:@"ipsws_v2" ofType:@"json"];
    NSArray *images = path ? [self imagesFromData:[NSData dataWithContentsOfFile:path] error:NULL] : nil;
    return [self imagesByMergingImages:@[] withBundledImages:images ?: @[]];
}

+ (NSArray<NSDictionary *> *)imagesByMergingImages:(NSArray<NSDictionary *> *)images
                                withBundledImages:(NSArray<NSDictionary *> *)bundled
{
    NSMutableArray *order = [NSMutableArray array];
    NSMutableDictionary *records = [NSMutableDictionary dictionary];
    // The signed recommendations remain available offline and retain their
    // verified download URLs even if the online catalog omits older builds.
    for (NSArray *source in @[bundled, images, VZVerifiedRestoreImages()]) {
        for (NSDictionary *image in source) {
            NSString *key = VZRestoreString(image[@"build"]);
            if (!key.length) key = VZRestoreString(image[@"url"]);
            if (!key.length) continue;
            if (!records[key]) [order addObject:key];
            records[key] = image;
        }
    }
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:order.count];
    for (NSString *key in order) [result addObject:records[key]];
    return result;
}

+ (NSArray<NSDictionary *> *)recommendedImagesFromImages:(NSArray<NSDictionary *> *)images
{
    NSMutableArray *result = [NSMutableArray array];
    for (NSDictionary *verified in VZVerifiedRestoreImages()) {
        for (NSDictionary *image in images) {
            if ([VZRestoreString(image[@"build"]) isEqualToString:verified[@"build"]]) {
                [result addObject:image];
                break;
            }
        }
    }
    return result;
}

+ (BOOL)isVerifiedAppleAccountImage:(NSDictionary *)image
{
    NSString *build = VZRestoreString(image[@"build"]);
    for (NSDictionary *verified in VZVerifiedRestoreImages())
        if ([build isEqualToString:verified[@"build"]]) return YES;
    return NO;
}

+ (NSDictionary *)recommendedImageFromImages:(NSArray<NSDictionary *> *)images
{
    NSDictionary *verified = [self recommendedImagesFromImages:images].firstObject;
    if (verified) return verified;
    NSArray *matches = [images filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:
        ^BOOL(NSDictionary *image, NSDictionary *bindings) {
            (void)bindings;
            return [VZRestoreString(image[@"group"]) isEqualToString:@"sequoia"] &&
                [VZRestoreString(image[@"channel"]) isEqualToString:@"regular"];
        }]];
    if (!matches.count)
        matches = [images filteredArrayUsingPredicate:[NSPredicate
            predicateWithBlock:^BOOL(NSDictionary *image,
                                      NSDictionary *bindings) {
            (void)bindings;
            return [VZRestoreString(image[@"channel"])
                isEqualToString:@"regular"];
        }]];
    return [matches sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
        return [VZRestoreString(right[@"version"])
            compare:VZRestoreString(left[@"version"]) options:NSNumericSearch];
    }].firstObject;
}

+ (NSArray<NSString *> *)orderedGroupsForImages:(NSArray<NSDictionary *> *)images
{
    NSMutableArray *preferred = [NSMutableArray array];
    for (NSDictionary *identity in
            [VZMacOSReleaseIdentities() reverseObjectEnumerator])
        [preferred addObject:identity[@"group"]];
    NSMutableArray *result = [NSMutableArray array];
    NSMutableSet *present = [NSMutableSet set];
    for (NSDictionary *image in images) {
        NSString *group = VZRestoreString(image[@"group"]);
        if (group.length)
            [present addObject:group];
    }
    for (NSString *group in preferred) if ([present containsObject:group]) [result addObject:group];
    for (NSString *group in present)
        if (![result containsObject:group]) [result addObject:group];
    // A new Apple release belongs above older known marketing-name groups.
    NSMutableDictionary *majors = [NSMutableDictionary dictionary];
    for (NSDictionary *image in images) {
        NSString *group = VZRestoreString(image[@"group"]);
        NSInteger major = [self majorVersionForImage:image];
        if (major > [majors[group] integerValue]) majors[group] = @(major);
    }
    return [result sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        NSInteger left = [majors[a] integerValue], right = [majors[b] integerValue];
        if (left != right) return left > right ? NSOrderedAscending : NSOrderedDescending;
        return [a localizedCaseInsensitiveCompare:b];
    }];
}

+ (BOOL)isExperimentalImage:(NSDictionary *)image
{
    return [self majorVersionForImage:image] >= 27;
}

+ (BOOL)isUnsupportedImage:(NSDictionary *)image
{
    (void)image;
    // Catalog visibility is independent of this App's last tested OS version.
    return NO;
}

+ (BOOL)enablesOpenGLByDefaultForImage:(NSDictionary *)image
{
    NSInteger major = [self majorVersionForImage:image];
    return major == 0 || (major >= 14 && major < 28);
}

+ (NSInteger)majorVersionForImage:(NSDictionary *)image
{
    NSDictionary *identity = VZMacOSIdentityForImage(image);
    if (identity)
        return [identity[@"major"] integerValue];
    NSString *version = VZRestoreString(image[@"version"]);
    if (!version.length)
        version = VZRestoreString(image[@"name"]);
    return VZRestoreMajorVersionFromText(version);
}

+ (NSString *)versionForImage:(NSDictionary *)image
{
    NSString *version = VZRestoreString(image[@"version"]);
    return version.length ? version
        : VZRestoreVersionFromText(VZRestoreString(image[@"name"]));
}

+ (NSString *)marketingNameForImage:(NSDictionary *)image
{
    return VZMacOSIdentityForImage(image)[@"marketing"];
}

+ (NSString *)displayNameForImage:(NSDictionary *)image compact:(BOOL)compact
{
    NSString *marketing = [self marketingNameForImage:image];
    NSInteger major = [self majorVersionForImage:image];
    if (compact) {
        if (marketing.length && major >= 27)
            return [NSString stringWithFormat:@"macOS %ld %@",
                (long)major, marketing];
        if (marketing.length && major > 0)
            return [NSString stringWithFormat:@"macOS %@ %ld",
                marketing, (long)major];
        if (major > 0)
            return [NSString stringWithFormat:@"macOS %ld", (long)major];
    }
    NSString *version = [self versionForImage:image];
    if ([version hasSuffix:@".0"])
        version = [version substringToIndex:version.length - 2];
    if (marketing.length)
        return version.length
            ? [NSString stringWithFormat:@"macOS %@ %@", marketing, version]
            : [NSString stringWithFormat:@"macOS %@", marketing];
    NSString *name = VZRestoreString(image[@"name"]);
    if (name.length)
        return name;
    return version.length ? [NSString stringWithFormat:@"macOS %@", version]
                          : @"macOS";
}

+ (NSString *)macOSNameForImage:(NSDictionary *)image
{
    NSString *marketing = [self marketingNameForImage:image];
    NSInteger major = [self majorVersionForImage:image];
    if (marketing.length)
        return [@"macOS " stringByAppendingString:marketing];
    return major > 0 ? [NSString stringWithFormat:@"macOS %ld", (long)major]
                     : @"macOS";
}

+ (NSString *)artworkNameForImage:(NSDictionary *)image
{
    return VZMacOSIdentityForImage(image)[@"artwork"] ?: @"ipsw";
}

+ (NSString *)artworkNameForMachineName:(NSString *)name
{
    NSDictionary *identity = VZMacOSIdentityInText(name);
    if (!identity)
        identity = VZMacOSIdentityForMajor(
            VZRestoreMajorVersionFromText(name));
    return identity[@"artwork"] ?: @"tiger";
}

+ (NSString *)defaultVirtualMachineNameForRestoreImagePath:(NSString *)path
{
    NSString *base = path.lastPathComponent.stringByDeletingPathExtension;
    NSDictionary *identity = VZMacOSIdentityInText(base);
    if (identity)
        return identity[@"marketing"];
    NSInteger major = VZRestoreMajorVersionFromText(base);
    identity = VZMacOSIdentityForMajor(major);
    if (identity)
        return identity[@"marketing"];
    if (major > 0)
        return [NSString stringWithFormat:@"macOS %ld", (long)major];
    return base.length ? base : @"macOS";
}

@end
