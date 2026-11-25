#import "VZNewVMViewController.h"
#import "VZLocalization.h"
#import "VZRestoreCatalog.h"

static NSString *VZCatalogString(id value)
{
    return [value isKindOfClass:NSString.class] ? value : @"";
}

static UIImage *VZCatalogIcon(NSDictionary *image)
{
    NSString *name = [VZRestoreCatalog artworkNameForImage:image];
    static NSMutableDictionary *cache;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [[NSMutableDictionary alloc] init]; });
    UIImage *cached = cache[name];
    if (cached)
        return cached;
    NSString *path = [NSBundle.mainBundle pathForResource:name ofType:@"png"
                                               inDirectory:@"Installers"];
    UIImage *source = [UIImage imageWithContentsOfFile:path];
    if (!source)
        return nil;
    CGSize size = CGSizeMake(48, 48);
    UIGraphicsBeginImageContextWithOptions(size, NO, UIScreen.mainScreen.scale);
    [source drawInRect:(CGRect){CGPointZero, size}];
    UIImage *scaled = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    if (scaled)
        cache[name] = scaled;
    return scaled;
}

@interface VZNewVMViewController () <UISearchResultsUpdating>
@property(nonatomic, retain) NSArray<NSDictionary *> *catalog;
@property(nonatomic, retain) UIActivityIndicatorView *activity;
@property(nonatomic, assign) BOOL showMinorReleases;
@property(nonatomic, assign) BOOL showDeveloperBetas;
@property(nonatomic, assign) BOOL showVersionDetails;
@property(nonatomic, assign) BOOL versionDetailsBeforeDeveloperBetas;
@property(nonatomic, assign) CGFloat lastLayoutWidth;
@property(nonatomic, assign) BOOL browsingAllVersions;
@property(nonatomic, assign) BOOL catalogLoading;
@property(nonatomic, assign) BOOL catalogOffline;
@property(nonatomic, copy) NSString *versionQuery;
@property(nonatomic, retain) UISearchController *versionSearch;
@end

@implementation VZNewVMViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = VZL(self.browsingAllVersions ? @"Choose macOS Version" : @"New Virtual Mac");
    self.tableView.rowHeight = 54.0;
    self.tableView.estimatedRowHeight = 54.0;
    self.tableView.contentInset = UIEdgeInsetsMake(0, 0, 24, 0);
    self.tableView.verticalScrollIndicatorInsets = UIEdgeInsetsMake(0, 0, 24, 0);
    if (!self.browsingAllVersions)
        self.navigationItem.leftBarButtonItem = [[[UIBarButtonItem alloc]
            initWithBarButtonSystemItem:UIBarButtonSystemItemCancel target:self
            action:@selector(cancel:)] autorelease];
    // Show the bundled, verified choices immediately while the online list loads.
    if (!self.catalog.count) self.catalog = VZRestoreCatalog.bundledImages;
    self.activity = [[[UIActivityIndicatorView alloc]
        initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium]
        autorelease];
    self.refreshControl = [[[UIRefreshControl alloc] init] autorelease];
    [self.refreshControl addTarget:self action:@selector(reloadCatalog:)
        forControlEvents:UIControlEventValueChanged];
    if (self.browsingAllVersions) {
        self.versionSearch = [[[UISearchController alloc] initWithSearchResultsController:nil] autorelease];
        self.versionSearch.searchResultsUpdater = self;
        self.versionSearch.obscuresBackgroundDuringPresentation = NO;
        self.versionSearch.searchBar.placeholder = VZL(@"Search macOS version or build");
        self.navigationItem.searchController = self.versionSearch;
        self.navigationItem.hidesSearchBarWhenScrolling = NO;
        self.definesPresentationContext = YES;
    }
    [self reloadCatalog:nil];
}

- (void)updateCatalogButtons
{
    UIBarButtonItem *refresh = [[[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self
        action:@selector(reloadCatalog:)] autorelease];
    refresh.enabled = !self.catalogLoading;
    refresh.accessibilityLabel = VZL(@"Refresh macOS Versions");
    if (self.browsingAllVersions) {
        UIBarButtonItem *filters = [[[UIBarButtonItem alloc]
            initWithImage:[UIImage systemImageNamed:@"ellipsis.circle"]
            menu:[self filterMenu]] autorelease];
        self.navigationItem.rightBarButtonItems = @[filters, refresh];
    } else self.navigationItem.rightBarButtonItems = @[refresh];
}

- (void)reloadCatalog:(id)sender
{
    (void)sender;
    if (self.catalogLoading) return;
    self.catalogLoading = YES;
    [self.activity startAnimating];
    [self.refreshControl beginRefreshing];
    [self updateCatalogButtons];
    [VZRestoreCatalog loadWithCompletion:^(NSArray<NSDictionary *> *images,
                                            NSError *error) {
        self.catalog = images;
        self.catalogLoading = NO;
        self.catalogOffline = error != nil;
        [self.activity stopAnimating];
        [self.refreshControl endRefreshing];
        [self updateCatalogButtons];
        [self.tableView reloadData];
        if (error)
            NSLog(@"Virtual Mac restore catalog fallback failed: %@", error);
    }];
}

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    self.versionQuery = [searchController.searchBar.text
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    [self.tableView reloadData];
}

- (void)cancel:(id)sender
{
    (void)sender;
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)viewDidLayoutSubviews
{
    [super viewDidLayoutSubviews];
    CGFloat width = CGRectGetWidth(self.tableView.bounds);
    BOOL changed = self.lastLayoutWidth > 0 &&
        fabs(width - self.lastLayoutWidth) > 0.5;
    self.lastLayoutWidth = width;
    if (changed)
        [self.tableView reloadData];
}

- (UIMenu *)filterMenu
{
    UIAction *minor = [UIAction actionWithTitle:VZL(@"Show Minor Releases")
        image:nil identifier:nil handler:^(__kindof UIAction *action) {
        (void)action;
        self.showMinorReleases = !self.showMinorReleases;
        self.navigationItem.rightBarButtonItem.menu = [self filterMenu];
        [self.tableView reloadData];
    }];
    minor.state = self.showMinorReleases ? UIMenuElementStateOn
                                         : UIMenuElementStateOff;
    UIAction *betas = [UIAction actionWithTitle:VZL(@"Show Developer Betas")
        image:nil identifier:nil handler:^(__kindof UIAction *action) {
        (void)action;
        if (!self.showDeveloperBetas) {
            self.versionDetailsBeforeDeveloperBetas = self.showVersionDetails;
            self.showDeveloperBetas = YES;
            self.showVersionDetails = YES;
        } else {
            self.showDeveloperBetas = NO;
            self.showVersionDetails = self.versionDetailsBeforeDeveloperBetas;
        }
        self.navigationItem.rightBarButtonItem.menu = [self filterMenu];
        [self.tableView reloadData];
    }];
    betas.state = self.showDeveloperBetas ? UIMenuElementStateOn
                                          : UIMenuElementStateOff;
    UIAction *details = [UIAction actionWithTitle:VZL(@"Show Version Details")
        image:nil identifier:nil handler:^(__kindof UIAction *action) {
        (void)action;
        self.showVersionDetails = !self.showVersionDetails;
        self.navigationItem.rightBarButtonItem.menu = [self filterMenu];
        [self.tableView reloadData];
    }];
    details.state = self.showVersionDetails ? UIMenuElementStateOn
                                            : UIMenuElementStateOff;
    details.attributes = self.showDeveloperBetas
        ? UIMenuElementAttributesDisabled : 0;
    return [UIMenu menuWithTitle:VZL(@"Available macOS Versions")
                         children:@[minor, betas, details]];
}

- (NSArray<NSDictionary *> *)versionImages
{
    NSMutableArray *result = [NSMutableArray array];
    BOOL showsAdvancedVersions = self.showMinorReleases ||
        self.showDeveloperBetas || self.showVersionDetails;
    for (NSString *group in [VZRestoreCatalog orderedGroupsForImages:self.catalog]) {
        NSArray *matches = [self.catalog filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(NSDictionary *image,
                                                   NSDictionary *bindings) {
            (void)bindings;
            return [VZCatalogString(image[@"group"]) isEqualToString:group];
        }]];
        NSArray *sorted = [matches sortedArrayUsingComparator:
            ^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
            return [VZCatalogString(right[@"version"])
                compare:VZCatalogString(left[@"version"])
                options:NSNumericSearch];
        }];
        NSMutableArray *releases = [NSMutableArray array];
        NSMutableArray *betas = [NSMutableArray array];
        for (NSDictionary *image in sorted) {
            if (self.versionQuery.length) {
                NSString *searchable = [NSString stringWithFormat:@"%@ %@ %@",
                    VZCatalogString(image[@"version"]), VZCatalogString(image[@"build"]),
                    VZCatalogString(image[@"name"])];
                if ([searchable rangeOfString:self.versionQuery
                    options:NSCaseInsensitiveSearch | NSDiacriticInsensitiveSearch].location == NSNotFound)
                    continue;
            }
            if (!showsAdvancedVersions &&
                [VZRestoreCatalog isUnsupportedImage:image])
                continue;
            if ([VZCatalogString(image[@"channel"]) isEqualToString:@"devbeta"])
                [betas addObject:image];
            else
                [releases addObject:image];
        }
        if (self.showMinorReleases || self.versionQuery.length)
            [result addObjectsFromArray:releases];
        else if (releases.count)
            [result addObject:releases.firstObject];
        if (self.showDeveloperBetas || self.versionQuery.length)
            [result addObjectsFromArray:betas];
        else if (!releases.count && betas.count)
            [result addObject:betas.firstObject];
    }
    return result;
}

- (NSArray<NSDictionary *> *)recommendedImages
{
    NSArray *verified = [VZRestoreCatalog recommendedImagesFromImages:self.catalog];
    if (verified.count) return verified;
    NSDictionary *fallback = [VZRestoreCatalog recommendedImageFromImages:self.catalog];
    return fallback ? @[fallback] : @[];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    (void)tableView;
    return self.browsingAllVersions ? 2 : 3;
}

- (NSInteger)tableView:(UITableView *)tableView
 numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if (section == 0)
        return self.browsingAllVersions ? self.versionImages.count : self.recommendedImages.count;
    return 1;
}

- (NSString *)tableView:(UITableView *)tableView
 titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    if (section == 0)
        return VZL(self.browsingAllVersions ? @"Available macOS Releases" : @"Recommended macOS Release");
    if (!self.browsingAllVersions && section == 1)
        return VZL(@"Other macOS Versions");
    return VZL(@"Local Restore Image");
}

- (NSString *)tableView:(UITableView *)tableView
 titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if (section == 0) {
        NSString *detail = VZL(@"Recommended versions have passed Apple Account sign-in checks. You can also install other versions, with compatibility shown below.");
        if (self.catalogOffline) return [NSString stringWithFormat:@"%@\n%@", detail,
            VZL(@"The online catalog is unavailable. Showing offline versions; pull to refresh.")];
        return detail;
    }
    return section == (self.browsingAllVersions ? 1 : 2)
        ? VZL(@"Select an IPSW file downloaded from Apple.") : nil;
}

- (CGFloat)tableView:(UITableView *)tableView
 heightForRowAtIndexPath:(NSIndexPath *)indexPath
{
    (void)tableView;
    (void)indexPath;
    return 76.0;
}

- (void)setAccessoryForImage:(NSDictionary *)image
                         cell:(UITableViewCell *)cell
{
    cell.accessoryView = nil;
    if (![VZRestoreCatalog isExperimentalImage:image]) {
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return;
    }
    cell.accessoryType = UITableViewCellAccessoryNone;
    UIView *accessory = [[[UIView alloc] initWithFrame:CGRectMake(0, 0, 44, 24)]
        autorelease];
    UIImageView *warning = [[[UIImageView alloc] initWithFrame:
        CGRectMake(0, 2, 20, 20)] autorelease];
    warning.image = [UIImage systemImageNamed:@"exclamationmark.triangle.fill"];
    warning.contentMode = UIViewContentModeScaleAspectFit;
    warning.tintColor = UIColor.quaternaryLabelColor;
    warning.isAccessibilityElement = YES;
    warning.accessibilityLabel = VZL(@"Experimental");
    UIImageView *chevron = [[[UIImageView alloc] initWithFrame:
        CGRectMake(32, 5, 8, 14)] autorelease];
    chevron.image = [UIImage systemImageNamed:@"chevron.right"];
    chevron.tintColor = UIColor.tertiaryLabelColor;
    [accessory addSubview:warning];
    [accessory addSubview:chevron];
    cell.accessoryView = accessory;
}

- (NSDictionary *)imageAtIndexPath:(NSIndexPath *)indexPath
{
    if (indexPath.section == 0) {
        NSArray *images = self.browsingAllVersions ? self.versionImages : self.recommendedImages;
        if (indexPath.row < images.count) return images[indexPath.row];
    }
    return nil;
}

- (BOOL)title:(NSString *)title fitsCell:(UITableViewCell *)cell
{
    [cell setNeedsLayout];
    [cell layoutIfNeeded];
    CGFloat available = CGRectGetWidth(cell.textLabel.bounds);
    if (available <= 0)
        available = MAX(CGRectGetWidth(self.tableView.bounds) - 200.0, 80.0);
    CGFloat needed = [title sizeWithAttributes:
        @{NSFontAttributeName: cell.textLabel.font}].width;
    return needed <= available;
}

- (void)fitTitleForImage:(NSDictionary *)image
                    cell:(UITableViewCell *)cell
{
    NSString *displayName = [VZRestoreCatalog displayNameForImage:image
                                                           compact:NO];
    NSString *title = displayName;
    cell.textLabel.text = title;
    [self setAccessoryForImage:image cell:cell];
    if (![self title:title fitsCell:cell]) {
        NSString *version = [VZRestoreCatalog versionForImage:image];
        if (version.length) cell.textLabel.text = [@"macOS " stringByAppendingString:version];
    }
    // The warning is supplementary: preserve the complete actionable title
    // on narrow windows and retain the normal disclosure chevron.
    if ([VZRestoreCatalog isExperimentalImage:image] &&
        ![self title:title fitsCell:cell]) {
        cell.accessoryView = nil;
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"image"];
    if (!cell)
        cell = [[[UITableViewCell alloc]
            initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"image"]
            autorelease];
    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    cell.imageView.layer.cornerRadius = 9.0;
    cell.imageView.layer.cornerCurve = kCACornerCurveContinuous;
    cell.imageView.layer.masksToBounds = YES;
    cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
    cell.detailTextLabel.numberOfLines = 2;
    if (!self.browsingAllVersions && indexPath.section == 1) {
        cell.textLabel.text = VZL(@"Choose Another macOS Version");
        cell.detailTextLabel.text = VZL(@"Browse available releases and developer betas");
        cell.imageView.image = [UIImage systemImageNamed:@"list.bullet"];
        cell.imageView.tintColor = UIColor.systemBlueColor;
        return cell;
    }
    if (indexPath.section == (self.browsingAllVersions ? 1 : 2)) {
        cell.textLabel.text = VZL(@"Choose Custom IPSW");
        cell.detailTextLabel.text = VZDeviceString(VZL(@"Use an IPSW on your iPad"),
                                                   VZL(@"Use an IPSW on your iPhone"));
        cell.imageView.layer.cornerRadius = 9.0;
        cell.imageView.contentMode = UIViewContentModeScaleAspectFill;
        cell.imageView.tintColor = nil;
        cell.imageView.image = VZCatalogIcon(@{});
        return cell;
    }
    NSDictionary *image = [self imageAtIndexPath:indexPath];
    cell.imageView.image = VZCatalogIcon(image);
    NSMutableArray *details = [NSMutableArray array];
    if (!self.browsingAllVersions && indexPath.row == 0)
        [details addObject:VZL(@"Recommended")];
    [details addObject:VZL([VZRestoreCatalog isVerifiedAppleAccountImage:image]
        ? @"Apple Account sign-in verified" : @"Apple Account sign-in not verified")];
    if (self.showVersionDetails) {
        NSString *build = VZCatalogString(image[@"build"]);
        if (build.length)
            [details addObject:[NSString stringWithFormat:VZL(@"Build %@"), build]];
        NSString *channel = VZCatalogString(image[@"channel"]);
        if ([channel isEqualToString:@"devbeta"])
            [details addObject:VZL(@"Developer Beta")];
        else if ([channel isEqualToString:@"regular"])
            [details addObject:VZL(@"Release")];
        long long size = [image[@"downloadSize"] longLongValue];
        if (size > 0) {
            NSByteCountFormatter *formatter = [[[NSByteCountFormatter alloc]
                init] autorelease];
            formatter.countStyle = NSByteCountFormatterCountStyleFile;
            [details addObject:[formatter stringFromByteCount:size]];
        }
    }
    cell.detailTextLabel.text = [details componentsJoinedByString:@" · "];
    [self fitTitleForImage:image cell:cell];
    return cell;
}

- (void)tableView:(UITableView *)tableView
   willDisplayCell:(UITableViewCell *)cell
 forRowAtIndexPath:(NSIndexPath *)indexPath
{
    (void)tableView;
    NSDictionary *image = [self imageAtIndexPath:indexPath];
    if (image)
        [self fitTitleForImage:image cell:cell];
}

- (void)tableView:(UITableView *)tableView
 didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (!self.browsingAllVersions && indexPath.section == 1) {
        VZNewVMViewController *versions = [[[VZNewVMViewController alloc] init] autorelease];
        versions.browsingAllVersions = YES;
        versions.showMinorReleases = YES;
        versions.showVersionDetails = YES;
        versions.catalog = self.catalog;
        versions.delegate = self.delegate;
        [self.navigationController pushViewController:versions animated:YES];
        return;
    }
    if (indexPath.section == (self.browsingAllVersions ? 1 : 2)) {
        [self.delegate newVMControllerChooseLocalRestoreImage:self];
        return;
    }
    NSDictionary *image = [self imageAtIndexPath:indexPath];
    if (image)
        [self.delegate newVMController:self downloadRestoreImage:image];
}

- (void)dealloc
{
    [_catalog release];
    [_activity release];
    [_versionQuery release];
    [_versionSearch release];
    [super dealloc];
}

@end
