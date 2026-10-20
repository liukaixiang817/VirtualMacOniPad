#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface VZSettingsViewController : UITableViewController
- (instancetype)initWithMachines:(NSArray<NSDictionary *> *)machines;
- (instancetype)initWithMachines:(NSArray<NSDictionary *> *)machines
             focusFrameworkBackend:(BOOL)focus;
@end

NS_ASSUME_NONNULL_END
