// Read-only ABI and single-extension approval state, without credentials.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <signal.h>
#include <unistd.h>

@protocol VM27RadioApprovalReadPolicyV1 <NSObject>
- (id)currentPolicy;
- (id)pendingApprovals;
- (BOOL)requiresSecurityDowngrade;
@end
@protocol VM27RadioApprovalReadItemV1 <NSObject>
- (NSArray *)bundleIDs;
- (BOOL)isAllowed;
- (BOOL)isRebootRequired;
@end

static NSArray *targetItems(id objects) {
    NSMutableArray *rows = [NSMutableArray array];
    if ([objects isKindOfClass:NSArray.class]) for (id<VM27RadioApprovalReadItemV1> item in objects) {
        if ([item respondsToSelector:@selector(bundleIDs)] &&
            [[item bundleIDs] isEqual:@[@"com.virtualmac.SharedRadioNativeV1"]])
            [rows addObject:@{@"allowed":@([item isAllowed]),
                              @"rebootRequired":@([item isRebootRequired])}];
    }
    return rows;
}
int main(int argc, const char **argv) { @autoreleasepool {
    (void)argv;
    if (argc != 1 || geteuid()) return EPERM;
    alarm(20);
    NSDictionary *version = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *build = version[@"ProductBuildVersion"];
    if (![@[@"24G90",@"25G83",@"26A5416b"] containsObject:build]) return EPERM;
    if (!dlopen("/System/Library/PrivateFrameworks/SystemPolicy.framework/SystemPolicy",RTLD_NOW|RTLD_LOCAL)) return ENOENT;
    Class policyClass = objc_getClass("SPKernelExtensionPolicy");
    if (!policyClass) return ENOTSUP;
    NSMutableArray *methods = [NSMutableArray array];
    for (NSArray *entry in @[@[LAContext.class,@"setOptionUserId:"],
                             @[LAContext.class,@"setCredential:type:error:"],
                             @[LAContext.class,@"externalizedContext"],
                             @[policyClass,@"updatePolicyItems:withExternalContext:error:"],
                             @[policyClass,@"pendingApprovals"],
                             @[policyClass,@"requiresSecurityDowngrade"]]) {
        Method method = class_getInstanceMethod(entry[0],NSSelectorFromString(entry[1]));
        if (!method) return ENOTSUP;
        [methods addObject:@{@"class":NSStringFromClass(entry[0]),@"selector":entry[1],
                             @"encoding":@(method_getTypeEncoding(method))}];
    }
    id<VM27RadioApprovalReadPolicyV1> policy = [[policyClass alloc]init];
    if (!policy) return ENOENT;
    NSDictionary *report = @{@"schema":@1,@"build":build,@"policyMutation":@NO,
        @"credentialsRequested":@NO,@"methods":methods,
        @"requiresSecurityDowngrade":@([policy requiresSecurityDowngrade]),
        @"currentTargetItems":targetItems([policy currentPolicy]),
        @"pendingTargetItems":targetItems([policy pendingApprovals])};
    NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:NULL];
    if (!json) return EIO;
    fwrite(json.bytes,1,json.length,stdout);putchar('\n');return 0;
} }
