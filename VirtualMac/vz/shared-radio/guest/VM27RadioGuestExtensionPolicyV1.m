// Native SystemPolicy client, restricted to this development extension.
#import <Foundation/Foundation.h>
#import <Security/Authorization.h>
#import <Security/AuthorizationTags.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <ptrauth.h>
#include <sys/sysctl.h>
#include <pwd.h>
#include <stdlib.h>
@protocol VM27NativeKextItemV1 <NSObject>
@property(readonly) NSString *teamID;
@property(readonly) NSArray *bundleIDs;
@property(readonly) BOOL isAllowed;
@property(readonly) BOOL isModified;
@property(readonly) BOOL isRebootRequired;
- (void)setAllowed:(BOOL)allowed;
@end
@protocol VM27NativeKextPolicyV1 <NSObject>
- (NSXPCConnection *)connection;
- (id)currentPolicy;
- (id)pendingApprovals;
- (id)currentUAKL;
- (BOOL)requiresAuthenticationOnUpdates;
- (BOOL)requiresAdministratorToApproveUpdates;
- (BOOL)requiresSecurityDowngrade;
- (BOOL)updatePolicyItems:(NSArray *)items error:(NSError **)error;
- (BOOL)updatePolicyItems:(NSArray *)items withExternalContext:(NSData *)context error:(NSError **)error;
- (void)notifyLoadedKernelExtension:(NSString *)identifier withPath:(NSString *)path;
@end
static NSString *target = @"com.virtualmac.SharedRadioABIProbeV1";
static void eraseSecret(void *bytes, size_t length) {
    volatile unsigned char *cursor = bytes;
    while (length--) *cursor++ = 0;
}
static NSArray *items(id object) {
    if (![object isKindOfClass:NSArray.class]) return @[];
    NSMutableArray *rows = [NSMutableArray array];
    for (id<VM27NativeKextItemV1> item in (NSArray *)object) {
        if (![item respondsToSelector:@selector(bundleIDs)] || ![item.bundleIDs containsObject:target]) continue;
        [rows addObject:@{@"bundleIDs":item.bundleIDs, @"teamID":item.teamID ?: @"",
            @"allowed":@(item.isAllowed), @"modified":@(item.isModified), @"rebootRequired":@(item.isRebootRequired)}];
    }
    return rows;
}
int main(int argc, char **argv) { @autoreleasepool {
    const char *operation = argc > 1 ? argv[1] : "";
    if (!strcmp(operation, "--native-driver-status")) {
        target = @"com.virtualmac.SharedRadioNativeV1"; operation = "--status";
    } else if (!strcmp(operation, "--approve-native-driver-with-auth")) {
        target = @"com.virtualmac.SharedRadioNativeV1"; operation = "--approve-target-with-auth";
    }
    BOOL notify = argc == 3 && !strcmp(operation, "--report-loaded-target");
    if (!notify && (argc != 2 || (strcmp(operation, "--status") && strcmp(operation, "--approve-target") && strcmp(operation, "--approve-target-with-auth")))) return 64;
    if (notify) {
        char boot[64] = {0}; size_t count = sizeof(boot);
        if (geteuid() || strlen(argv[2]) != 36 || sysctlbyname("kern.bootsessionuuid", boot, &count, NULL, 0) ||
            strcmp(boot, argv[2])) return EPERM;
    }
    alarm(20);
    if (!dlopen("/System/Library/PrivateFrameworks/SystemPolicy.framework/SystemPolicy", RTLD_NOW | RTLD_LOCAL)) return 69;
    Class cls = objc_getClass("SPKernelExtensionPolicy");
    id<VM27NativeKextPolicyV1> policy = [[cls alloc] init];
    if (!policy) return 69;
    id current = [policy currentPolicy], pending = [policy pendingApprovals], uakl = [policy currentUAKL];
    NSMutableDictionary *report = [@{@"schema":@1, @"target":target,
        @"currentPolicyClass":current ? NSStringFromClass([current class]) : @"nil",
        @"pendingApprovalsClass":pending ? NSStringFromClass([pending class]) : @"nil",
        @"uaklClass":uakl ? NSStringFromClass([uakl class]) : @"nil",
        @"currentTargetItems":items(current), @"pendingTargetItems":items(pending),
        @"requiresAuthenticationOnUpdates":@([policy requiresAuthenticationOnUpdates]),
        @"requiresAdministratorToApproveUpdates":@([policy requiresAdministratorToApproveUpdates]),
        @"requiresSecurityDowngrade":@([policy requiresSecurityDowngrade]), @"policyMutationRequested":@NO} mutableCopy];
    if ([uakl isKindOfClass:NSURL.class]) {
        report[@"uaklURL"] = [(NSURL *)uakl absoluteString];
        NSData *contents = [NSData dataWithContentsOfURL:uakl options:NSDataReadingMappedIfSafe error:NULL];
        report[@"uaklReadable"] = @(contents != nil);
        report[@"uaklBytes"] = @(contents.length);
        if (contents && contents.length <= 16384) report[@"uaklPayloadBase64"] = [contents base64EncodedStringWithOptions:0];
    }
    // Read-only inspection of one native reporting method. Do not invoke an
    // undocumented object argument until its ABI and meaning are established.
    Method notification = class_getInstanceMethod(cls, sel_registerName("notifyLoadedKernelExtension:withPath:"));
    if (notification) {
        void *code = ptrauth_strip((void *)method_getImplementation(notification), ptrauth_key_function_pointer);
        uint8_t bytes[256]; mach_vm_size_t count = 0;
        kern_return_t result = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)code,
            sizeof(bytes), (mach_vm_address_t)bytes, &count);
        if (result == KERN_SUCCESS && count == sizeof(bytes)) {
            report[@"nativeLoadNotificationPC"] = [NSString stringWithFormat:@"%p", code];
            report[@"nativeLoadNotificationCodeBase64"] = [[NSData dataWithBytes:bytes length:sizeof(bytes)] base64EncodedStringWithOptions:0];
        }
    }
    NSXPCConnection *connection = [policy connection];
    NSXPCInterface *interface = connection.remoteObjectInterface;
    if (interface) {
        report[@"nativePolicyProtocol"] = @(protocol_getName(interface.protocol));
        NSMutableArray *arguments = [NSMutableArray array];
        SEL selector = sel_registerName("notifyLoadedKernelExtension:withPath:");
        struct objc_method_description description = protocol_getMethodDescription(interface.protocol, selector, YES, YES);
        if (description.types) report[@"nativeLoadNotificationProtocolTypes"] = @(description.types);
        for (NSUInteger i = 0; i < 2; ++i) {
            NSMutableArray *classes = [NSMutableArray array];
            @try {
                for (Class allowed in [interface classesForSelector:selector argumentIndex:i ofReply:NO])
                    [classes addObject:NSStringFromClass(allowed)];
            } @catch (NSException *exception) { [classes addObject:exception.name]; }
            [arguments addObject:classes];
        }
        report[@"nativeLoadNotificationAllowedArgumentClasses"] = arguments;
    }
    int status = 0;
    if (notify) {
        // Report only the exact already-approved, genuinely active probe. This
        // updates native load tracking; it cannot approve another extension.
        NSString *path = @"/Library/Extensions/VM27SharedRadioABIProbeV1.kext";
        SecStaticCodeRef code = NULL; CFDictionaryRef information = NULL;
        OSStatus signature = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags, &code);
        if (!signature) signature = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
        if (!signature) signature = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
        NSData *hash = information ? [(__bridge NSDictionary *)information objectForKey:(__bridge id)kSecCodeInfoUnique] : nil;
        NSMutableString *hex = [NSMutableString string];
        for (NSUInteger i = 0; i < hash.length; ++i) [hex appendFormat:@"%02x", ((const uint8_t *)hash.bytes)[i]];
        if (information) CFRelease(information);
        if (code) CFRelease(code);
        io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("VM27SharedRadioABIProbeV1"));
        CFTypeRef ready = service ? IORegistryEntryCreateCFProperty(service, CFSTR("NativeABIReady"), kCFAllocatorDefault, 0) : NULL;
        BOOL active = ready && CFEqual(ready, kCFBooleanTrue);
        if (ready) CFRelease(ready);
        if (service) IOObjectRelease(service);
        NSArray *approved = items(current);
        BOOL allowed = approved.count == 1 && [approved[0][@"allowed"] boolValue] &&
            [approved[0][@"bundleIDs"] isEqual:@[target]];
        NSSet *first = [interface classesForSelector:@selector(notifyLoadedKernelExtension:withPath:) argumentIndex:0 ofReply:NO];
        NSSet *second = [interface classesForSelector:@selector(notifyLoadedKernelExtension:withPath:) argumentIndex:1 ofReply:NO];
        if (signature || ![hex isEqual:@"fe3ddf44dbeca8854a7457a0f9560a78744b6b57"] || !active || !allowed ||
            ![first isEqual:[NSSet setWithObject:NSString.class]] || ![second isEqual:first]) return EPERM;
        report[@"policyMutationRequested"] = @YES;
        report[@"approvalPolicyMutationRequested"] = @NO;
        report[@"nativeActiveProbeVerified"] = @YES;
        [policy notifyLoadedKernelExtension:target withPath:path];
        report[@"nativeLoadNotificationSubmitted"] = @YES;
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        report[@"currentTargetItemsAfter"] = items([policy currentPolicy]);
        report[@"pendingTargetItemsAfter"] = items([policy pendingApprovals]);
    } else if (strcmp(operation, "--status")) {
        if (geteuid()) return EPERM;
        NSMutableArray *selected = [NSMutableArray array];
        if ([pending isKindOfClass:NSArray.class]) for (id<VM27NativeKextItemV1> item in pending) {
            if (item.bundleIDs.count == 1 && [item.bundleIDs[0] isEqual:target]) [selected addObject:item];
        }
        if (selected.count != 1) {
            report[@"error"] = @"Expected exactly one native pending item containing only the target"; status = ENOENT;
        } else {
            [selected[0] setAllowed:NO]; // local object only: send exactly one final allowed item
            [selected[0] setAllowed:YES];
            NSError *error = nil;
            BOOL result = NO;
            if (!strcmp(operation, "--approve-target-with-auth")) {
                // Native authorization capability, never a blanket approval-policy change.
                char password[256] = {0};
                if (!fgets(password, sizeof(password), stdin) || !strchr(password, '\n')) return EINVAL;
                password[strcspn(password, "\r\n")] = 0;
                char *user=getenv("SUDO_USER");
                struct passwd *owner=user?getpwnam(user):NULL;
                if(!owner||owner->pw_uid<500||strlen(user)>64){eraseSecret(password,sizeof(password));return EPERM;}
                AuthorizationItem credentialItems[] = {
                    {kAuthorizationEnvironmentUsername, strlen(user), user, 0},
                    {kAuthorizationEnvironmentPassword, strlen(password), password, 0}};
                AuthorizationEnvironment environment = {2, credentialItems};
                AuthorizationItem right = {"com.apple.system-extensions.admin", 0, NULL, 0};
                AuthorizationRights rights = {1, &right};
                AuthorizationRef authorization = NULL;
                OSStatus authStatus = AuthorizationCreate(&rights, &environment,
                    kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize, &authorization);
                eraseSecret(password, sizeof(password));
                report[@"nativeAuthorizationStatus"] = @(authStatus);
                if (authStatus == errAuthorizationSuccess && authorization) {
                    AuthorizationExternalForm external = {0};
                    authStatus = AuthorizationMakeExternalForm(authorization, &external);
                    if (!authStatus) {
                        NSData *context = [NSData dataWithBytes:&external length:sizeof(external)];
                        report[@"policyMutationRequested"] = @YES;
                        result = [policy updatePolicyItems:selected withExternalContext:context error:&error];
                    }
                    eraseSecret(&external, sizeof(external));
                }
                if (authorization) AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
            } else {
                report[@"policyMutationRequested"] = @YES;
                result = [policy updatePolicyItems:selected error:&error];
            }
            report[@"nativeUpdateSucceeded"] = @(result);
            if (error) report[@"nativeError"] = @{@"domain":error.domain, @"code":@(error.code), @"description":error.localizedDescription};
            if (!result) status = EACCES;
            report[@"currentTargetItemsAfter"] = items([policy currentPolicy]);
        }
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!data) return 70;
    fwrite(data.bytes, 1, data.length, stdout); fputc('\n', stdout);
    return status;
} }
