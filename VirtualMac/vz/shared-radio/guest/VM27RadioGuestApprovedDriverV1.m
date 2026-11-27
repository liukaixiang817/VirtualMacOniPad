// Development-only native approval client. The build pins one guest build and
// one installed driver signature; no other extension can be approved here.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/SecCode.h>
#include <dlfcn.h>
#include <objc/runtime.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#ifndef VM27_APPROVAL_GUEST_BUILD
#error A reviewed guest build must be specified
#endif
#ifndef VM27_APPROVAL_DRIVER_CDHASH
#error The approved driver signature must be specified
#endif

@interface LAContext (VM27NativeOwnerCredentialV1)
- (void)setOptionUserId:(NSNumber *)uid;
- (BOOL)setCredential:(NSData *)credential type:(NSInteger)type error:(NSError **)error;
- (NSData *)externalizedContext;
@end
@protocol VM27ApprovedKextItemV1 <NSObject>
@property(readonly) NSArray *bundleIDs;
- (void)setAllowed:(BOOL)allowed;
@end
@protocol VM27ApprovedKextPolicyV1 <NSObject>
- (id)pendingApprovals;
- (BOOL)requiresSecurityDowngrade;
- (BOOL)updatePolicyItems:(NSArray *)items withExternalContext:(NSData *)context error:(NSError **)error;
@end

static void erase(void *data, size_t size) {
    volatile unsigned char *bytes = data;
    while (size--) *bytes++ = 0;
}

int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 2 || strcmp(argv[1], "--approve") || geteuid()) return EPERM;
    alarm(25);
    NSDictionary *version = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if (![version[@"ProductBuildVersion"] isEqual:@VM27_APPROVAL_GUEST_BUILD]) return EPERM;
    NSString *target = @"com.virtualmac.SharedRadioNativeV1";
    NSString *path = @"/Library/Extensions/VM27SharedRadioNativeV1.kext";
    SecStaticCodeRef code = NULL;
    CFDictionaryRef signing = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], 0, &code);
    if (!status) status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing);
    NSDictionary *information = (__bridge NSDictionary *)signing;
    NSData *hash = information[(__bridge id)kSecCodeInfoUnique];
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < hash.length; i++) [hex appendFormat:@"%02x", ((const unsigned char *)hash.bytes)[i]];
    BOOL exact = !status && [information[(__bridge id)kSecCodeInfoIdentifier] isEqual:target] &&
        [hex isEqual:@VM27_APPROVAL_DRIVER_CDHASH];
    if (signing) CFRelease(signing);
    if (code) CFRelease(code);
    if (!exact) return EPERM;
    if (!dlopen("/System/Library/PrivateFrameworks/SystemPolicy.framework/SystemPolicy", RTLD_NOW | RTLD_LOCAL)) return ENOENT;
    Class cls = objc_getClass("SPKernelExtensionPolicy");
    if (!cls) return ENOTSUP;
    for (NSArray *entry in @[@[LAContext.class,@"setOptionUserId:",@"v24@0:8@16"],
                             @[LAContext.class,@"setCredential:type:error:",@"B40@0:8@16q24^@32"],
                             @[LAContext.class,@"externalizedContext",@"@16@0:8"],
                             @[cls,@"updatePolicyItems:withExternalContext:error:",@"B40@0:8@16@24^@32"]]) {
        Method method = class_getInstanceMethod(entry[0],NSSelectorFromString(entry[1]));
        if (!method || strcmp(method_getTypeEncoding(method),[entry[2] UTF8String])) return ENOTSUP;
    }
    id<VM27ApprovedKextPolicyV1> policy = [[cls alloc] init];
    if (!policy || [policy requiresSecurityDowngrade]) return EPERM;
    id pending = [policy pendingApprovals];
    NSMutableArray *selected = [NSMutableArray array];
    if ([pending isKindOfClass:NSArray.class]) for (id<VM27ApprovedKextItemV1> item in pending) {
        if ([item.bundleIDs isEqual:@[target]]) [selected addObject:item];
    }
    if (selected.count != 1) return ENOENT;
    const char *name = getenv("SUDO_USER");
    struct passwd *owner = name ? getpwnam(name) : NULL;
    if (!owner || owner->pw_uid < 500 || strlen(name) > 64) return EPERM;
    char password[256] = {0};
    if (!fgets(password, sizeof(password), stdin) || !strchr(password, '\n')) {
        erase(password, sizeof(password)); return EINVAL;
    }
    password[strcspn(password, "\r\n")] = 0;
    NSMutableData *credential = [NSMutableData dataWithBytes:password length:strlen(password)];
    erase(password, sizeof(password));
    LAContext *context = [LAContext new];
    context.interactionNotAllowed = YES;
    NSError *error = nil;
    // Audited native bputil contract on 24G90, 26A5416b and 26B131: invoking
    // administrator UID and its UTF-8 password as credential type -7.
    [context setOptionUserId:@(owner->pw_uid)];
    BOOL credentialSet = [context setCredential:credential type:-7 error:&error];
    erase(credential.mutableBytes, credential.length);
    NSData *external = credentialSet ? [context externalizedContext] : nil;
    BOOL updated = NO;
    if (external.length) {
        [selected[0] setAllowed:NO]; // Local object only; send one final allowed item.
        [selected[0] setAllowed:YES];
        updated = [policy updatePolicyItems:selected withExternalContext:external error:&error];
    }
    [context invalidate];
    NSMutableDictionary *report = [@{@"schema":@1, @"target":target,
        @"guestBuild":@VM27_APPROVAL_GUEST_BUILD, @"exactDriverSignatureVerified":@YES,
        @"nativeOwnerCredentialSet":@(credentialSet), @"nativeACMContextAvailable":@(external.length > 0),
        @"nativeUpdateSucceeded":@(updated), @"onlyTargetSelected":@YES,
        @"credentialsOrContextPersisted":@NO} mutableCopy];
    if (error) report[@"nativeError"] = @{@"domain":error.domain,@"code":@(error.code)};
    NSData *output = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:NULL];
    if (output) { fwrite(output.bytes, 1, output.length, stdout); fputc('\n', stdout); }
    return updated ? 0 : EACCES;
} }
