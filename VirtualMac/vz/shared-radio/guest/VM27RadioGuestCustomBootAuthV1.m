// Temporary 24G90 review adapter. Native configure-boot normally runs in
// Recovery and supplies an archived recovery credential. In the VM's main-OS
// override environment, use the same real local-owner authentication as bputil.
// This never manufactures authentication success or stores credentials.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <OpenDirectory/OpenDirectory.h>
#include <objc/runtime.h>
#include <pwd.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <limits.h>

// Each probe is built for exactly one candidate, never an arbitrary CLI path.
#ifndef VM27_CUSTOM_BOOT_OBJECT
#define VM27_CUSTOM_BOOT_OBJECT "KernelCollection-24G90-RadioReview.kc"
#endif
#ifndef VM27_CUSTOM_BOOT_GUEST_BUILD
#define VM27_CUSTOM_BOOT_GUEST_BUILD "24G90"
#endif
#ifndef VM27_CUSTOM_BOOT_BASE_DIRECTORY
#define VM27_CUSTOM_BOOT_BASE_DIRECTORY "/private/var/root/VirtualMacWiFiReview15-v033"
#endif

@interface LAContext (VM27CustomBootOwnerV1)
- (void)setOptionUserId:(NSNumber *)uid;
- (BOOL)setCredential:(NSData *)data type:(NSInteger)type error:(NSError **)error;
@end

static IMP original;
static uid_t ownerUID;
static NSString *ownerGUID;

static BOOL ownerCredential(id context, SEL selector, NSData *data, NSInteger type) {
    if (type != -7) return ((BOOL (*)(id, SEL, NSData *, NSInteger))original)(context, selector, data, type);
    @autoreleasepool {
        NSMutableData *password = nil;
        BOOL archived = data.length >= 8 && !memcmp(data.bytes, "bplist00", 8);
        if (archived) {
            NSSet *classes = [NSSet setWithObjects:NSDictionary.class, NSString.class, nil];
            id object = [NSKeyedUnarchiver unarchivedObjectOfClasses:classes fromData:data error:NULL];
            if (![object isKindOfClass:NSDictionary.class] || [object count] != 2 ||
                ![object[@"guid"] isKindOfClass:NSString.class] ||
                [object[@"guid"] caseInsensitiveCompare:ownerGUID] != NSOrderedSame ||
                ![object[@"password"] isKindOfClass:NSString.class]) return NO;
            password = [[object[@"password"] dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        } else password = [data mutableCopy];
        if (!password.length || password.length > 255) return NO;
        [context setOptionUserId:@(ownerUID)];
        NSError *error = nil;
        BOOL accepted = [context setCredential:password type:-7 error:&error];
        volatile unsigned char *bytes = password.mutableBytes;
        for (NSUInteger i = 0; i < password.length; i++) bytes[i] = 0;
        fprintf(stderr, "[RadioReviewCustomBootAuth] recoveryArchive=%u realLocalOwnerCredentialAccepted=%u error=%ld\n",
            archived ? 1U : 0U, accepted ? 1U : 0U, (long)error.code);
        return accepted;
    }
}

__attribute__((constructor)) static void installOwnerFormatAdapter(void) { @autoreleasepool {
    NSArray *arguments = NSProcessInfo.processInfo.arguments;
    NSString *base = @VM27_CUSTOM_BOOT_BASE_DIRECTORY;
    NSArray *expected = @[[base stringByAppendingPathComponent:@"kmutil-native-owner-v1"],
        @"configure-boot", @"--custom-boot-object", [base stringByAppendingPathComponent:@VM27_CUSTOM_BOOT_OBJECT],
        @"--volume", @"/"];
    NSDictionary *version = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    const char *user = getenv("SUDO_USER");
    struct passwd *owner = user ? getpwnam(user) : NULL;
    uid_t uid = owner ? owner->pw_uid : 0;
    char executable[PATH_MAX], resolved[PATH_MAX], wanted[PATH_MAX];
    uint32_t capacity = sizeof(executable);
    BOOL sameProgram = !_NSGetExecutablePath(executable, &capacity) && realpath(executable, resolved) &&
        realpath([expected[0] fileSystemRepresentation], wanted) && !strcmp(resolved, wanted);
    BOOL command = sameProgram && arguments.count == expected.count &&
        [[arguments subarrayWithRange:NSMakeRange(1, 5)] isEqual:[expected subarrayWithRange:NSMakeRange(1, 5)]];
    BOOL diagnose = sameProgram && arguments.count == 2 && [arguments[1] isEqual:@"help"];
    BOOL validOwner = user && uid >= 500 && !strcmp(user, "radioreview");
    BOOL validBuild = [version[@"ProductBuildVersion"] isEqual:@VM27_CUSTOM_BOOT_GUEST_BUILD];
    fprintf(stderr, "[RadioReviewCustomBootAuth] initialized command=%u diagnostic=%u root=%u owner=%u build=%u\n",
        command ? 1U : 0U, diagnose ? 1U : 0U, geteuid() == 0 ? 1U : 0U,
        validOwner ? 1U : 0U, validBuild ? 1U : 0U);
    if (geteuid() || (!command && !diagnose) || !validBuild || !validOwner) return;
    NSError *error = nil;
    ODNode *node = [ODNode nodeWithSession:ODSession.defaultSession name:@"/Local/Default" error:&error];
    ODRecord *record = [node recordWithRecordType:kODRecordTypeUsers name:@(user) attributes:@[kODAttributeTypeGUID] error:&error];
    NSArray *values = [record valuesForAttribute:kODAttributeTypeGUID error:&error];
    fprintf(stderr, "[RadioReviewCustomBootAuth] localOwnerRecordReady=%u error=%ld\n",
        values.count == 1 && [values[0] isKindOfClass:NSString.class] ? 1U : 0U, (long)error.code);
    if (values.count != 1 || ![values[0] isKindOfClass:NSString.class]) return;
    if (diagnose) return;
    ownerGUID = values[0]; ownerUID = uid;
    Method method = class_getInstanceMethod(LAContext.class, @selector(setCredential:type:));
    if (!method || strcmp(method_getTypeEncoding(method),"B32@0:8@16q24")) return;
    original = method_setImplementation(method, (IMP)ownerCredential);
    fprintf(stderr, "[RadioReviewCustomBootAuth] exact temporary guest command admitted; native password verification retained\n");
} }
