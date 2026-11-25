#import "VMAppleAccountInstallationV1.h"
#import "VMAppleAccountProfileV1.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Generated and linked by the product builder from the exact signed helpers.
extern const char *const VMAppleAccountInstallerPathsV1[3];
extern const uint64_t VMAppleAccountInstallerBytesV1[3];
extern const uint8_t VMAppleAccountInstallerHashesV1[3][32];
static BOOL Failure(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"VMAppleAccountInstallationV1" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
NSString *VMAppleAccountInstallationLauncherV1(void) {
    for (unsigned i = 0; i < 3; ++i) {
        int fd = open(VMAppleAccountInstallerPathsV1[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return nil;
        struct stat st;
        BOOL valid = !fstat(fd, &st) && S_ISREG(st.st_mode) && !st.st_uid && st.st_nlink == 1 &&
            (st.st_mode & 07777) == (i == 0 ? 04755 : 0755) && st.st_size > 0 &&
            (uint64_t)st.st_size == VMAppleAccountInstallerBytesV1[i];
        CC_SHA256_CTX hash;
        CC_SHA256_Init(&hash);
        uint8_t buffer[65536], actual[32];
        ssize_t n = 0;
        while (valid && (n = read(fd, buffer, sizeof(buffer))) > 0) CC_SHA256_Update(&hash, buffer, (CC_LONG)n);
        valid = valid && !n;
        CC_SHA256_Final(actual, &hash);
        close(fd);
        if (!valid || memcmp(actual, VMAppleAccountInstallerHashesV1[i], 32)) return nil;
    }
    return @(VMAppleAccountInstallerPathsV1[0]);
}
NSDictionary *VMAppleAccountPrepareInstallationV1(NSURL *image, NSString *attempt,
    NSDictionary *options, BOOL native27, NSError **error) {
    NSString *build = VMAppleAccountRestoreBuildV1(image, error);
    if (!build) return nil;
    // Always prepare an independent identity. Runtime/backend validation is a
    // separate boot decision and must never silently omit this restore state.
    (void)native27;
    if (!VMAppleAccountInstallationLauncherV1()) {
        Failure(error, @"The Apple Account installation components are unavailable. Reinstall this version of Virtual Mac.");
        return nil;
    }
    NSDictionary *profile = VMAppleAccountMakeProfileV1(build, error);
    if (!profile || !VMAppleAccountSaveNewProfileV1(profile, attempt, error)) return nil;
    NSMutableDictionary *saved = [options mutableCopy];
    saved[VMAppleAccountProfileOptionV1] = profile[@"UUID"];
    saved[@"AppleAccountGuestBuildV1"] = build;
    saved[@"MACAddress"] = profile[@"MACAddresses"][0];
    saved[@"HibernateOnBackgroundEnabled"] = @NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:saved
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    NSString *path = [attempt stringByAppendingPathComponent:@"VirtualMac.plist"];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:error] ||
        chmod(path.fileSystemRepresentation, 0600)) return nil;
    return saved;
}
