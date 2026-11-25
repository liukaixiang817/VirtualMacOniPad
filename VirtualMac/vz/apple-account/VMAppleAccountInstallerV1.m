#import "VMAppleAccountInstallerV1.h"
#import "VMAppleAccountProfileV1.h"
#include <sys/stat.h>

static BOOL Invalid(NSError **error) {
    if (error) *error = [NSError errorWithDomain:@"VMAppleAccountInstallerV1" code:1
        userInfo:@{NSLocalizedDescriptionKey:@"The installation's saved Apple Account identity or restore build does not match."}];
    return NO;
}
BOOL VMAppleAccountInstallerValidateV1(NSString *attempt, NSString *build, NSError **error) {
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
        [attempt stringByAppendingPathComponent:VMAppleAccountProfileFileV1]];
    NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:
        [attempt stringByAppendingPathComponent:@"VirtualMac.plist"]];
    if (!VMAppleAccountProfileValidV1(profile) || ![profile[@"GuestBuild"] isEqual:build] ||
        ![profile[@"UUID"] isEqual:options[VMAppleAccountProfileOptionV1]] ||
        ![profile[@"MACAddresses"][0] isEqual:options[@"MACAddress"]]) return Invalid(error);
    return YES;
}
BOOL VMAppleAccountInstallerBindV1(NSString *attempt, NSString *bundle, NSError **error) {
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:
        [attempt stringByAppendingPathComponent:VMAppleAccountProfileFileV1]];
    if (!VMAppleAccountInstallerValidateV1(attempt, profile[@"GuestBuild"], error) ||
        !VMAppleAccountBindRestoredProfileV1(attempt, bundle, error)) return NO;
    NSData *options = [NSData dataWithContentsOfFile:[attempt stringByAppendingPathComponent:@"VirtualMac.plist"]];
    NSString *destination = [bundle stringByAppendingPathComponent:@"VirtualMac.plist"];
    if (!options || ![options writeToFile:destination options:NSDataWritingAtomic error:error]) return NO;
    if (chmod(destination.fileSystemRepresentation, 0600)) return Invalid(error);
    return YES;
}
