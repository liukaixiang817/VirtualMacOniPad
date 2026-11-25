#pragma once
#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString *const VMAppleAccountProfileFileV1;
FOUNDATION_EXPORT NSString *const VMAppleAccountProfileOptionV1;
// Whether an actual manifest build can receive a persistent identity. This does
// not claim that its kernel policy or Apple services have passed validation.
BOOL VMAppleAccountSupportsBuildV1(NSString *build);
NSString *VMAppleAccountRestoreBuildV1(NSURL *ipswURL, NSError **error);
NSDictionary *VMAppleAccountMakeProfileV1(NSString *build, NSError **error);
BOOL VMAppleAccountProfileValidV1(NSDictionary *profile);
BOOL VMAppleAccountSaveNewProfileV1(NSDictionary *profile, NSString *directory, NSError **error);
BOOL VMAppleAccountBindRestoredProfileV1(NSString *attemptDirectory, NSString *bundle, NSError **error);
BOOL VMAppleAccountPrepareBootV1(NSString *bundle, NSDictionary *options, BOOL native27, NSError **error);
