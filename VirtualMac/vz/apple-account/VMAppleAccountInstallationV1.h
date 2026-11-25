#pragma once
#import <Foundation/Foundation.h>

NSDictionary *VMAppleAccountPrepareInstallationV1(NSURL *image, NSString *attempt,
    NSDictionary *options, BOOL native27, NSError **error);
NSString *VMAppleAccountInstallationLauncherV1(void);
