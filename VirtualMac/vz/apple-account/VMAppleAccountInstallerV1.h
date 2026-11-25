#pragma once
#import <Foundation/Foundation.h>

BOOL VMAppleAccountInstallerValidateV1(NSString *attempt, NSString *build, NSError **error);
BOOL VMAppleAccountInstallerBindV1(NSString *attempt, NSString *bundle, NSError **error);
