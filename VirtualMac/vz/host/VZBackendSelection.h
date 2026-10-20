#import <Foundation/Foundation.h>
#define VZBL(key) NSLocalizedStringFromTable((key), @"Backend", nil)

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT NSString * const VZFrameworkBackendKey;
NSString *VZBackendSelectedVersion(void);
NSString *VZBackendLoadedVersion(void);
NSString *VZBackendRuntimeRoot(void);
NSString * _Nullable VZBackendAvailabilityReason(NSString *version);
BOOL VZBackendSelectVersion(NSString *version, NSError **error);
BOOL VZBackendBeginRun(NSError **error);
BOOL VZBackendIsRunActive(void);
BOOL VZBackendBeginInstallation(NSError **error);
void VZBackendEndInstallation(void);
void VZBackendMarkLoadAttempt(void);
void VZBackendMarkLoaded(void);
void VZBackendEndRun(void);
NS_ASSUME_NONNULL_END
