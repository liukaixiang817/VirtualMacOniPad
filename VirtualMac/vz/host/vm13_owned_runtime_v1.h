#include <stddef.h>
#include <stdint.h>
extern const uint8_t VM13OwnedRuntimeManifestSHA256V1[32];
extern const size_t VM13OwnedRuntimeManifestBytesV1;
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
/* Whole original13 stack in its own root, never the old package's directory. */
BOOL VM13OwnedRuntimePreflightV1(NSString *root, NSError **error);
NS_ASSUME_NONNULL_END
#endif
