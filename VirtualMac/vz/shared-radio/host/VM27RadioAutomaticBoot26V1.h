#import <Foundation/Foundation.h>

// Called only before a VM/platform exists, with the newly created guest's
// durable options. Returns nil for guests outside the supported radio profiles.
NSString *VM27RadioAutomaticBoot26V1(NSString *bundle, NSString *firmware, NSError **error);
BOOL VM27RadioUseAutomaticBootROMV1(id loader, NSString *rom, NSString *expectedNativeImage, NSError **error);
