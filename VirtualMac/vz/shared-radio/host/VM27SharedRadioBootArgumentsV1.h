#import <Foundation/Foundation.h>
// Select the built-in virtual Bluetooth transport in this guest's NVRAM.
// Does not alter SIP, authenticated-root, kext consent, or host security.
BOOL VM27SharedRadioBluetoothBootArgumentsV1(id auxiliaryStorage, NSString *nativeImage, NSError **error);
BOOL VM27SharedRadioAutomatic26BootArgumentsV1(id auxiliaryStorage, NSString *nativeImage, NSError **error);
// Reuse the project's existing root-owned installation service when this
// independent App did not bundle its optional launcher resource.
NSString *VM27SharedRadioInstallationLauncherV1(void);
