#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Adds the Virtio socket endpoint consumed by macOS's built-in
// AppleQEMUGuestAgent. No network connection or guest credentials are used.
BOOL VZGuestToolsConfigureDevice(id configuration);
void VZGuestToolsAttachToVirtualMachine(id virtualMachine);
void VZGuestToolsStartProvisioning(NSString *bundlePath,
                                   BOOL guestToolsEnabled,
                                   BOOL openGLAccelerationEnabled,
                                   BOOL pencilSupportEnabled,
                                   BOOL removalPending);
void VZGuestToolsReset(void);

// Narrow development action for the isolated modern-backend test app.
// Uses the existing guest agent; no arbitrary guest command or password input.
void VZGuestToolsEnableRemoteLogin(void (^completion)(BOOL success, NSData *output));

// Updates the virtual Mac's NVRAM before its platform configuration is used.
BOOL VZGuestToolsConfigureBootArguments(id auxiliaryStorage,
                                        BOOL guestAgentEnabled,
                                        BOOL openGLAccelerationEnabled,
                                        NSError **error);

NS_ASSUME_NONNULL_END
