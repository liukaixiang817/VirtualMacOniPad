#ifndef VM27_SSH_SETTINGS_V3_H
#define VM27_SSH_SETTINGS_V3_H
#import <Foundation/Foundation.h>
#include "vm27_host_vsock_ssh_owner_v3.h"
#define VM27_SSH_ENABLED @"SSHForwardingEnabled"
#define VM27_SSH_PORT @"SSHForwardingPort"
#define VM27_SSH_SCOPE @"SSHForwardingScope"
#define VM27_SSH_FAMILIES @"SSHForwardingIPFamilies"
typedef struct {BOOL enabled;uint16_t port;unsigned scope,families;} VM27SSHSettingsV3;
static inline BOOL VM27SSHSettingsReadV3(NSDictionary *options,VM27SSHSettingsV3 *out) {
 if(!out || ![options isKindOfClass:NSDictionary.class])return NO;
 id enabled=options[VM27_SSH_ENABLED],port=options[VM27_SSH_PORT],scope=options[VM27_SSH_SCOPE],families=options[VM27_SSH_FAMILIES];
 if(enabled && ![enabled isKindOfClass:NSNumber.class])return NO;
 if(port && (![port isKindOfClass:NSNumber.class] || [port doubleValue]!=[port integerValue] || [port integerValue]<1 || [port integerValue]>65535))return NO;
 if(scope && (![scope isKindOfClass:NSNumber.class] || [scope doubleValue]!=[scope integerValue] || [scope integerValue]<0 || [scope integerValue]>2))return NO;
 if(families && (![families isKindOfClass:NSNumber.class] || [families doubleValue]!=[families integerValue] || [families integerValue]<1 || [families integerValue]>3))return NO;
 *out=(VM27SSHSettingsV3){enabled?[enabled boolValue]:YES,port?[port unsignedIntValue]:22222,scope?[scope unsignedIntValue]:VM27SSHLocalV3,families?[families unsignedIntValue]:VM27SSHIPv4V3};return YES;
}
static inline NSDictionary *VM27SSHSettingsDictionaryV3(VM27SSHSettingsV3 value) {
 return @{VM27_SSH_ENABLED:@(value.enabled),VM27_SSH_PORT:@(value.port),VM27_SSH_SCOPE:@(value.scope),VM27_SSH_FAMILIES:@(value.families)};
}
FOUNDATION_EXPORT void VZVMApplySSHSettingsV3(NSString *bundlePath,NSDictionary *options,void (^completion)(NSError *error));
FOUNDATION_EXPORT NSString *VZVMSSHStatusV3(NSString *bundlePath);
FOUNDATION_EXPORT void VZGuestToolsEnsurePersistentSSHV3(void (^completion)(BOOL,NSData *));
#endif
