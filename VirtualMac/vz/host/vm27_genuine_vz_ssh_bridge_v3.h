#ifndef VM27_GENUINE_VZ_SSH_BRIDGE_V3_H
#define VM27_GENUINE_VZ_SSH_BRIDGE_V3_H
#import "vm27_genuine_vz_ssh_bridge_v1.h"
#include "vm27_host_vsock_ssh_owner_v3.h"
FOUNDATION_EXPORT BOOL VM27CreateGenuineVZSSHBridgeV3(id actualVM,NSString *expectedVZImagePath,
 uint32_t idleMilliseconds,uint16_t tcpPort,unsigned scope,unsigned families,
 VM27GenuineVZSSHBridgeV1 **outOwner,NSError **error);
#endif
