#ifndef VM27_GENUINE_VZ_SSH_BRIDGE_V4_H
#define VM27_GENUINE_VZ_SSH_BRIDGE_V4_H
#import "vm27_genuine_vz_ssh_bridge_v3.h"
/* Creates the original VZ VM with its explicit original control queue. */
FOUNDATION_EXPORT id VM27SSHCreateActualVMWithQueueV4(id configuration,NSString *expectedVZImagePath,
 dispatch_queue_t queue,NSError **error) NS_RETURNS_RETAINED;
#endif
