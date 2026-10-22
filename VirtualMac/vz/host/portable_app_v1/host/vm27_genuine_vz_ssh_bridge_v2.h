#ifndef VM27_GENUINE_VZ_SSH_BRIDGE_V2_H
#define VM27_GENUINE_VZ_SSH_BRIDGE_V2_H
/* Implementation V2 retains the frozen V1 public ABI. A future build replaces
 * the V1 translation unit with V2; linking both would duplicate the own class
 * and factory. This does not enable SSH or install a guest helper itself. */
#import "vm27_genuine_vz_ssh_bridge_v1.h"
#endif
