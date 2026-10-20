#include "vm27_owned_app_child_startup_v2.h"
/* One provider image owns both parent and child state; frozen v1 source is
 * inherited byte-for-byte. Do not load a second v1 provider alongside this. */
#include "vm27_owned_app_child_startup_v1.c"
#include "vm27_owned_app_parent_scoped_policy_v2.inc"
