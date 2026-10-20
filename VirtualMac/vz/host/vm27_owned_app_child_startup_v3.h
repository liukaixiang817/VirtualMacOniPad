#ifndef VM27_OWNED_APP_CHILD_STARTUP_V3_H
#define VM27_OWNED_APP_CHILD_STARTUP_V3_H
#include "vm27_owned_app_child_startup_v2.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Same true two-phase native identity and configuration gates as V2. Local
 * Prepare owner is published under the activated handler's mutex, including
 * acquired owners returned on failure. Only the actual V3 control queue can
 * dispatch control; late bootstrap events cannot borrow the prepared owner. */
int VM27OwnedAppChildBootstrapBeforeMainV3(VM27OwnedAppChildV1 **owner);
#ifdef __cplusplus
}
#endif
#endif
