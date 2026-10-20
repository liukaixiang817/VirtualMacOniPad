#include "vm27_owned_app_child_startup_v3.h"
/* The unsafe historical V2 body remains frozen and hidden, never a product
 * entry. Parent APIs keep their exact V2 ABI in this one new provider image. */
__attribute__((visibility("hidden")))
int VM27OwnedAppChildBootstrapBeforeMainInheritedV2(VM27OwnedAppChildV1 **);
#define VM27OwnedAppChildBootstrapBeforeMainV2 VM27OwnedAppChildBootstrapBeforeMainInheritedV2
#include "vm27_owned_app_child_startup_v2.c"
#undef VM27OwnedAppChildBootstrapBeforeMainV2
#include "vm27_owned_app_child_bootstrap_v3.inc"
