#define main InheritedOwnershipModelsV1
#include "test-vm27-owned-app-child-startup-v1.c"
#undef main
#include "vm27_owned_app_child_startup_v2.h"
#include "vm27_owned_app_parent_scoped_policy_v2.inc"
int main(void) {
 int result=InheritedOwnershipModelsV1();if(result)return result;
 xpc_object_t borrowed=xpc_dictionary_create(NULL,NULL,0);
 VM27OwnedAppParentConfigurationV1 c=ParentConfigV1(borrowed);VM27OwnedAppParentV1 *owner=NULL;
 Check(VM27OwnedAppParentStartWithScopedPolicyV2(&c,&owner)==EINVAL && !owner,"ARC-wrapper-refuses-supplied-policy");
 c.originalImmutableRequirement=NULL;RegistryResult=EACCES;
 Check(VM27OwnedAppParentStartWithScopedPolicyV2(&c,&owner)==EACCES && owner,"ARC-wrapper-actual-policy-parent-error-owner-kept");
 Check(VM27OwnedAppParentStartWithScopedPolicyV2(&c,&owner)==EINVAL && owner,"ARC-wrapper-never-overwrites-owned-context");
 Check(!VM27OwnedAppParentReleaseV1(&owner) && !owner,"ARC-wrapper-own-policy-release-does-not-free-parent-owner");
 xpc_release(borrowed);
 printf("{\"checks\":%u,\"passed\":true,\"registryAndNativeTrustMocked\":true,\"nativeVMOperations\":0,\"processesSpawned\":0,\"actualXPCHandshakeExecuted\":false,\"guestBoot\":false}\n",Checks);
 return 0;
}
