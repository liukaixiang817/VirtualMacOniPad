int VM27OwnedAppParentStartWithScopedPolicyV2(const VM27OwnedAppParentConfigurationV1 *source,
 VM27OwnedAppParentV1 **owner) {
 if(!source || source->originalImmutableRequirement || !owner || *owner)return EINVAL;
 xpc_object_t requirement=NULL;int status=VM27OwnedAppCreateScopedPluginRequirementV1(&requirement);
 if(status)return status;
 VM27OwnedAppParentConfigurationV1 actual=*source;actual.originalImmutableRequirement=requirement;
 status=VM27OwnedAppParentStartV1(&actual,owner);xpc_release(requirement);return status;
}
