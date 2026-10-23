/* Preserve the accepted owned-bundle V6 bootstrap, native peer checks and typed owner ABI. */
#include "vm27_owned_app_child_startup_v6.c"
#include "vm27_original_client_retire_v1.h"

int VM27OwnedAppParentRetireAfterExitV1(VM27OwnedAppParentV1 **address) {
    if(!address || !*address)return EINVAL;
    VM27OwnedAppParentV1 *owner=*address;
    int status=ParentOwnedV1(owner);
    if(status)return status;
    if(owner->queue && dispatch_get_specific(&ParentQueueKeyV1)==owner)return EDEADLK;
    if(LockV1(&owner->mutex))return EBUSY;
    bool eligible=owner->state.spawned && owner->state.helloInstalled &&
        owner->state.childPID>1 && owner->state.startupStatus==0 && !owner->draining;
    uint64_t nonce=owner->nonce;
    if(UnlockV1(&owner->mutex))return EBUSY;
    if(!eligible || !nonce)return EBUSY;
    VM27LargePrivateConsumerV2State child={0};
    status=VM27LargePrivateServiceConsumerV2CopyState(owner->consumer,&child);
    if(status)return status;
    if(!child.reaped) {
        status=VM27LargePrivateServiceConsumerV2Wait(owner->consumer,false,&child);
        if(status)return status;
    }
    if(!child.started || !child.reaped || !child.absent || child.childPID!=owner->state.childPID)
        return EBUSY;
    // Only a genuinely exited child reaches cancellation of these own queues.
    status=VM27OwnedAppParentDrainV1(owner);
    if(status)return status;
    status=VM27OriginalClientRetireAfterExitV1(owner->consumer,nonce);
    if(status)return status;
    status=VM27LargePrivateServiceConsumerV2Release(owner->consumer);
    if(status)return status; // Retain remaining storage if an invariant failed.
    owner->consumer=NULL;
    if(owner->registry)VM27LargeBundleRegistryRelease(owner->registry);
    if(owner->peer)xpc_release(owner->peer);
    if(owner->endpoint)xpc_release(owner->endpoint);
    if(owner->listener)xpc_release(owner->listener);
    if(owner->queue)dispatch_release(owner->queue);
    if(owner->ready)dispatch_release(owner->ready);
    if(owner->peerInvalid)dispatch_release(owner->peerInvalid);
    if(owner->listenerInvalid)dispatch_release(owner->listenerInvalid);
    pthread_mutex_destroy(&owner->mutex);
    free(owner);*address=NULL;
    return 0;
}
