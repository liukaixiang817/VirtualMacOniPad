/* Included after V4's manifest/owner helpers, inside the same runtime state. */
#include "vm27_owned_parent_rearm_v1.h"
#include "vm27_independent_runtime_rearm_v1.h"

BOOL VM27IndependentAppRuntimeUnbindStoppedGuestV1(id vm,dispatch_queue_t queue,NSError **error) {
    if(!pthread_main_np() || queue!=dispatch_get_main_queue())
        return RefuseV1(error,@"Stopped guest unbinding requires its actual main queue.");
    if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Guest unbind lock failed.");
    BOOL result=NO;
    @try {
        if(!BoundVMV1)result=YES;
        else if(vm==BoundVMV1 && BoundQueueV1==queue &&
                dispatch_get_specific(&RuntimeQueueKeyV1)==(__bridge void *)vm &&
                [BoundVMV1 queue]==queue && [BoundVMV1 state]==0) {
            dispatch_queue_set_specific(queue,&RuntimeQueueKeyV1,NULL,NULL);
            BoundVMV1=nil;BoundQueueV1=NULL;result=YES;
        } else RefuseV1(error,@"The exact bound VM must have stopped before unbinding.");
    } @catch(NSException *exception) {
        (void)exception;RefuseV1(error,@"Stopped guest unbinding raised an exception; owner retained.");
    }
    if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Guest unbind unlock failed.");
    return result;
}

static BOOL VM27RetireExitedBootstrapV5(NSString *root,NSDictionary *manifest,NSError **error) {
    if(!BootstrapReadyV3)return YES;
    if(BootstrapPIDV3!=getpid() || !RetainedParentV3 || !ActualParentStateV3)
        return RefuseV1(error,@"The actual bootstrap process owner changed.");
    VM27OwnedAppParentStateV1 state={0};
    if(ActualParentStateV3(RetainedParentV3,&state) || state.ownerPID!=getpid())
        return RefuseV1(error,@"The actual bootstrap state cannot be inspected.");
    if(!state.controlFinalInvalid && !state.listenerFinalInvalid && !state.controlStatus)return YES;
    if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Runtime rearm lock failed.");
    BOOL eligible=!RuntimePoisonedV1 && LoadedPIDV1==getpid() && [LoadedRootV1 isEqual:root] &&
        LoadedManifestV1 && [LoadedManifestV1 isEqual:manifest] && !BoundVMV1 && !BoundQueueV1;
    if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Runtime rearm unlock failed.");
    if(!eligible)return RefuseV1(error,@"The old guest binding or partial runtime is still retained.");
    if(pthread_main_np())return RefuseV1(error,@"Runtime session rebuilding requires the background startup queue.");
    NSDictionary *contract=manifest[@"parentBootstrapContract"];
    NSDictionary *provider=FileV3(manifest,contract[@"providerID"]);
    NSDictionary *entry=BootstrapEntryV3(manifest,contract[@"providerID"],@"VM27OwnedAppParentRetireAfterExitV1");
    NSUInteger index=[manifest[@"loadOrder"]indexOfObject:contract[@"providerID"]];
    void *handle=index<RetainedHandlesV1.count?RetainedHandlesV1[index].pointerValue:NULL;
    NSString *path=[root stringByAppendingPathComponent:provider[@"path"]];
    if(!entry || !handle || !EntryV1(handle,path,entry[@"symbol"],entry[@"rva"],provider[@"uuid"],error))return NO;
    int (*retire)(VM27OwnedAppParentV1 **)=(int(*)(VM27OwnedAppParentV1 **))dlsym(handle,"VM27OwnedAppParentRetireAfterExitV1");
    if(!retire)return RefuseV1(error,@"The authenticated bootstrap retirement entry is absent.");
    int status=retire(&RetainedParentV3);
    for(unsigned attempt=0;RetainedParentV3 && attempt<10 && (status==EAGAIN || status==EBUSY);attempt++) {
        usleep(50000);
        status=retire(&RetainedParentV3);
    }
    fprintf(stderr,"[VM27RuntimeRearmV1] oldChild=%d status=%d released=%u\n",state.childPID,status,RetainedParentV3==NULL);
    if(status || RetainedParentV3)return RefuseV1(error,[NSString stringWithFormat:
        @"The previous runtime session has not finished closing (%d).",status]);
    BootstrapReadyV3=NO;BootstrapPIDV3=0;ActualParentStateV3=NULL;
    return YES;
}
