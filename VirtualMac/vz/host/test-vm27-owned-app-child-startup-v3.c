#define main InheritedOwnershipModelsV1
#include "test-vm27-owned-app-child-startup-v1.c"
#undef main
#include "vm27_owned_app_child_startup_v2.h"
#include "vm27_owned_app_parent_scoped_policy_v2.inc"
static int InheritedOwnershipModelsV2(void) {
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

#include "vm27_owned_app_child_startup_v3.h"
static VM27OwnedAppChildV1 *PublishingOwnerV3;
static dispatch_queue_t ActualModelControlQueueV3;
static unsigned ActualPrepareCallsV3;
static int ModelChildPrepareCheckedV3(const VM27OwnedStartupConfigurationV3 *,VM27OwnedStartupChildV3 **,xpc_object_t *);
#undef VM27OwnedStartupChildPrepareV3
#define VM27OwnedStartupChildPrepareV3 ModelChildPrepareCheckedV3
#include "vm27_owned_app_child_bootstrap_v3.inc"
static int ModelChildPrepareCheckedV3(const VM27OwnedStartupConfigurationV3 *c,VM27OwnedStartupChildV3 **owner,xpc_object_t *hello) {
 ++ActualPrepareCallsV3;
 Check(owner!=&PublishingOwnerV3->prepared,"actual-Prepare-output-is-local-not-shared-owner-field");
 int status=ModelChildPrepareV1(c,owner,hello);
 __block VM27OwnedStartupChildV3 *borrowed=NULL;
 dispatch_sync(ActualModelControlQueueV3,^{borrowed=ChildControlPreparedSnapshotV3(PublishingOwnerV3);});
 Check(!borrowed,"actual-control-queue-sees-no-owner-during-external-Prepare");
 return status;
}
static VM27OwnedAppChildV1 *ModelOwnerV3(void) {
 VM27OwnedAppChildV1 *o=calloc(1,sizeof(*o));if(!o)abort();
 if(pthread_mutex_init(&o->mutex,NULL))abort();o->ownerPID=getpid();o->startupStatus=EINPROGRESS;
 o->queue=dispatch_queue_create("VM27.model.bootstrap.queue.v3",DISPATCH_QUEUE_SERIAL);
 dispatch_queue_set_specific(o->queue,&ChildQueueKeyV1,o,NULL);return o;
}
int main(void) {
 int status=InheritedOwnershipModelsV2();if(status)return status;
 VM27OwnedAppChildV1 *child=ModelOwnerV3();PublishingOwnerV3=child;
 ActualModelControlQueueV3=dispatch_queue_create("VM27.model.actual.control.queue.v3",DISPATCH_QUEUE_SERIAL);
 dispatch_queue_set_specific(ActualModelControlQueueV3,&ChildControlQueueKeyV3,child,NULL);
 ChildPrepareResult=0;xpc_object_t hello=NULL;VM27OwnedStartupChildV3 *prepared=NULL;
 dispatch_group_t readers=dispatch_group_create();__block unsigned observed=0;__block bool invalidObserved=false;
 VM27OwnedAppChildV1 *borrowed=child;
 dispatch_group_async(readers,ActualModelControlQueueV3,^{
  for(unsigned i=0;i<4000;i++) {
   VM27OwnedStartupChildV3 *value=ChildControlPreparedSnapshotV3(borrowed);
   if(value)observed++;
  }
 });
 VM27OwnedStartupConfigurationV3 config=ChildConfigV1();
 Check(!ChildPrepareAndPublishV3(child,&config,&prepared,&hello) && prepared && hello,"actual-local-Prepare-then-mutex-publish-success");
 Check(!dispatch_group_wait(readers,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)),"bounded-actual-serial-reader-callbacks-drain");
 dispatch_sync(ActualModelControlQueueV3,^{
  for(unsigned i=0;i<4000;i++){VM27OwnedStartupChildV3 *value=ChildControlPreparedSnapshotV3(borrowed);if(value!=prepared)invalidObserved=true;}
 });
 Check(!invalidObserved,"post-publication-exact-owner-stable-for-4000-actual-queue-reads");
 __block VM27OwnedStartupChildV3 *snapshot=NULL;
 dispatch_sync(child->queue,^{snapshot=ChildControlPreparedSnapshotV3(borrowed);});
 Check(!snapshot,"late-real-bootstrap-queue-cannot-borrow-published-owner");
 dispatch_sync(ActualModelControlQueueV3,^{snapshot=ChildControlPreparedSnapshotV3(borrowed);});
 Check(snapshot==prepared,"only-bound-actual-control-queue-can-borrow-owner");
 dispatch_queue_t foreign=dispatch_queue_create("VM27.model.foreign.control.queue.v3",DISPATCH_QUEUE_SERIAL);
 dispatch_sync(foreign,^{snapshot=ChildControlPreparedSnapshotV3(borrowed);});
 Check(!snapshot,"foreign-serial-queue-refused-without-fake-control-identity");
 ChildFailedSetupV3(child,EBUSY);dispatch_sync(ActualModelControlQueueV3,^{snapshot=ChildControlPreparedSnapshotV3(borrowed);});
 Check(!snapshot && child->prepared==prepared && child->closing && child->startupStatus==EBUSY,"late-copyqueue-failure-retains-owner-and-closes-admission");
 xpc_release(hello);hello=NULL;ChildStopResult=0;
 Check(!VM27OwnedAppChildReleaseV1(&child) && !child,"actual-readers-drained-before-owned-release");
 dispatch_release(readers);dispatch_release(foreign);dispatch_release(ActualModelControlQueueV3);
 child=ModelOwnerV3();PublishingOwnerV3=child;borrowed=child;
 ActualModelControlQueueV3=dispatch_queue_create("VM27.model.failed.control.queue.v3",DISPATCH_QUEUE_SERIAL);
 dispatch_queue_set_specific(ActualModelControlQueueV3,&ChildControlQueueKeyV3,child,NULL);
 ChildPrepareResult=EACCES;prepared=NULL;
 Check(ChildPrepareAndPublishV3(child,&config,&prepared,&hello)==EACCES && prepared && child->prepared==prepared,"actual-failed-Prepare-acquired-owner-still-published");
 Check(child->closing && child->startupStatus==EACCES && !hello,"failed-Prepare-does-not-grant-control-or-success");
 dispatch_sync(ActualModelControlQueueV3,^{snapshot=ChildControlPreparedSnapshotV3(borrowed);});
 Check(!snapshot,"late-actual-control-event-after-failed-Prepare-is-refused");
 ChildStopResult=EBUSY;
 Check(VM27OwnedAppChildReleaseV1(&child)==EBUSY && child && child->prepared==prepared,"failed-true-service-stop-keeps-published-acquired-owner");
 ChildStopResult=0;
 Check(!VM27OwnedAppChildReleaseV1(&child) && !child,"successful-stop-drain-then-release-failed-Prepare-owner");
 dispatch_release(ActualModelControlQueueV3);PublishingOwnerV3=NULL;
 Check(ActualPrepareCallsV3==2,"exact-one-Prepare-per-finite-success-and-failure-no-retry");
 printf("{\"checks\":%u,\"passed\":true,\"actualPrepareCalls\":%u,\"serialQueueReads\":8000,\"prepublicationOwnerInvisible\":true,\"lateBootstrapQueueRejected\":true,\"failedPrepareOwnerRetained\":true,\"registryAndNativeTrustMocked\":true,\"nativeVMOperations\":0,\"processesSpawned\":0,\"actualXPCHandshakeExecuted\":false,\"guestBoot\":false}\n",Checks,ActualPrepareCallsV3);
 (void)observed;return 0;
}
