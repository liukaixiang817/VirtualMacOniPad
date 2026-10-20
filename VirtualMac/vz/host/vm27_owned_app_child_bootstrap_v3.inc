/* Private publication and exact queue boundary for the product pre-Main.
 * The prior versions stay frozen; no native permission or hash gate changes. */
static const char ChildControlQueueKeyV3;
static void ChildFailedSetupV3(VM27OwnedAppChildV1 *o,int status) {
 if(LockV1(&o->mutex))abort();o->startupStatus=status;o->closing=true;if(UnlockV1(&o->mutex))abort();
}
static void ChildPublishPreparedV3(VM27OwnedAppChildV1 *o,VM27OwnedStartupChildV3 *prepared,int status) {
 if(LockV1(&o->mutex))abort();
 /* A second publication is a private implementation invariant violation. */
 if(o->prepared)abort();o->prepared=prepared;
 if(status){o->startupStatus=status;o->closing=true;}
 if(UnlockV1(&o->mutex))abort();
}
static VM27OwnedStartupChildV3 *ChildControlPreparedSnapshotV3(VM27OwnedAppChildV1 *o) {
 if(LockV1(&o->mutex))abort();
 VM27OwnedStartupChildV3 *prepared=!o->closing &&
  dispatch_get_specific(&ChildControlQueueKeyV3)==o?o->prepared:NULL;
 if(UnlockV1(&o->mutex))abort();return prepared;
}
static int ChildPrepareAndPublishV3(VM27OwnedAppChildV1 *o,const VM27OwnedStartupConfigurationV3 *configuration,
 VM27OwnedStartupChildV3 **actualPrepared,xpc_object_t *hello) {
 VM27OwnedStartupChildV3 *prepared=NULL;
 int status=VM27OwnedStartupChildPrepareV3(configuration,&prepared,hello);
 ChildPublishPreparedV3(o,prepared,status);*actualPrepared=prepared;return status;
}
int VM27OwnedAppChildBootstrapBeforeMainV3(VM27OwnedAppChildV1 **out) {
 if(!out || *out || getppid()<=1)return EINVAL;
 VM27OwnedAppChildV1 *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 int status=pthread_mutex_init(&o->mutex,NULL);if(status){free(o);return status;}
 o->ownerPID=getpid();o->startupStatus=EINPROGRESS;*out=o;
 o->queue=dispatch_queue_create("VM27.owned.app.child.bootstrap.v3",DISPATCH_QUEUE_SERIAL);
 o->ready=dispatch_semaphore_create(0);o->invalid=dispatch_semaphore_create(0);
 if(!o->queue || !o->ready || !o->invalid)return ENOMEM;
 dispatch_queue_set_specific(o->queue,&ChildQueueKeyV1,o,NULL);
 mach_port_array_t ports=NULL;mach_msg_type_number_t count=0;status=mach_ports_lookup(mach_task_self(),&ports,&count)==KERN_SUCCESS?0:EIO;
 if(!status)status=count==3 && MACH_PORT_VALID(ports[2])?VM27PrivateEndpointConnectSendRight(ports[2],o->queue,&o->control):ENOTCONN;
 int portStatus=ports?ReleasePortsV1(ports,count):0;if(!status)status=portStatus;
 if(!o->control){o->startupStatus=status?status:ENOTCONN;return o->startupStatus;}
 xpc_connection_set_event_handler(o->control,^(xpc_object_t event) {
  if(event==XPC_ERROR_CONNECTION_INVALID) {
   if(LockV1(&o->mutex))abort();if(!o->finalInvalid){o->finalInvalid=true;dispatch_semaphore_signal(o->invalid);}if(UnlockV1(&o->mutex))abort();
   ChildReadyV1(o,ECONNRESET);return;
  }
  if(xpc_get_type(event)!=XPC_TYPE_DICTIONARY)return;
  VM27OwnedStartupChildV3 *prepared=ChildControlPreparedSnapshotV3(o);
  xpc_object_t reply=NULL;int result=prepared?VM27OwnedStartupChildReceiveControlV3(prepared,event,&reply):ENOTCONN;
  if(reply){xpc_connection_t remote=xpc_dictionary_get_remote_connection(event);if(remote)xpc_connection_send_message(remote,reply);xpc_release(reply);}
  if(LockV1(&o->mutex))abort();o->controlStatus=result;if(UnlockV1(&o->mutex))abort();
 });
 xpc_connection_activate(o->control);if(status){ChildFailedSetupV3(o,status);return status;}
 xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);if(!request){ChildFailedSetupV3(o,ENOMEM);return ENOMEM;}
 xpc_dictionary_set_string(request,"privateMethod",ConfigurationMethodV1);
 if(LockV1(&o->mutex))abort();++o->pendingReplies;if(UnlockV1(&o->mutex))abort();
 xpc_connection_send_message_with_reply(o->control,request,o->queue,^(xpc_object_t reply) {
  VM27OwnedAppParentIdentityV1 native={0};int result=VM27OwnedAppCheckActualParentMessageV1(reply,&native);
  if(!result) {
   result=ConfigurationShapeV2(reply,&native);
   if(!result){if(LockV1(&o->mutex))abort();o->configurationMessage=xpc_retain(reply);o->nonce=xpc_dictionary_get_uint64(reply,"nonce");o->parentIdentity=native;if(UnlockV1(&o->mutex))abort();}
  }
  if(LockV1(&o->mutex))abort();--o->pendingReplies;if(UnlockV1(&o->mutex))abort();ChildReadyV1(o,result);
 });
 xpc_release(request);
 if(dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))){ChildReadyV1(o,ETIMEDOUT);return ETIMEDOUT;}
 dispatch_sync(o->queue,^{});
 if(LockV1(&o->mutex))return EBUSY;status=o->startupStatus;bool invalid=o->finalInvalid;if(UnlockV1(&o->mutex))return EBUSY;
 if(status || invalid)return status?status:ECONNRESET;
 if(getppid()!=(pid_t)o->parentIdentity.auditPID)return EACCES;
 xpc_object_t configuration=o->configurationMessage;
 VM27OwnedStartupConfigurationV3 c={0};c.parent.formatVersion=1;c.parent.kind=VM27OriginalV10ParentFlatBundle;c.parent.expectedParentPID=getppid();c.bootstrapNonce=o->nonce;
 c.parent.source.flatBundle=(VM27BundleParentConfigurationV1){
  ConfigurationStringV2(configuration,"bundlePath",4096),ConfigurationStringV2(configuration,"executableName",256),
  ConfigurationStringV2(configuration,"executableSHA256",65),ConfigurationStringV2(configuration,"executableCDHash",41),
  (uid_t)xpc_dictionary_get_uint64(configuration,"ownerUID")};
 VM27OwnedStartupChildV3 *actualPrepared=NULL;
 xpc_object_t hello=NULL;
 /* Prepare can return an acquired owner even on failure. Publish every real
  * owner under the same mutex used by the activated control handler. No lock
  * is held across Prepare or its external callbacks. */
 status=ChildPrepareAndPublishV3(o,&c,&actualPrepared,&hello);
 dispatch_queue_t actualControlQueue=NULL;
 if(!status)status=VM27OwnedStartupChildCopyControlQueueV3(actualPrepared,&actualControlQueue);
 if(status){if(hello)xpc_release(hello);ChildFailedSetupV3(o,status);return status;}
 /* Late bootstrap events can still exist after the earlier drain. Only the
  * exact genuine V3 control queue may consume the published owner; the old
  * bootstrap queue rejects control even during the retarget transition. */
 dispatch_queue_set_specific(actualControlQueue,&ChildQueueKeyV1,o,NULL);
 dispatch_queue_set_specific(actualControlQueue,&ChildControlQueueKeyV3,o,NULL);
 xpc_connection_set_target_queue(o->control,actualControlQueue);
 dispatch_queue_t bootstrap=o->queue;o->queue=actualControlQueue;dispatch_release(bootstrap);
 if(LockV1(&o->mutex))return EBUSY;
 if(o->finalInvalid){UnlockV1(&o->mutex);xpc_release(hello);return ECONNRESET;}
 o->readySignaled=false;o->startupStatus=EINPROGRESS;++o->pendingReplies;if(UnlockV1(&o->mutex))return EBUSY;
 xpc_connection_send_message_with_reply(o->control,hello,o->queue,^(xpc_object_t reply) {
  VM27OwnedAppParentIdentityV1 native={0};int result=VM27OwnedAppCheckActualParentMessageV1(reply,&native);
  if(!result) {
   const char *method=ConfigurationStringV2(reply,"privateMethod",128);xpc_object_t nonce=xpc_dictionary_get_value(reply,"nonce"),value=xpc_dictionary_get_value(reply,"status");
   if(native.auditPID!=o->parentIdentity.auditPID || native.auditPIDVersion!=o->parentIdentity.auditPIDVersion ||
    xpc_dictionary_get_count(reply)!=3 || !method || strcmp(method,AckMethodV1) || !nonce || xpc_get_type(nonce)!=XPC_TYPE_UINT64 ||
    xpc_uint64_get_value(nonce)!=o->nonce || !value || xpc_get_type(value)!=XPC_TYPE_INT64 || strcmp(native.kernelCDHash,c.parent.source.flatBundle.reviewedExecutableCDHash))result=EPROTO;
   else {int64_t actual=xpc_int64_get_value(value);result=actual>=0 && actual<=INT32_MAX?(int)actual:EPROTO;}
  }
  if(LockV1(&o->mutex))abort();--o->pendingReplies;if(UnlockV1(&o->mutex))abort();ChildReadyV1(o,result);
 });
 xpc_release(hello);
 if(dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))){ChildReadyV1(o,ETIMEDOUT);return ETIMEDOUT;}
 if(LockV1(&o->mutex))return EBUSY;status=o->startupStatus;int released=UnlockV1(&o->mutex);return status?status:released;
}
