#include "vm27_owned_app_child_startup_v1.h"
#include "modern_xpc_private_endpoint.h"
#include "vm27_owned_app_parent_identity_v1.h"
#include "modern_xpc_lwcr_policy.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct VM27OwnedAppParentV1 {
 pthread_mutex_t mutex;
 pid_t ownerPID;
 dispatch_queue_t queue;
 dispatch_semaphore_t ready,listenerInvalid,peerInvalid;
 xpc_connection_t listener,peer;
 xpc_endpoint_t endpoint;
 VM27LargeBundleRegistry *registry;
 VM27LargePrivateServiceConsumerV2 *consumer;
 uint64_t nonce;
 bool readySignaled,closing,draining,listenerActivated;
 bool configurationDelivered;
 char parentBundle[4096],parentExecutable[256],parentSHA[65],parentCD[41];
 uid_t parentOwner;
 VM27OwnedAppParentStateV1 state;
};
struct VM27OwnedAppChildV1 {
 pthread_mutex_t mutex;
 pid_t ownerPID;
 VM27OwnedStartupChildV3 *prepared;
 dispatch_queue_t queue;
 dispatch_semaphore_t ready,invalid;
 xpc_connection_t control;
 uint64_t nonce;
 bool readySignaled,finalInvalid,closing,draining,serviceStopped;
 unsigned pendingReplies;
 xpc_object_t configurationMessage;
 VM27OwnedAppParentIdentityV1 parentIdentity;
 int startupStatus,controlStatus;
};
static const char ParentQueueKeyV1,ChildQueueKeyV1;
static const char AckMethodV1[]="VM27.owned-app-startup-ack.v1";
static const char ConfigurationMethodV1[]="VM27.owned-app-configuration.v1";
static int LockV1(pthread_mutex_t *m){return pthread_mutex_lock(m);}
static int UnlockV1(pthread_mutex_t *m){return pthread_mutex_unlock(m);}
static bool HexV1(const char *s,size_t n) {
 if(!s || strnlen(s,n+1)!=n)return false;
 for(size_t i=0;i<n;i++)if(!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f')))return false;
 return true;
}
int VM27OwnedAppCreateScopedPluginRequirementV1(xpc_object_t *out) {
 if(!out || *out)return EINVAL;
 xpc_object_t requirement=xpc_dictionary_create(NULL,NULL,0),entitlements=xpc_dictionary_create(NULL,NULL,0);
 xpc_object_t query=xpc_array_create(NULL,0),select=xpc_array_create(NULL,0),match=xpc_array_create(NULL,0);
 xpc_object_t opSelect=xpc_int64_create(1),opEqual=xpc_int64_create(5),key=xpc_string_create(VM27_PLUGIN_ENTITLEMENT),boolean=xpc_bool_create(true);
 int status=0;
 if(!requirement || !entitlements || !query || !select || !match || !opSelect || !opEqual || !key || !boolean)status=ENOMEM;
 if(!status) {
  xpc_array_append_value(select,opSelect);xpc_array_append_value(select,key);xpc_array_append_value(match,opEqual);xpc_array_append_value(match,boolean);
  xpc_array_append_value(query,select);xpc_array_append_value(query,match);xpc_dictionary_set_value(entitlements,"$query",query);xpc_dictionary_set_value(requirement,"entitlements",entitlements);
  VM27LWCRPolicy *policy=NULL;status=VM27LWCRPolicyCreate(requirement,&policy);if(!status)VM27LWCRPolicyRelease(policy);
 }
 if(opSelect)xpc_release(opSelect);if(opEqual)xpc_release(opEqual);if(key)xpc_release(key);if(boolean)xpc_release(boolean);
 if(select)xpc_release(select);if(match)xpc_release(match);if(query)xpc_release(query);if(entitlements)xpc_release(entitlements);
 if(status){if(requirement)xpc_release(requirement);}else *out=requirement;return status;
}
static int ParentOwnedV1(VM27OwnedAppParentV1 *o) {
 return !o?EINVAL:o->ownerPID!=getpid()?EPERM:0;
}
static int ChildOwnedV1(VM27OwnedAppChildV1 *o) {
 return !o?EINVAL:o->ownerPID!=getpid()?EPERM:0;
}
static void ParentReadyV1(VM27OwnedAppParentV1 *o,int status) {
 if(LockV1(&o->mutex))abort();
 if(!o->readySignaled){o->readySignaled=true;o->state.startupStatus=status;dispatch_semaphore_signal(o->ready);}
 if(UnlockV1(&o->mutex))abort();
}
static void ParentPeerEventV1(VM27OwnedAppParentV1 *o,xpc_object_t event) {
 if(event==XPC_ERROR_CONNECTION_INVALID) {
  if(LockV1(&o->mutex))abort();
  if(!o->state.controlFinalInvalid){o->state.controlFinalInvalid=true;dispatch_semaphore_signal(o->peerInvalid);}
  if(UnlockV1(&o->mutex))abort();ParentReadyV1(o,ECONNRESET);return;
 }
 if(xpc_get_type(event)!=XPC_TYPE_DICTIONARY){ParentReadyV1(o,EPROTO);return;}
 xpc_object_t method=xpc_dictionary_get_value(event,"privateMethod");
 if(method && xpc_get_type(method)==XPC_TYPE_STRING && !strcmp(xpc_string_get_string_ptr(method),ConfigurationMethodV1)) {
  if(LockV1(&o->mutex))abort();bool admit=!o->closing && !o->configurationDelivered && !o->readySignaled;if(UnlockV1(&o->mutex))abort();
  VM27ApprovedCodeMessageResult identity={0};
  int status=!admit?EALREADY:xpc_dictionary_get_count(event)!=1?EPROTO:VM27LargePrivateServiceConsumerV2CheckMessage(o->consumer,event,&identity);
  xpc_object_t reply=xpc_dictionary_create_reply(event);
  if(reply) {
   xpc_dictionary_set_string(reply,"privateMethod",ConfigurationMethodV1);
   xpc_dictionary_set_int64(reply,"status",status);
   if(!status) {
    xpc_dictionary_set_uint64(reply,"nonce",o->nonce);
    xpc_dictionary_set_string(reply,"bundlePath",o->parentBundle);
    xpc_dictionary_set_string(reply,"executableName",o->parentExecutable);
    xpc_dictionary_set_string(reply,"executableSHA256",o->parentSHA);
    xpc_dictionary_set_string(reply,"executableCDHash",o->parentCD);
    xpc_dictionary_set_uint64(reply,"ownerUID",o->parentOwner);
   }
   xpc_connection_t remote=xpc_dictionary_get_remote_connection(event);
   if(remote)xpc_connection_send_message(remote,reply);else if(!status)status=ENOTCONN;xpc_release(reply);
  }else if(!status)status=ENOMEM;
  if(!status){if(LockV1(&o->mutex))abort();o->configurationDelivered=true;if(UnlockV1(&o->mutex))abort();}
  else ParentReadyV1(o,status);return;
 }
 if(LockV1(&o->mutex))abort();
 bool admit=!o->closing && o->configurationDelivered && !o->state.helloInstalled && !o->readySignaled;
 if(UnlockV1(&o->mutex))abort();
 int status=admit?VM27OwnedStartupParentInstallFactoryV3(o->consumer,event,o->nonce):EALREADY;
 /* Never acknowledge success unless the genuine native consumer accepted
  * this received dictionary's actual audit token and kernel code identity. */
 if(!status) {
  if(LockV1(&o->mutex))abort();o->state.helloInstalled=true;if(UnlockV1(&o->mutex))abort();
 }
 xpc_object_t reply=xpc_dictionary_create_reply(event);
 if(reply) {
  xpc_dictionary_set_string(reply,"privateMethod",AckMethodV1);
  xpc_dictionary_set_uint64(reply,"nonce",o->nonce);
  xpc_dictionary_set_int64(reply,"status",status);
  xpc_connection_t remote=xpc_dictionary_get_remote_connection(event);
  if(remote)xpc_connection_send_message(remote,reply);else if(!status)status=ENOTCONN;
  xpc_release(reply);
 }else if(!status)status=ENOMEM;
 ParentReadyV1(o,status);
}
int VM27OwnedAppParentStartV1(const VM27OwnedAppParentConfigurationV1 *c,VM27OwnedAppParentV1 **out) {
 if(!out || *out || !c || !c->actualRegistryRoot || c->actualRegistryRoot[0]!='/' ||
  !c->actualImmediateBundlePath || c->actualImmediateBundlePath[0]!='/' ||
  !c->actualServiceIdentifier || strcmp(c->actualServiceIdentifier,VM27_ORIGINAL_VM_SERVICE) ||
  !HexV1(c->reviewedChildSHA256,64) || !HexV1(c->reviewedChildCDHash,40) ||
  !c->originalImmutableRequirement || !c->actualArgv || !c->actualEnvironment || !c->bootstrapNonce ||
  !c->actualParentBundle.bundlePath || c->actualParentBundle.bundlePath[0]!='/' || strnlen(c->actualParentBundle.bundlePath,4096)>=4096 ||
  !c->actualParentBundle.executableName || !c->actualParentBundle.executableName[0] || strnlen(c->actualParentBundle.executableName,256)>=256 ||
  !HexV1(c->actualParentBundle.reviewedExecutableSHA256,64) || !HexV1(c->actualParentBundle.reviewedExecutableCDHash,40))return EINVAL;
 VM27OwnedAppParentV1 *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 int status=pthread_mutex_init(&o->mutex,NULL);if(status){free(o);return status;}
 o->ownerPID=getpid();o->state.ownerPID=o->ownerPID;o->nonce=c->bootstrapNonce;o->state.startupStatus=EINPROGRESS;*out=o;
 strcpy(o->parentBundle,c->actualParentBundle.bundlePath);strcpy(o->parentExecutable,c->actualParentBundle.executableName);
 strcpy(o->parentSHA,c->actualParentBundle.reviewedExecutableSHA256);strcpy(o->parentCD,c->actualParentBundle.reviewedExecutableCDHash);
 o->parentOwner=c->actualParentBundle.expectedOwnerUID;
 o->queue=dispatch_queue_create("VM27.owned.app.parent.control.v1",DISPATCH_QUEUE_SERIAL);
 o->ready=dispatch_semaphore_create(0);o->listenerInvalid=dispatch_semaphore_create(0);o->peerInvalid=dispatch_semaphore_create(0);
 if(!o->queue || !o->ready || !o->listenerInvalid || !o->peerInvalid)return ENOMEM;
 dispatch_queue_set_specific(o->queue,&ParentQueueKeyV1,o,NULL);
 status=VM27LargeBundleRegistryCreate(c->actualRegistryRoot,&o->registry);
 if(!status)status=VM27LargeBundleRegistryRegister(o->registry,c->actualImmediateBundlePath,2,c->originalImmutableRequirement);
 if(!status)status=VM27LargePrivateServiceConsumerV2Create(o->registry,c->actualServiceIdentifier,
  c->reviewedChildSHA256,c->reviewedChildCDHash,c->originalImmutableRequirement,VM27LargeConsumerV2StrictNative,&o->consumer);
 if(status){o->state.startupStatus=status;return status;}
 o->listener=xpc_connection_create(NULL,o->queue);
 if(!o->listener){o->state.startupStatus=ENOMEM;return ENOMEM;}
 xpc_connection_set_event_handler(o->listener,^(xpc_object_t event) {
  if(event==XPC_ERROR_CONNECTION_INVALID) {
   if(LockV1(&o->mutex))abort();
   if(!o->state.listenerFinalInvalid){o->state.listenerFinalInvalid=true;dispatch_semaphore_signal(o->listenerInvalid);}
   if(UnlockV1(&o->mutex))abort();return;
  }
  if(xpc_get_type(event)!=XPC_TYPE_CONNECTION){ParentReadyV1(o,EPROTO);return;}
  if(LockV1(&o->mutex))abort();bool refuse=o->peer || o->closing;if(UnlockV1(&o->mutex))abort();
  if(refuse){xpc_connection_cancel((xpc_connection_t)event);return;}
  o->peer=(xpc_connection_t)xpc_retain(event);
  xpc_connection_set_target_queue(o->peer,o->queue);
  xpc_connection_set_event_handler(o->peer,^(xpc_object_t value){ParentPeerEventV1(o,value);});
  xpc_connection_activate(o->peer);
 });
 o->endpoint=xpc_endpoint_create(o->listener);
 if(!o->endpoint){o->state.startupStatus=ENOMEM;return ENOMEM;}
 xpc_connection_activate(o->listener);o->listenerActivated=true;
 pid_t child=0;status=VM27LargePrivateServiceConsumerV2Spawn(o->consumer,o->endpoint,c->actualArgv,c->actualEnvironment,&child);
 /* A late Spawn error may still own an actual child. Preserve the true state. */
 VM27LargePrivateConsumerV2State actual={0};int copied=VM27LargePrivateServiceConsumerV2CopyState(o->consumer,&actual);
 if(LockV1(&o->mutex))abort();
 if(!copied){o->state.spawned=actual.started;o->state.childPID=actual.childPID;}
 else if(child>0){o->state.spawned=true;o->state.childPID=child;}
 if(UnlockV1(&o->mutex))abort();
 if(status || copied){ParentReadyV1(o,status?status:copied);return status?status:copied;}
 if(dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))) {
  ParentReadyV1(o,ETIMEDOUT);return ETIMEDOUT;
 }
 if(LockV1(&o->mutex))return EBUSY;status=o->state.startupStatus;int released=UnlockV1(&o->mutex);return status?status:released;
}
int VM27OwnedAppParentCopyStateV1(VM27OwnedAppParentV1 *o,VM27OwnedAppParentStateV1 *out) {
 int status=ParentOwnedV1(o);if(status || !out)return status?status:EINVAL;
 if((status=LockV1(&o->mutex)))return status;*out=o->state;return UnlockV1(&o->mutex);
}
int VM27OwnedAppParentDrainV1(VM27OwnedAppParentV1 *o) {
 int status=ParentOwnedV1(o);if(status)return status;
 if(o->queue && dispatch_get_specific(&ParentQueueKeyV1)==o)return EDEADLK;
 if((status=LockV1(&o->mutex)))return status;
 if(o->draining){UnlockV1(&o->mutex);return EBUSY;}o->draining=true;o->closing=true;
 if(UnlockV1(&o->mutex))return EBUSY;
 if(o->queue)dispatch_sync(o->queue,^{
  if(o->peer)xpc_connection_cancel(o->peer);
  if(o->listener){xpc_connection_cancel(o->listener);if(!o->listenerActivated){xpc_connection_activate(o->listener);o->listenerActivated=true;}}
 });
 dispatch_time_t until=dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC);
 if(LockV1(&o->mutex))return EBUSY;bool peerDone=o->state.controlFinalInvalid,listenerDone=o->state.listenerFinalInvalid;if(UnlockV1(&o->mutex))return EBUSY;
 if(o->peer && !peerDone && dispatch_semaphore_wait(o->peerInvalid,until))status=ETIMEDOUT;
 if(!status && o->listener && !listenerDone && dispatch_semaphore_wait(o->listenerInvalid,until))status=ETIMEDOUT;
 if(!status && o->queue)dispatch_sync(o->queue,^{});
 if(LockV1(&o->mutex))return EBUSY;o->draining=false;o->state.controlStatus=status;
 if(UnlockV1(&o->mutex))return EBUSY;return status;
}
int VM27OwnedAppParentReleaseV1(VM27OwnedAppParentV1 **address) {
 if(!address || !*address)return EINVAL;VM27OwnedAppParentV1 *o=*address;
 int status=ParentOwnedV1(o);if(status)return status;
 if((status=LockV1(&o->mutex)))return status;bool live=o->state.spawned || o->state.helloInstalled;if(UnlockV1(&o->mutex))return EBUSY;
 if(live)return EBUSY;
 if((status=VM27OwnedAppParentDrainV1(o)))return status;
 if(o->consumer && (status=VM27LargePrivateServiceConsumerV2Release(o->consumer)))return status;
 if(o->registry)VM27LargeBundleRegistryRelease(o->registry);
 if(o->peer)xpc_release(o->peer);if(o->endpoint)xpc_release(o->endpoint);if(o->listener)xpc_release(o->listener);
 if(o->queue)dispatch_release(o->queue);if(o->ready)dispatch_release(o->ready);
 if(o->peerInvalid)dispatch_release(o->peerInvalid);if(o->listenerInvalid)dispatch_release(o->listenerInvalid);
 pthread_mutex_destroy(&o->mutex);free(o);*address=NULL;return 0;
}
static int ReleasePortsV1(mach_port_array_t ports,mach_msg_type_number_t count) {
 int status=0;
 for(mach_msg_type_number_t i=0;i<count;i++)if(MACH_PORT_VALID(ports[i]) && mach_port_deallocate(mach_task_self(),ports[i]))status=EIO;
 if(ports && vm_deallocate(mach_task_self(),(vm_address_t)ports,count*sizeof(*ports)))status=EIO;return status;
}
static void ChildReadyV1(VM27OwnedAppChildV1 *o,int status) {
 if(LockV1(&o->mutex))abort();
 if(!o->readySignaled){o->readySignaled=true;o->startupStatus=status;dispatch_semaphore_signal(o->ready);}
 if(UnlockV1(&o->mutex))abort();
}
int VM27OwnedAppChildPrepareBeforeMainV1(const VM27OwnedStartupConfigurationV3 *c,VM27OwnedAppChildV1 **out) {
 if(!out || *out || !c || c->parent.kind!=VM27OriginalV10ParentFlatBundle ||
  c->parent.expectedParentPID!=getppid() || getppid()<=1 || !c->bootstrapNonce)return EINVAL;
 VM27OwnedAppChildV1 *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 int status=pthread_mutex_init(&o->mutex,NULL);if(status){free(o);return status;}
 o->ownerPID=getpid();o->nonce=c->bootstrapNonce;o->startupStatus=EINPROGRESS;*out=o;
 o->ready=dispatch_semaphore_create(0);o->invalid=dispatch_semaphore_create(0);if(!o->ready || !o->invalid)return ENOMEM;
 xpc_object_t hello=NULL;status=VM27OwnedStartupChildPrepareV3(c,&o->prepared,&hello);
 if(!status)status=VM27OwnedStartupChildCopyControlQueueV3(o->prepared,&o->queue);
 if(status){if(hello)xpc_release(hello);o->startupStatus=status;return status;}
 dispatch_queue_set_specific(o->queue,&ChildQueueKeyV1,o,NULL);
 mach_port_array_t ports=NULL;mach_msg_type_number_t count=0;
 kern_return_t kr=mach_ports_lookup(mach_task_self(),&ports,&count);
 if(kr!=KERN_SUCCESS)status=EIO;
 else if(count!=3 || !MACH_PORT_VALID(ports[2]))status=ENOTCONN;
 else status=VM27PrivateEndpointConnectSendRight(ports[2],o->queue,&o->control);
 int portStatus=ports?ReleasePortsV1(ports,count):0;
 if(!status)status=portStatus;
 if(status && !o->control){xpc_release(hello);o->startupStatus=status;return status;}
 xpc_connection_set_event_handler(o->control,^(xpc_object_t event) {
  if(event==XPC_ERROR_CONNECTION_INVALID) {
   if(LockV1(&o->mutex))abort();
   if(!o->finalInvalid){o->finalInvalid=true;dispatch_semaphore_signal(o->invalid);}
   if(UnlockV1(&o->mutex))abort();ChildReadyV1(o,ECONNRESET);return;
  }
  if(xpc_get_type(event)!=XPC_TYPE_DICTIONARY)return;
  if(LockV1(&o->mutex))abort();bool closing=o->closing;if(UnlockV1(&o->mutex))abort();
  xpc_object_t reply=NULL;int result=closing?ECANCELED:VM27OwnedStartupChildReceiveControlV3(o->prepared,event,&reply);
  if(reply){xpc_connection_t remote=xpc_dictionary_get_remote_connection(event);if(remote)xpc_connection_send_message(remote,reply);xpc_release(reply);}
  if(LockV1(&o->mutex))abort();o->controlStatus=result;if(UnlockV1(&o->mutex))abort();
 });
 xpc_connection_activate(o->control);
 if(status){xpc_release(hello);o->startupStatus=status;return status;}
 if(LockV1(&o->mutex))abort();++o->pendingReplies;if(UnlockV1(&o->mutex))abort();
 xpc_connection_send_message_with_reply(o->control,hello,o->queue,^(xpc_object_t reply) {
  int result=EPROTO;
  if(reply && xpc_get_type(reply)==XPC_TYPE_DICTIONARY && xpc_dictionary_get_count(reply)==3) {
   xpc_object_t method=xpc_dictionary_get_value(reply,"privateMethod"),nonce=xpc_dictionary_get_value(reply,"nonce"),value=xpc_dictionary_get_value(reply,"status");
   if(method && xpc_get_type(method)==XPC_TYPE_STRING && !strcmp(xpc_string_get_string_ptr(method),AckMethodV1) &&
    nonce && xpc_get_type(nonce)==XPC_TYPE_UINT64 && xpc_uint64_get_value(nonce)==o->nonce &&
    value && xpc_get_type(value)==XPC_TYPE_INT64) {
    int64_t actual=xpc_int64_get_value(value);if(actual>=0 && actual<=INT32_MAX)result=(int)actual;
   }
  }
  if(LockV1(&o->mutex))abort();--o->pendingReplies;if(UnlockV1(&o->mutex))abort();
  ChildReadyV1(o,result);
 });
 xpc_release(hello);
 if(dispatch_semaphore_wait(o->ready,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_SEC))){ChildReadyV1(o,ETIMEDOUT);return ETIMEDOUT;}
 if((status=LockV1(&o->mutex)))return status;status=o->startupStatus;int released=UnlockV1(&o->mutex);return status?status:released;
}
int VM27OwnedAppChildDrainV1(VM27OwnedAppChildV1 *o) {
 int status=ChildOwnedV1(o);if(status)return status;
 if(o->queue && dispatch_get_specific(&ChildQueueKeyV1)==o)return EDEADLK;
 if((status=LockV1(&o->mutex)))return status;
 if(o->draining){UnlockV1(&o->mutex);return EBUSY;}o->draining=true;o->closing=true;
 if(UnlockV1(&o->mutex))return EBUSY;
 if(o->prepared && !o->serviceStopped){status=VM27OwnedStartupChildStopV3(o->prepared);if(!status)o->serviceStopped=true;}
 if(o->control)xpc_connection_cancel(o->control);
 if(LockV1(&o->mutex))return EBUSY;bool invalid=o->finalInvalid;if(UnlockV1(&o->mutex))return EBUSY;
 if(!status && o->control && !invalid && dispatch_semaphore_wait(o->invalid,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)))status=ETIMEDOUT;
 if(!status && o->queue)dispatch_sync(o->queue,^{});
 if(LockV1(&o->mutex))return EBUSY;if(!status && o->pendingReplies)status=EBUSY;o->draining=false;o->controlStatus=status;if(UnlockV1(&o->mutex))return EBUSY;return status;
}
int VM27OwnedAppChildReleaseV1(VM27OwnedAppChildV1 **address) {
 if(!address || !*address)return EINVAL;VM27OwnedAppChildV1 *o=*address;
 int status=ChildOwnedV1(o);if(status)return status;
 if((status=VM27OwnedAppChildDrainV1(o)))return status;
 if(o->prepared && (status=VM27OwnedStartupChildReleaseV3(&o->prepared)))return status;
 if(o->control)xpc_release(o->control);if(o->queue)dispatch_release(o->queue);
 if(o->configurationMessage)xpc_release(o->configurationMessage);
 if(o->ready)dispatch_release(o->ready);if(o->invalid)dispatch_release(o->invalid);
 pthread_mutex_destroy(&o->mutex);free(o);*address=NULL;return 0;
}
static const char *ConfigurationStringV2(xpc_object_t message,const char *name,size_t limit) {
 xpc_object_t value=xpc_dictionary_get_value(message,name);
 if(!value || xpc_get_type(value)!=XPC_TYPE_STRING)return NULL;
 const char *s=xpc_string_get_string_ptr(value);return s && strnlen(s,limit)<limit?s:NULL;
}
static int ConfigurationShapeV2(xpc_object_t reply,const VM27OwnedAppParentIdentityV1 *native) {
 if(!reply || !native || xpc_get_type(reply)!=XPC_TYPE_DICTIONARY)return EPROTO;
 const char *method=ConfigurationStringV2(reply,"privateMethod",128),*cd=ConfigurationStringV2(reply,"executableCDHash",41);
 xpc_object_t source=xpc_dictionary_get_value(reply,"status"),nonce=xpc_dictionary_get_value(reply,"nonce"),uid=xpc_dictionary_get_value(reply,"ownerUID");
 return xpc_dictionary_get_count(reply)!=8 || !method || strcmp(method,ConfigurationMethodV1) || !source || xpc_get_type(source)!=XPC_TYPE_INT64 ||
  xpc_int64_get_value(source)!=0 || !nonce || xpc_get_type(nonce)!=XPC_TYPE_UINT64 || !xpc_uint64_get_value(nonce) ||
  !uid || xpc_get_type(uid)!=XPC_TYPE_UINT64 || xpc_uint64_get_value(uid)>UINT32_MAX || !cd || strcmp(cd,native->kernelCDHash) ||
  !ConfigurationStringV2(reply,"bundlePath",4096) || !ConfigurationStringV2(reply,"executableName",256) ||
  !HexV1(ConfigurationStringV2(reply,"executableSHA256",65),64)?EPROTO:0;
}
int VM27OwnedAppChildBootstrapBeforeMainV2(VM27OwnedAppChildV1 **out) {
 if(!out || *out || getppid()<=1)return EINVAL;
 VM27OwnedAppChildV1 *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 int status=pthread_mutex_init(&o->mutex,NULL);if(status){free(o);return status;}
 o->ownerPID=getpid();o->startupStatus=EINPROGRESS;*out=o;
 o->queue=dispatch_queue_create("VM27.owned.app.child.bootstrap.v2",DISPATCH_QUEUE_SERIAL);
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
  if(LockV1(&o->mutex))abort();bool admit=!o->closing && o->prepared!=NULL;if(UnlockV1(&o->mutex))abort();
  xpc_object_t reply=NULL;int result=admit?VM27OwnedStartupChildReceiveControlV3(o->prepared,event,&reply):ENOTCONN;
  if(reply){xpc_connection_t remote=xpc_dictionary_get_remote_connection(event);if(remote)xpc_connection_send_message(remote,reply);xpc_release(reply);}
  if(LockV1(&o->mutex))abort();o->controlStatus=result;if(UnlockV1(&o->mutex))abort();
 });
 xpc_connection_activate(o->control);if(status){o->startupStatus=status;return status;}
 xpc_object_t request=xpc_dictionary_create(NULL,NULL,0);if(!request){o->startupStatus=ENOMEM;return ENOMEM;}
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
 xpc_object_t hello=NULL;status=VM27OwnedStartupChildPrepareV3(&c,&o->prepared,&hello);
 dispatch_queue_t actualControlQueue=NULL;if(!status)status=VM27OwnedStartupChildCopyControlQueueV3(o->prepared,&actualControlQueue);
 if(status){if(hello)xpc_release(hello);o->startupStatus=status;return status;}
 /* All bootstrap callbacks have drained above. Preserve V3's genuine queue
  * identity for each later control dispatch; a VZ CPU pthread is unrelated. */
 dispatch_queue_set_specific(actualControlQueue,&ChildQueueKeyV1,o,NULL);
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
