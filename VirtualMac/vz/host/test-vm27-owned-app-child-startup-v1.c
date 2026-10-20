/* Finite adapter ownership models; native trust/registry/spawn are replaced
 * below. Public dispatch/XPC objects remain real. No process is spawned. */
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#error Mocked native startup fixture must never be compiled for the product.
#endif
#define VM27LargeBundleRegistryCreate ModelRegistryCreateV1
#define VM27LargeBundleRegistryRegister ModelRegistryRegisterV1
#define VM27LargeBundleRegistryRelease ModelRegistryReleaseV1
#define VM27LargePrivateServiceConsumerV2Create ModelConsumerCreateV1
#define VM27LargePrivateServiceConsumerV2Spawn ModelConsumerSpawnV1
#define VM27LargePrivateServiceConsumerV2CopyState ModelConsumerCopyStateV1
#define VM27LargePrivateServiceConsumerV2Release ModelConsumerReleaseV1
#define VM27LargePrivateServiceConsumerV2CheckMessage ModelConsumerCheckMessageV1
#define VM27OwnedStartupParentInstallFactoryV3 ModelInstallV1
#define VM27OwnedStartupChildPrepareV3 ModelChildPrepareV1
#define VM27OwnedStartupChildCopyControlQueueV3 ModelChildQueueV1
#define VM27OwnedStartupChildReceiveControlV3 ModelChildReceiveV1
#define VM27OwnedStartupChildStopV3 ModelChildStopV1
#define VM27OwnedStartupChildReleaseV3 ModelChildReleaseV1
#define VM27PrivateEndpointConnectSendRight ModelEndpointConnectV1
#define VM27OwnedAppCheckActualParentMessageV1 ModelParentIdentityV1
#include "vm27_owned_app_child_startup_v1.c"
#include <stdio.h>
static unsigned Checks,ConsumerReleases,RegistryReleases,Stops,ChildReleases,Installs;
static int RegistryResult,ChildPrepareResult,ChildStopResult,InstallResult;
static VM27LargePrivateConsumerV2State ConsumerState;
struct VM27LargeBundleRegistry {int own;};
struct VM27LargePrivateServiceConsumerV2 {int own;};
struct VM27OwnedStartupChildV3 {dispatch_queue_t queue;};
static void Check(bool value,const char *name) {
 ++Checks;if(!value){fprintf(stderr,"FAILED %s\n",name);exit(1);}
}
int ModelRegistryCreateV1(const char *root,VM27LargeBundleRegistry **out) {
 (void)root;if(RegistryResult)return RegistryResult;*out=calloc(1,sizeof(**out));return *out?0:ENOMEM;
}
int ModelRegistryRegisterV1(VM27LargeBundleRegistry *registry,const char *path,uint64_t flags,xpc_object_t constraint) {
 (void)registry;(void)path;(void)flags;(void)constraint;return 0;
}
void ModelRegistryReleaseV1(VM27LargeBundleRegistry *registry){++RegistryReleases;free(registry);}
int ModelConsumerCreateV1(VM27LargeBundleRegistry *r,const char *service,const char *sha,const char *cd,
 xpc_object_t requirement,VM27LargePrivateConsumerV2Mode mode,VM27LargePrivateServiceConsumerV2 **out) {
 (void)r;(void)service;(void)sha;(void)cd;(void)requirement;
 Check(mode==VM27LargeConsumerV2StrictNative,"production-selects-strict-mode");*out=calloc(1,sizeof(**out));return *out?0:ENOMEM;
}
int ModelConsumerSpawnV1(VM27LargePrivateServiceConsumerV2 *c,xpc_endpoint_t e,char *const a[],char *const v[],pid_t *pid) {
 (void)c;(void)e;(void)a;(void)v;(void)pid;return ENOTSUP;
}
int ModelConsumerCopyStateV1(VM27LargePrivateServiceConsumerV2 *c,VM27LargePrivateConsumerV2State *out){(void)c;*out=ConsumerState;return 0;}
int ModelConsumerReleaseV1(VM27LargePrivateServiceConsumerV2 *c){++ConsumerReleases;free(c);return 0;}
int ModelConsumerCheckMessageV1(VM27LargePrivateServiceConsumerV2 *c,xpc_object_t message,VM27ApprovedCodeMessageResult *out){(void)c;(void)message;(void)out;return EACCES;}
int ModelParentIdentityV1(xpc_object_t message,VM27OwnedAppParentIdentityV1 *out){(void)message;(void)out;return EACCES;}
int ModelInstallV1(VM27LargePrivateServiceConsumerV2 *c,xpc_object_t event,uint64_t nonce) {
 (void)c;(void)event;(void)nonce;++Installs;return InstallResult;
}
int ModelChildPrepareV1(const VM27OwnedStartupConfigurationV3 *c,VM27OwnedStartupChildV3 **out,xpc_object_t *hello) {
 (void)c;*out=calloc(1,sizeof(**out));if(!*out)return ENOMEM;
 (*out)->queue=dispatch_queue_create("VM27.model.true.child.serial",DISPATCH_QUEUE_SERIAL);
 if(ChildPrepareResult)return ChildPrepareResult;
 *hello=xpc_dictionary_create(NULL,NULL,0);return *hello?0:ENOMEM;
}
int ModelChildQueueV1(VM27OwnedStartupChildV3 *c,dispatch_queue_t *out){*out=c->queue;dispatch_retain(*out);return 0;}
int ModelChildReceiveV1(VM27OwnedStartupChildV3 *c,xpc_object_t event,xpc_object_t *reply){(void)c;(void)event;(void)reply;return ENOTSUP;}
int ModelChildStopV1(VM27OwnedStartupChildV3 *c){(void)c;++Stops;return ChildStopResult;}
int ModelChildReleaseV1(VM27OwnedStartupChildV3 **c){++ChildReleases;dispatch_release((*c)->queue);free(*c);*c=NULL;return 0;}
int ModelEndpointConnectV1(mach_port_t p,dispatch_queue_t q,xpc_connection_t *c){(void)p;(void)q;(void)c;return ENOTSUP;}
static VM27OwnedAppParentConfigurationV1 ParentConfigV1(xpc_object_t policy) {
 static char *argv[]={"/private/VM27Model/child",NULL};static char *env[]={NULL};
 static const char sha[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 static const char cd[]="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
 VM27OwnedAppParentConfigurationV1 c={"/private/VM27Model","/private/VM27Model/VM.bundle",VM27_ORIGINAL_VM_SERVICE,sha,cd,policy,argv,env,73,
  {"/private/VirtualMacModel.app","VirtualMacModel",sha,cd,geteuid()}};return c;
}
static VM27OwnedStartupConfigurationV3 ChildConfigV1(void) {
 VM27OwnedStartupConfigurationV3 c={0};c.parent.formatVersion=1;c.parent.kind=VM27OriginalV10ParentFlatBundle;c.parent.expectedParentPID=getppid();c.bootstrapNonce=73;return c;
}
int main(void) {
 xpc_object_t ownedPolicy=NULL;
 Check(!VM27OwnedAppCreateScopedPluginRequirementV1(&ownedPolicy) && ownedPolicy,"real-parser-accepts-owned-app-private-policy");
 Check(VM27OwnedAppCreateScopedPluginRequirementV1(&ownedPolicy)==EINVAL,"existing-policy-output-not-overwritten");
 xpc_release(ownedPolicy);
 xpc_object_t policy=xpc_dictionary_create(NULL,NULL,0);
 VM27OwnedAppParentConfigurationV1 p=ParentConfigV1(policy);VM27OwnedAppParentV1 *parent=NULL;
 p.originalImmutableRequirement=NULL;
 Check(VM27OwnedAppParentStartV1(&p,&parent)==EINVAL && !parent,"missing-policy-no-owned-start");
 p=ParentConfigV1(policy);RegistryResult=EACCES;
 Check(VM27OwnedAppParentStartV1(&p,&parent)==EACCES && parent,"failed-registry-keeps-actual-owner");
 VM27OwnedAppParentStateV1 state={0};
 Check(!VM27OwnedAppParentCopyStateV1(parent,&state) && state.startupStatus==EACCES && !state.spawned,"true-failure-state-no-spawn");
 Check(!VM27OwnedAppParentReleaseV1(&parent) && !parent && !ConsumerReleases && !RegistryReleases,"pre-spawn-owner-serial-drain-release");
 /* Real borrowed consumer lifetime after factory commit remains retained.
  * Do not pretend that adapter control INVALID is original VZ INVALID. */
 parent=calloc(1,sizeof(*parent));pthread_mutex_init(&parent->mutex,NULL);parent->ownerPID=getpid();parent->state.spawned=true;
 Check(VM27OwnedAppParentReleaseV1(&parent)==EBUSY && parent && !ConsumerReleases,"spawned-owner-release-retained");
 parent->state.spawned=false;parent->state.helloInstalled=true;
 Check(VM27OwnedAppParentReleaseV1(&parent)==EBUSY && parent && !ConsumerReleases,"installed-factory-release-retained");
 parent->state.helloInstalled=false;
 Check(!VM27OwnedAppParentReleaseV1(&parent) && !parent,"uninstalled-model-release");
 VM27OwnedStartupConfigurationV3 c=ChildConfigV1();VM27OwnedAppChildV1 *child=NULL;
 c.parent.expectedParentPID++;
 Check(VM27OwnedAppChildPrepareBeforeMainV1(&c,&child)==EINVAL && !child,"actual-getppid-required");
 c=ChildConfigV1();c.parent.kind=VM27OriginalV10ParentCodeOnlyDiagnostic;
 Check(VM27OwnedAppChildPrepareBeforeMainV1(&c,&child)==EINVAL && !child,"diagnostic-not-production-parent");
 c=ChildConfigV1();ChildPrepareResult=EACCES;
 Check(VM27OwnedAppChildPrepareBeforeMainV1(&c,&child)==EACCES && child && child->prepared,"late-prepare-failure-retains-v3-owner");
 ChildStopResult=EBUSY;
 Check(VM27OwnedAppChildReleaseV1(&child)==EBUSY && child && child->prepared && !ChildReleases,"failed-service-stop-retains-owner");
 ChildStopResult=0;
 Check(!VM27OwnedAppChildReleaseV1(&child) && !child && ChildReleases==1,"true-service-stop-then-release");
 /* A reply callback remains a real borrow even after connection INVALID. */
 child=calloc(1,sizeof(*child));pthread_mutex_init(&child->mutex,NULL);child->ownerPID=getpid();child->pendingReplies=1;
 Check(VM27OwnedAppChildReleaseV1(&child)==EBUSY && child,"pending-reply-borrow-retained");
 child->pendingReplies=0;
 Check(!VM27OwnedAppChildReleaseV1(&child) && !child,"completed-reply-borrow-release");
 /* Real queue identity, not the current pthread, prevents self-drain. */
 child=calloc(1,sizeof(*child));pthread_mutex_init(&child->mutex,NULL);child->ownerPID=getpid();
 child->queue=dispatch_queue_create("VM27.model.identity.child",DISPATCH_QUEUE_SERIAL);dispatch_queue_set_specific(child->queue,&ChildQueueKeyV1,child,NULL);
 __block int drained=0;VM27OwnedAppChildV1 *borrowed=child;
 dispatch_sync(child->queue,^{drained=VM27OwnedAppChildDrainV1(borrowed);});
 Check(drained==EDEADLK && child && !child->closing,"actual-queue-self-drain-refused");
 Check(!VM27OwnedAppChildReleaseV1(&child) && !child,"off-queue-real-barrier-release");
 VM27OwnedAppParentIdentityV1 native={0};memset(native.kernelCDHash,'b',40);
 xpc_object_t cfg=xpc_dictionary_create(NULL,NULL,0);
 xpc_dictionary_set_string(cfg,"privateMethod",ConfigurationMethodV1);xpc_dictionary_set_int64(cfg,"status",0);xpc_dictionary_set_uint64(cfg,"nonce",73);
 xpc_dictionary_set_uint64(cfg,"ownerUID",501);xpc_dictionary_set_string(cfg,"bundlePath","/private/Model.app");xpc_dictionary_set_string(cfg,"executableName","Model");
 xpc_dictionary_set_string(cfg,"executableSHA256",p.reviewedChildSHA256);xpc_dictionary_set_string(cfg,"executableCDHash",p.reviewedChildCDHash);
 Check(!ConfigurationShapeV2(cfg,&native),"finite-configuration-shape-only-native-auth-remains-separate");
 native.kernelCDHash[0]='a';Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"body-CD-does-not-substitute-kernel-CD");native.kernelCDHash[0]='b';
 xpc_dictionary_set_uint64(cfg,"nonce",0);Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"zero-binding-nonce-refused");xpc_dictionary_set_uint64(cfg,"nonce",73);
 xpc_dictionary_set_bool(cfg,"status",false);Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"Boolean-is-not-actual-typed-status");xpc_dictionary_set_int64(cfg,"status",0);
 xpc_dictionary_set_int64(cfg,"ownerUID",501);Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"signed-owner-field-wrong-type-refused");xpc_dictionary_set_uint64(cfg,"ownerUID",501);
 xpc_dictionary_set_string(cfg,"extraAuthority","ignored-must-fail");Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"extra-authority-facts-refused");xpc_dictionary_set_value(cfg,"extraAuthority",NULL);
 xpc_dictionary_set_string(cfg,"executableSHA256","0");Check(ConfigurationShapeV2(cfg,&native)==EPROTO,"malformed-file-expectation-refused");xpc_release(cfg);
 xpc_release(policy);
 printf("{\"checks\":%u,\"passed\":true,\"registryAndNativeTrustMocked\":true,\"nativeVMOperations\":0,\"processesSpawned\":0,\"actualXPCHandshakeExecuted\":false,\"guestBoot\":false}\n",Checks);
 return 0;
}
