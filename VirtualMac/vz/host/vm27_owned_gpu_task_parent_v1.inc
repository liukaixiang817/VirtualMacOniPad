/* Included only by the fresh MD26 root, after the unchanged MD25 scope helpers.
 * No Foundation swizzle, task port, named service registration or GPU emulation. */
#include "vm27_owned_gpu_task_parent_v1.h"
#include "modern_xpc_large_private_consumer_v5.h"
#include "vm27_owned_app_child_startup_v1.h"
#include <objc/message.h>
#include <signal.h>
#include <sys/stat.h>

#if __has_feature(objc_arc)
#error This source preserves the actual MD root MRC build contract
#endif

static const char VM27GPUControlQueueKeyV1, VM27GPUConnectionLeaseKeyV1;
static BOOL GPUHexV1(const char *s, size_t n) {
    if (!s || strnlen(s,n+1)!=n) return NO;
    for (size_t i=0;i<n;++i) if (!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return NO;
    return YES;
}
static BOOL GPUProfileV1(void) {
    const VM27OwnedGPUTaskParentProfileV1 *p=&VM27OwnedGPUTaskPinnedParentProfileV1;
    static const char root[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/gpu-task-flat";
    static const char bundle[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/gpu-task-flat/GPUTask.bundle";
    static const char executable[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc/Contents/MacOS/com.apple.gpusw.ParavirtualizedGraphicsGPUTask";
    return p->version==1 && p->ownerUID==501 && p->canonicalRegistryRoot && p->canonicalBundlePath && p->canonicalExecutablePath &&
        !strcmp(p->canonicalRegistryRoot,root) && !strcmp(p->canonicalBundlePath,bundle) && !strcmp(p->canonicalExecutablePath,executable) &&
        GPUHexV1(p->signedExecutableSHA256,64) && GPUHexV1(p->signedExecutableCDHash,40) && GPUHexV1(p->executableUUID,32);
}
static BOOL GPUParentAdmissionV1(id allocated,SEL selector,NSString *service,void *caller) {
    uint32_t status=0,capacity=4096;uint8_t uuid[16];char path[4096]={0},canonical[4096]={0};Dl_info owner={0};
    if (!GPUProfileV1() || !allocated || !selector || strcmp(sel_getName(selector),"initWithServiceName:") ||
        object_getClass(allocated)!=objc_getClass("NSXPCConnection") || ![service isKindOfClass:NSString.class] ||
        ![service isEqualToString:@VM27_GPU_TASK_SERVICE_V1] || getuid()!=501 || geteuid()!=501 ||
        csops(getpid(),0,&status,sizeof(status)) || (status&UINT32_C(0x04000001))!=UINT32_C(0x04000001) ||
        !vm27_metal_device_array_profile_matches() || _NSGetExecutablePath(path,&capacity) || capacity>sizeof(path) ||
        !memchr(path,0,sizeof(path)) || !realpath(path,canonical) || strcmp(canonical,PVGChildPathV1) ||
        !caller || !dladdr(caller,&owner) || !owner.dli_fname || strcmp(owner.dli_fname,PVGImagePathV1) ||
        !PVGReadUUIDV1(owner.dli_fbase,MH_DYLIB,uuid) || memcmp(uuid,PVGImageUUIDV1,16) ||
        (uintptr_t)caller<(uintptr_t)owner.dli_fbase || (uintptr_t)caller-(uintptr_t)owner.dli_fbase!=0x36398) return NO;
    unsigned mains=0;
    for (uint32_t i=0,n=_dyld_image_count();i<n && n<=4096;++i) {
        const char *name=_dyld_get_image_name(i);
        if (!name || strcmp(name,PVGChildPathV1)) continue;
        if (++mains!=1 || !PVGReadUUIDV1(_dyld_get_image_header(i),MH_EXECUTE,uuid) || memcmp(uuid,PVGChildUUIDV1,16)) return NO;
    }
    Method init=class_getInstanceMethod(objc_getClass("NSXPCConnection"),sel_registerName("initWithListenerEndpoint:"));
    return mains==1 && init && method_getNumberOfArguments(init)==3;
}

@interface VM27OwnedGPUTaskParentV1 : NSObject {
@public
    VM27LargeBundleRegistry *registry;
    VM27LargePrivateServiceConsumerV2 *consumer;
    dispatch_queue_t queue;
    dispatch_semaphore_t ready;
    dispatch_source_t process;
    xpc_connection_t listener,peer;
    xpc_endpoint_t bootstrapEndpoint,serviceEndpoint;
    uint64_t nonce;
    pid_t childPID;
    int startupStatus;
    BOOL configured,readySignaled,closing,listenerInvalid,peerInvalid,reaped,processCanceled,lifetimeHeld,spawnDecisionFinished;
}
- (int)start;
- (void)event:(xpc_object_t)value;
- (void)signalReady:(int)status;
- (void)close;
- (void)closeOnQueue;
- (void)finishIfDrained;
- (void)signalOwnedChild:(int)signal;
- (void)reapOwnedChildWithBudget:(unsigned)budget;
- (void)finishSpawnDecision;
@end

/* The original PG still owns all NSXPC handlers and calls invalidate normally.
 * This independent associated lease only closes our extra bootstrap ownership
 * when the original connection is actually released. It never retains it. */
@interface VM27OwnedGPUTaskConnectionLeaseV1 : NSObject {
@public VM27OwnedGPUTaskParentV1 *owner;
}
@end
@implementation VM27OwnedGPUTaskConnectionLeaseV1
- (void)dealloc { [owner close];[owner release];[super dealloc]; }
@end

@implementation VM27OwnedGPUTaskParentV1
- (void)signalReady:(int)status {
    if (!readySignaled) { readySignaled=YES;startupStatus=status;dispatch_semaphore_signal(ready); }
}
- (void)finishIfDrained {
    if (!spawnDecisionFinished || !closing || !listenerInvalid || !peerInvalid || !reaped || !processCanceled || !lifetimeHeld) return;
    if (consumer && VM27LargePrivateServiceConsumerV2Release(consumer)) return;
    consumer=NULL;lifetimeHeld=NO;
    /* Each handler has a local autorelease pool and finishes before this lease
     * is released. No raw owner survives cancellation's final notifications. */
    [self autorelease];
}
- (void)signalOwnedChild:(int)signal {
    VM27LargePrivateConsumerV2State state={0};
    if (!consumer || VM27LargePrivateServiceConsumerV2CopyState(consumer,&state) ||
        !state.started || state.reaped || state.absent || state.childPID!=childPID || childPID<=1) return;
    /* Our sole serial waitpid owner has not reaped: this PID cannot be reused. */
    int result=kill(childPID,signal);
    if (result && errno!=ESRCH) dprintf(2,"[VM27OwnedGPUTaskParentV1] signal=%d status=%d ownedChild=%d\n",signal,errno,childPID);
}
- (void)reapOwnedChildWithBudget:(unsigned)budget {
    if (reaped || !consumer) return;
    VM27LargePrivateConsumerV2State ended={0};int status=VM27LargePrivateServiceConsumerV2Wait(consumer,false,&ended);
    if (!status && ended.reaped) {
        reaped=YES;
        dprintf(2,"[VM27OwnedGPUTaskParentV1] stage=reap status=0 child=%d reaped=1 exit=%d\n",childPID,ended.observedWaitExit);
        [self closeOnQueue];if (process) dispatch_source_cancel(process);[self finishIfDrained];
    } else if (status==EAGAIN && budget) {
        VM27OwnedGPUTaskParentV1 *retained=self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC/10),queue,^{@autoreleasepool {
            [retained reapOwnedChildWithBudget:budget-1];
        }});
    } else dprintf(2,"[VM27OwnedGPUTaskParentV1] stage=reap status=%d child=%d reaped=0 ownershipRetained=1\n",status,childPID);
}
- (void)closeOnQueue {
    if (closing) return;closing=YES;[self signalReady:ECANCELED];
    if (peer) xpc_connection_cancel(peer);else peerInvalid=YES;
    if (listener) xpc_connection_cancel(listener);else listenerInvalid=YES;
    [self signalOwnedChild:SIGTERM];
    VM27OwnedGPUTaskParentV1 *retained=self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),queue,^{@autoreleasepool {
        [retained signalOwnedChild:SIGKILL];[retained reapOwnedChildWithBudget:20];[retained finishIfDrained];
    }});
    [self finishIfDrained];
}
- (void)close {
    if (!queue) return;
    if (dispatch_get_specific(&VM27GPUControlQueueKeyV1)==self) [self closeOnQueue];
    else dispatch_async(queue,^{@autoreleasepool { [self closeOnQueue]; }});
}
- (void)finishSpawnDecision {
    if (!queue) return;
    void (^finish)(void)=^{ self->spawnDecisionFinished=YES;[self finishIfDrained]; };
    if (dispatch_get_specific(&VM27GPUControlQueueKeyV1)==self) finish();else dispatch_sync(queue,finish);
}
- (void)event:(xpc_object_t)value {
    if (value==XPC_ERROR_CONNECTION_INVALID) { peerInvalid=YES;[self signalReady:ECONNRESET];[self closeOnQueue];[self finishIfDrained];return; }
    if (closing || xpc_get_type(value)!=XPC_TYPE_DICTIONARY) { [self signalReady:EPROTO];[self closeOnQueue];return; }
    VM27ApprovedCodeMessageResult identity={0};
    int status=VM27LargePrivateServiceConsumerV2CheckMessage(consumer,value,&identity);
    const char *method=xpc_dictionary_get_string(value,"privateMethod");
    BOOL config=method && !strcmp(method,VM27_GPU_TASK_CONFIGURATION_V1);
    if (!status && config) {
        if (configured || xpc_dictionary_get_count(value)!=1) status=EPROTO;
    } else if (!status) {
        xpc_object_t endpoint=xpc_dictionary_get_value(value,"serviceEndpoint");
        const char *service=xpc_dictionary_get_string(value,"serviceIdentifier");
        xpc_object_t rawNonce=xpc_dictionary_get_value(value,"nonce");
        if (!configured || serviceEndpoint || !method || strcmp(method,VM27_GPU_TASK_ENDPOINT_V1) ||
            xpc_dictionary_get_count(value)!=4 || !service || strcmp(service,VM27_GPU_TASK_SERVICE_V1) ||
            !rawNonce || xpc_get_type(rawNonce)!=XPC_TYPE_UINT64 || xpc_uint64_get_value(rawNonce)!=nonce ||
            !endpoint || xpc_get_type(endpoint)!=XPC_TYPE_ENDPOINT) status=EPROTO;
        if (!status) serviceEndpoint=(xpc_endpoint_t)xpc_retain(endpoint);
    }
    xpc_object_t reply=xpc_dictionary_create_reply(value);
    if (!reply) status=status?status:ENOMEM;
    else {
        xpc_dictionary_set_string(reply,"privateMethod",config?VM27_GPU_TASK_CONFIGURATION_ACK_V1:VM27_GPU_TASK_ENDPOINT_ACK_V1);
        xpc_dictionary_set_uint64(reply,"nonce",status?0:nonce);xpc_dictionary_set_int64(reply,"status",status);
        xpc_connection_t remote=xpc_dictionary_get_remote_connection(value);
        if (remote) xpc_connection_send_message(remote,reply);else status=status?status:ENOTCONN;
        xpc_release(reply);
    }
    if (!status && config) configured=YES;
    else { [self signalReady:status];if (status) [self closeOnQueue]; }
}
- (int)start {
    startupStatus=EINPROGRESS;peerInvalid=YES;reaped=YES;processCanceled=YES;
    queue=dispatch_queue_create("VM27.owned.gpu.parent.v1",DISPATCH_QUEUE_SERIAL);ready=dispatch_semaphore_create(0);
    if (!queue || !ready) return ENOMEM;
    dispatch_queue_set_specific(queue,&VM27GPUControlQueueKeyV1,self,NULL);
    const VM27OwnedGPUTaskParentProfileV1 *p=&VM27OwnedGPUTaskPinnedParentProfileV1;
    xpc_object_t requirement=NULL;int status=VM27OwnedAppCreateScopedPluginRequirementV1(&requirement);
    if (!status) status=VM27LargeBundleRegistryCreate(p->canonicalRegistryRoot,&registry);
    if (!status) status=VM27LargeBundleRegistryRegister(registry,p->canonicalBundlePath,2,requirement);
    VM27LargeServicePlan *plan=NULL;VM27LargeServiceInfo info={0};
    if (!status) status=VM27LargeBundleRegistryCopyServicePlan(registry,VM27_GPU_TASK_SERVICE_V1,&plan);
    if (!status) status=VM27LargeServicePlanCopyInfo(plan,&info);
    if (!status && (strcmp(info.executablePath,p->canonicalExecutablePath) || strcmp(info.executableSHA256,p->signedExecutableSHA256) ||
        strcmp(info.executableUUID,p->executableUUID) || info.flags!=2)) status=EACCES;
    if (plan) VM27LargeServicePlanRelease(plan);
    if (!status) status=VM27OwnedBundlePrivateServiceConsumerCreateV5(registry,VM27_GPU_TASK_SERVICE_V1,
        p->signedExecutableSHA256,p->signedExecutableCDHash,requirement,&consumer);
    if (requirement) xpc_release(requirement);
    if (status) return status;
    do { arc4random_buf(&nonce,sizeof(nonce)); } while (!nonce);
    __block VM27OwnedGPUTaskParentV1 *unretained=self;
    [self retain];lifetimeHeld=YES;
    listener=xpc_connection_create(NULL,queue);if (!listener) { listenerInvalid=YES;[self finishSpawnDecision];[self close];return ENOMEM; }
    xpc_connection_set_event_handler(listener,^(xpc_object_t event) {@autoreleasepool {
        VM27OwnedGPUTaskParentV1 *o=unretained;
        if (event==XPC_ERROR_CONNECTION_INVALID) { o->listenerInvalid=YES;[o signalReady:ECONNRESET];[o closeOnQueue];[o finishIfDrained];return; }
        if (o->closing || o->peer || xpc_get_type(event)!=XPC_TYPE_CONNECTION) {
            if (xpc_get_type(event)==XPC_TYPE_CONNECTION) xpc_connection_cancel((xpc_connection_t)event);
            return;
        }
        o->peer=(xpc_connection_t)xpc_retain(event);o->peerInvalid=NO;
        xpc_connection_set_target_queue(o->peer,o->queue);
        xpc_connection_set_event_handler(o->peer,^(xpc_object_t message) {@autoreleasepool { [unretained event:message]; }});
        xpc_connection_activate(o->peer);
    }});
    bootstrapEndpoint=xpc_endpoint_create(listener);
    if (!bootstrapEndpoint) { xpc_connection_activate(listener);[self finishSpawnDecision];[self close];return ENOMEM; }
    xpc_connection_activate(listener);
    NSMutableDictionary *environment=[[[NSProcessInfo.processInfo environment] mutableCopy] autorelease];
    NSArray *keys=[[environment allKeys] copy];
    for (NSString *key in keys) if ([key hasPrefix:@"DYLD_"]) [environment removeObjectForKey:key];
    [keys release];
    environment[@VM27_GPU_TASK_ROLE_ENV_V1]=@VM27_GPU_TASK_SERVER_ROLE_V1;
    char **env=calloc(environment.count+1,sizeof(char *));
    if (!env) { [self finishSpawnDecision];[self close];return ENOMEM; }
    NSUInteger count=0;
    for (NSString *key in environment) {
        env[count]=strdup([[NSString stringWithFormat:@"%@=%@",key,environment[key]] UTF8String]);
        if (!env[count++]) { status=ENOMEM;break; }
    }
    char *arguments[]={(char *)p->canonicalExecutablePath,NULL};pid_t spawned=0;
    if (!status) status=VM27LargePrivateServiceConsumerV2Spawn(consumer,bootstrapEndpoint,arguments,env,&spawned);
    for (NSUInteger i=0;i<count;++i) free(env[i]);free(env);
    VM27LargePrivateConsumerV2State actual={0};int stateStatus=VM27LargePrivateServiceConsumerV2CopyState(consumer,&actual);
    dispatch_sync(queue,^{
        if (!stateStatus && actual.started) {
            unretained->childPID=actual.childPID;unretained->reaped=actual.reaped;
            unretained->process=dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC,(uintptr_t)actual.childPID,DISPATCH_PROC_EXIT,unretained->queue);
            if (unretained->process) {
                unretained->processCanceled=NO;
                dispatch_source_set_event_handler(unretained->process,^{@autoreleasepool {
                    [unretained reapOwnedChildWithBudget:0];
                }});
                dispatch_source_set_cancel_handler(unretained->process,^{@autoreleasepool {
                    dispatch_release(unretained->process);unretained->process=NULL;unretained->processCanceled=YES;[unretained finishIfDrained];
                }});dispatch_resume(unretained->process);
            }
        }
        unretained->spawnDecisionFinished=YES;
        [unretained finishIfDrained];
    });
    if (!status && stateStatus) status=stateStatus;
    __block BOOL watched=NO;dispatch_sync(queue,^{watched=unretained->process!=NULL;});
    if (!status && (!actual.started || !watched)) status=EIO;
    if (status) { [self close];return status; }
    if (dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,(VM27_GPU_TASK_CONFIGURATION_SECONDS_V1+VM27_GPU_TASK_ENDPOINT_SECONDS_V1)*NSEC_PER_SEC))) status=ETIMEDOUT;
    else status=startupStatus;
    if (status) [self close];
    dprintf(2,"[VM27OwnedGPUTaskParentV1] stage=bootstrap status=%d child=%d originalHandshakeNotClaimed=1\n",status,childPID);
    return status;
}
- (void)dealloc {
    if (consumer) VM27LargePrivateServiceConsumerV2Release(consumer);
    if (registry) VM27LargeBundleRegistryRelease(registry);
    if (serviceEndpoint) xpc_release(serviceEndpoint);
    if (bootstrapEndpoint) xpc_release(bootstrapEndpoint);
    if (peer) xpc_release(peer);if (listener) xpc_release(listener);
    if (ready) dispatch_release(ready);
    if (queue) { dispatch_queue_set_specific(queue,&VM27GPUControlQueueKeyV1,NULL,NULL);dispatch_release(queue); }
    [super dealloc];
}
@end

__attribute__((visibility("default"),ns_returns_retained))
id VM27OwnedGPUTaskConnectionInitV1(id allocated,SEL selector,NSString *service) {
    int incoming=errno;void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    if (!GPUParentAdmissionV1(allocated,selector,service,caller)) { errno=ENOTSUP;__builtin_trap(); }
    VM27OwnedGPUTaskParentV1 *owner=[[VM27OwnedGPUTaskParentV1 alloc] init];
    int status=ENOMEM;
    @try { if (owner) status=[owner start]; }
    @catch (id exception) { (void)exception;[owner finishSpawnDecision];[owner close];[owner release];[allocated release];@throw; }
    if (status) { [owner close];[owner release];[allocated release];errno=status;return nil; }
    __block xpc_endpoint_t actual=NULL;
    dispatch_sync(owner->queue,^{if (!owner->closing && owner->serviceEndpoint) actual=(xpc_endpoint_t)xpc_retain(owner->serviceEndpoint);});
    id endpoint=[(id)objc_getClass("NSXPCListenerEndpoint") new];id result=nil;
    @try {
        if (!actual || ![endpoint respondsToSelector:sel_registerName("_setEndpoint:")] ||
            ![endpoint respondsToSelector:sel_registerName("_endpoint")]) status=ENOTSUP;
        else {
            ((void(*)(id,SEL,xpc_endpoint_t))objc_msgSend)(endpoint,sel_registerName("_setEndpoint:"),actual);
            xpc_object_t readback=((xpc_object_t(*)(id,SEL))objc_msgSend)(endpoint,sel_registerName("_endpoint"));
            if (readback!=actual || xpc_get_type(readback)!=XPC_TYPE_ENDPOINT) status=EIO;
        }
        if (!status) {
            errno=incoming;
            result=((id(*)(id,SEL,id))objc_msgSend)(allocated,sel_registerName("initWithListenerEndpoint:"),endpoint);
            int nativeErrno=errno;allocated=nil;
            if (result) {
                VM27OwnedGPUTaskConnectionLeaseV1 *lease=[[VM27OwnedGPUTaskConnectionLeaseV1 alloc] init];
                if (lease) {
                    lease->owner=[owner retain];objc_setAssociatedObject(result,&VM27GPUConnectionLeaseKeyV1,lease,OBJC_ASSOCIATION_RETAIN_NONATOMIC);[lease release];
                } else { [result invalidate];[result release];result=nil;[owner close];nativeErrno=ENOMEM; }
            } else [owner close];
            errno=nativeErrno;
        } else { [allocated release];allocated=nil;[owner close];errno=status; }
    } @catch (id exception) { (void)exception;[owner close];@throw; }
    @finally { if (actual) xpc_release(actual);[endpoint release];[owner release]; }
    return result;
}
