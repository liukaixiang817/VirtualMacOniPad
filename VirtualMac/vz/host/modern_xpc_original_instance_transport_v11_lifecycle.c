/* V10's peer authentication and wire protocol remain intact. The new original
 * event-handler import must be routed only in the owned VZ27 image. */
#include "modern_xpc_original_instance_transport_v10.h"
static void VM27ForwardNativeEventSetter(xpc_connection_t, xpc_handler_t);
/* V10 installs its own server handlers while holding Lock. Those calls must
 * bypass the observer, which takes that lock to identify the VZ client. */
#define xpc_connection_set_event_handler VM27ForwardNativeEventSetter
#include "modern_xpc_original_instance_transport_v10.c"
#undef xpc_connection_set_event_handler
#include "vm27_original_client_retire_v1.h"

typedef void (*VM27NativeEventSetterV1)(xpc_connection_t, xpc_handler_t);
static VM27NativeEventSetterV1 VM27NativeEventSetter;
static pthread_once_t VM27EventSetterOnce=PTHREAD_ONCE_INIT;
static VM27OriginalClientLifecycleV1 VM27ClientLifecycle;

static void VM27ResolveNativeEventSetter(void) {
    /* Public, typed libxpc API: resolve its actual system export rather than
     * introducing a new OS build UUID/RVA pin. Retain the cache handle. */
    const char *path="/usr/lib/system/libxpc.dylib";
    void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    void *symbol=handle?dlsym(handle,"xpc_connection_set_event_handler"):NULL;
    Dl_info info={0};
    if(symbol && dladdr(ptrauth_strip(symbol,ptrauth_key_function_pointer),&info) &&
       info.dli_fname && !strcmp(info.dli_fname,path))
        VM27NativeEventSetter=(VM27NativeEventSetterV1)symbol;
}

static void VM27ForwardNativeEventSetter(xpc_connection_t connection,xpc_handler_t handler) {
    pthread_once(&VM27EventSetterOnce,VM27ResolveNativeEventSetter);
    if(!VM27NativeEventSetter)abort();
    VM27NativeEventSetter(connection,handler);
}

void VM27OriginalClientSetEventHandlerV1(xpc_connection_t connection,xpc_handler_t handler)
    __asm__("_xpc_connection_set_event_handler");
void VM27OriginalClientSetEventHandlerV1(xpc_connection_t connection,xpc_handler_t handler) {
    pthread_once(&VM27EventSetterOnce,VM27ResolveNativeEventSetter);
    if(!VM27NativeEventSetter)abort();
    pthread_mutex_lock(&Lock);
    bool own=connection && connection==ClientConnection && ClientConnectionMade;
    uint64_t generation=ClientGeneration;
    if(own && handler) {
        if(VM27ClientLifecycle.generation!=generation)
            VM27ClientLifecycle=(VM27OriginalClientLifecycleV1){.generation=generation};
        VM27ClientLifecycle.handlerInstalled=true;
    }
    pthread_mutex_unlock(&Lock);
    if(!own || !handler){VM27NativeEventSetter(connection,handler);return;}
    /* This is C, not ARC: capturing the pointer does not retain the connection
     * inside its own handler. V10's existing factory owns it until retirement. */
    VM27NativeEventSetter(connection,^(xpc_object_t event){
        pthread_mutex_lock(&Lock);
        bool current=connection==ClientConnection && generation==ClientGeneration &&
            VM27ClientLifecycle.generation==generation;
        if(current)VM27ClientLifecycle.callbacks++;
        pthread_mutex_unlock(&Lock);
        handler(event);
        pthread_mutex_lock(&Lock);
        if(current && connection==ClientConnection && generation==ClientGeneration) {
            if(event==XPC_ERROR_CONNECTION_INVALID)VM27ClientLifecycle.finalInvalidObserved=true;
            if(!VM27ClientLifecycle.callbacks)abort();
            VM27ClientLifecycle.callbacks--;
        }
        pthread_mutex_unlock(&Lock);
    });
}

void VM27OriginalClientCopyLifecycleV1(VM27OriginalClientLifecycleV1 *out) {
    if(!out)return;
    pthread_mutex_lock(&Lock);*out=VM27ClientLifecycle;pthread_mutex_unlock(&Lock);
}

int VM27OriginalClientRetireAfterExitV1(VM27LargePrivateServiceConsumerV2 *consumer,uint64_t nonce) {
    if(!consumer || !nonce)return EINVAL;
    VM27LargePrivateConsumerV2State child={0};
    int status=VM27LargePrivateServiceConsumerV2CopyState(consumer,&child);
    if(status)return status;
    if(!child.reaped) {
        status=VM27LargePrivateServiceConsumerV2Wait(consumer,false,&child);
        if(status)return status;
    }
    if(!child.started || !child.reaped || !child.absent || child.childPID<=1)return EBUSY;
    pthread_mutex_lock(&Lock);
    if(ClientPID!=child.childPID || ClientNonce!=nonce || !ClientEndpoint)status=ESTALE;
    else if(ActiveServer || RegistrationProcessCommitted || ClientBinding || ClientRegistrationBinding ||
        Stats.pendingInstanceRequests || RegistrationStats.pendingClientRequests)status=EBUSY;
    else if(ClientConnectionMade &&
        (VM27ClientLifecycle.generation!=ClientGeneration || !VM27ClientLifecycle.handlerInstalled ||
         !VM27ClientLifecycle.finalInvalidObserved || VM27ClientLifecycle.callbacks))status=EAGAIN;
    xpc_endpoint_t endpoint=NULL;
    xpc_connection_t connection=NULL,control=NULL;
    if(!status) {
        endpoint=ClientEndpoint;connection=ClientConnection;control=ClientControl;
        ClientEndpoint=NULL;ClientConnection=ClientControl=NULL;
        ClientConnectionMade=ClientBinding=ClientInstanceReady=false;
        ClientRegistrationBinding=ClientRegistrationReady=false;
        ClientOneShotReservation=ClientRegistrationReservation=0;
        ClientNonce=0;ClientPID=0;
        memset(ClientCD,0,sizeof(ClientCD));memset(ClientInstance,0,sizeof(ClientInstance));
        memset(ClientRegisteredTitle,0,sizeof(ClientRegisteredTitle));
        ++ClientGeneration;
        VM27ClientLifecycle=(VM27OriginalClientLifecycleV1){0};
    }
    pthread_mutex_unlock(&Lock);
    if(endpoint)xpc_release(endpoint);
    if(connection)xpc_release(connection);
    if(control)xpc_release(control);
    return status;
}
