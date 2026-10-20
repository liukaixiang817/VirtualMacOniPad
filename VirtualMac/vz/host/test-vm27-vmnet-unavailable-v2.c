#include "vm27_vmnet_unavailable_v2.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/resource.h>
#include <unistd.h>
static _Atomic unsigned checks;
static const char QueueKey;
static void Check(int value){atomic_fetch_add_explicit(&checks,1,memory_order_relaxed);if(!value)abort();}
int main(void) {
    struct rlimit cpu={5,6},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_CORE,&core))return 2;
    alarm(10);
    dispatch_queue_t queue=dispatch_queue_create("vm27.disabled-network.contract",NULL);
    dispatch_queue_set_specific(queue,&QueueKey,(void *)&QueueKey,NULL);
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    __block unsigned callbacks=0;
    vmnet_start_interface_completion_handler_t handler=^(vmnet_return_t status,xpc_object_t data) {
        Check(dispatch_get_specific(&QueueKey)==&QueueKey);
        Check(status==1001 && data==NULL);++callbacks;dispatch_semaphore_signal(done);
    };
    Check(vmnet_start_interface((xpc_object_t)(uintptr_t)1,queue,handler)==NULL);
    Check(errno==ENOTSUP);
    Check(vmnet_interface_start_with_network((vmnet_network_ref)(uintptr_t)1,
        (xpc_object_t)(uintptr_t)1,queue,handler)==NULL);Check(errno==ENOTSUP);
    for(unsigned i=0;i<2;i++)Check(!dispatch_semaphore_wait(done,
        dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)));
    dispatch_sync(queue,^{Check(callbacks==2);});
    Check(vmnet_start_interface(NULL,NULL,handler)==NULL);
    dispatch_sync(queue,^{Check(callbacks==2);});
    struct {uint32_t before,status,after;} result={0x12345678,0xabcdefab,0x87654321};
    Check(vmnet_network_create_with_serialization((xpc_object_t)(uintptr_t)1,&result.status)==NULL);
    Check(result.status==1001 && result.before==0x12345678 && result.after==0x87654321);
    Check(vmnet_network_create_with_serialization(NULL,NULL)==NULL);
    unsigned char bytes[32];memset(bytes,0xa5,sizeof(bytes));
    struct iovec vector={bytes,sizeof(bytes)};struct vmpktdesc packet={sizeof(bytes),&vector,1,77};
    struct vmpktdesc saved=packet;int count=3;
    Check(vmnet_read((interface_ref)(uintptr_t)1,&packet,&count)==1001);
    Check(count==3 && !memcmp(&packet,&saved,sizeof(packet)));
    Check(vmnet_write((interface_ref)(uintptr_t)1,&packet,&count)==1001);
    Check(count==3 && !memcmp(&packet,&saved,sizeof(packet)));
    for(unsigned i=0;i<sizeof(bytes);i++)Check(bytes[i]==0xa5);
    Check(vmnet_read(NULL,NULL,NULL)==1001);Check(vmnet_write(NULL,NULL,NULL)==1001);
    Check(vmnet_interface_set_event_callback(NULL,UINT32_MAX,queue,
        ^(interface_event_t mask,xpc_object_t data){(void)mask;(void)data;abort();})==1001);
    Check(vmnet_stop_interface(NULL,queue,^(vmnet_return_t status){(void)status;abort();})==1001);
    dispatch_sync(queue,^{Check(callbacks==2);});
#define VM27_KEY_VALUE(name) name,
    const char *keys[]={VM27_DISABLED_VMNET_KEYS(VM27_KEY_VALUE)};
#undef VM27_KEY_VALUE
    for(unsigned i=0;i<12;i++) {
        Check(keys[i] && !strncmp(keys[i],"vm27-disabled:",14));
        for(unsigned j=0;j<i;j++)Check(strcmp(keys[i],keys[j])!=0);
    }
    dispatch_release(done);dispatch_release(queue);
    printf("{\"checks\":%u,\"actualFailureCallbacks\":%u,\"callbacksUsedRequestedQueue\":true,"
        "\"failedIOPreservedBuffers\":true,\"networkOperations\":0,\"deviceOperations\":0,\"guestBoot\":false}\n",
        atomic_load_explicit(&checks,memory_order_relaxed),callbacks);
    return 0;
}
