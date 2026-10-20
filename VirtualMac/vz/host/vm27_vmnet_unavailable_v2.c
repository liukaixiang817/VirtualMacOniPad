#include "vm27_vmnet_unavailable_v2.h"
/* Preserve all five frozen V1 failure/enumeration contracts in one image. */
#include "vm27_vmnet_unavailable_v1.c"
_Static_assert(sizeof(interface_event_t)==4 && sizeof(struct vmpktdesc)==24 &&
    offsetof(struct vmpktdesc,vm_pkt_iov)==8 &&
    offsetof(struct vmpktdesc,vm_pkt_iovcnt)==16 &&
    offsetof(struct vmpktdesc,vm_flags)==20, "Darwin packet and callback ABI");
#define VM27_DEFINE_DISABLED_KEY(name) const char * const name="vm27-disabled:" #name;
VM27_DISABLED_VMNET_KEYS(VM27_DEFINE_DISABLED_KEY)
#undef VM27_DEFINE_DISABLED_KEY
static interface_ref RefuseStartV2(dispatch_queue_t queue,
    vmnet_start_interface_completion_handler_t handler) {
    errno=ENOTSUP;
    if(queue && handler)dispatch_async(queue, ^{handler(VM27_VMNET_FAILURE,NULL);});
    return NULL;
}
interface_ref vmnet_start_interface(xpc_object_t description,dispatch_queue_t queue,
    vmnet_start_interface_completion_handler_t handler) {
    (void)description;return RefuseStartV2(queue,handler);
}
interface_ref vmnet_interface_start_with_network(vmnet_network_ref network,
    xpc_object_t description,dispatch_queue_t queue,
    vmnet_start_interface_completion_handler_t handler) {
    (void)network;(void)description;return RefuseStartV2(queue,handler);
}
vmnet_network_ref vmnet_network_create_with_serialization(xpc_object_t serialized,
    vmnet_return_t *status) {
    (void)serialized;Unavailable(status);return NULL;
}
vmnet_return_t vmnet_interface_set_event_callback(interface_ref interface,
    interface_event_t mask,dispatch_queue_t queue,vmnet_interface_event_callback_t callback) {
    (void)interface;(void)mask;(void)queue;(void)callback;
    errno=ENOTSUP;return VM27_VMNET_FAILURE;
}
vmnet_return_t vmnet_read(interface_ref interface,struct vmpktdesc *packets,int *count) {
    (void)interface;(void)packets;(void)count;
    errno=ENOTSUP;return VM27_VMNET_FAILURE;
}
vmnet_return_t vmnet_write(interface_ref interface,struct vmpktdesc *packets,int *count) {
    (void)interface;(void)packets;(void)count;
    errno=ENOTSUP;return VM27_VMNET_FAILURE;
}
vmnet_return_t vmnet_stop_interface(interface_ref interface,dispatch_queue_t queue,
    vmnet_interface_completion_handler_t handler) {
    (void)interface;(void)queue;(void)handler;
    /* No interface was acquired and no completion was scheduled. */
    errno=ENOTSUP;return VM27_VMNET_FAILURE;
}
__attribute__((noreturn)) void vmnet_network_get_mode(vmnet_network_ref network) {
    (void)network;errno=ENOTSUP;__builtin_trap();
}
__attribute__((noreturn)) void vmnet_network_get_mtu(vmnet_network_ref network) {
    (void)network;errno=ENOTSUP;__builtin_trap();
}
