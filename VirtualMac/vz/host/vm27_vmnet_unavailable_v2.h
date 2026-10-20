#ifndef VM27_VMNET_UNAVAILABLE_V2_H
#define VM27_VMNET_UNAVAILABLE_V2_H
#include "vm27_vmnet_unavailable_v1.h"
#include <dispatch/dispatch.h>
#include <sys/uio.h>
typedef struct vmnet_interface *interface_ref;
typedef uint32_t interface_event_t;
struct vmpktdesc {
    size_t vm_pkt_size;
    struct iovec *vm_pkt_iov;
    uint32_t vm_pkt_iovcnt;
    uint32_t vm_flags;
};
typedef void (^vmnet_start_interface_completion_handler_t)(vmnet_return_t, xpc_object_t);
typedef void (^vmnet_interface_event_callback_t)(interface_event_t, xpc_object_t);
typedef void (^vmnet_interface_completion_handler_t)(vmnet_return_t);
#ifdef __cplusplus
extern "C" {
#endif
interface_ref vmnet_start_interface(xpc_object_t, dispatch_queue_t,
    vmnet_start_interface_completion_handler_t);
interface_ref vmnet_interface_start_with_network(vmnet_network_ref, xpc_object_t,
    dispatch_queue_t, vmnet_start_interface_completion_handler_t);
vmnet_network_ref vmnet_network_create_with_serialization(xpc_object_t, vmnet_return_t *);
vmnet_return_t vmnet_interface_set_event_callback(interface_ref, interface_event_t,
    dispatch_queue_t, vmnet_interface_event_callback_t);
vmnet_return_t vmnet_read(interface_ref, struct vmpktdesc *, int *);
vmnet_return_t vmnet_write(interface_ref, struct vmpktdesc *, int *);
vmnet_return_t vmnet_stop_interface(interface_ref, dispatch_queue_t,
    vmnet_interface_completion_handler_t);
/* Private property getters have no failure output. These unavailable entries
 * never return any property or fabricated network object. No return-value ABI
 * is claimed; the original caller receives a deliberate unsupported trap. */
__attribute__((noreturn)) void vmnet_network_get_mode(vmnet_network_ref);
__attribute__((noreturn)) void vmnet_network_get_mtu(vmnet_network_ref);
/* Const pointer ABI matches the SDK. Values identify only this disabled
 * provider's rejected dictionaries, not Apple's network service protocol. */
#define VM27_DISABLED_VMNET_KEYS(X) \
    X(vmnet_allocate_mac_address_key) \
    X(vmnet_audit_token_key) \
    X(vmnet_enable_checksum_offload_key) \
    X(vmnet_enable_isolation_key) \
    X(vmnet_enable_mac_nat_key) \
    X(vmnet_enable_tso_key) \
    X(vmnet_enable_virtio_header_key) \
    X(vmnet_estimated_packets_available_key) \
    X(vmnet_max_packet_size_key) \
    X(vmnet_mtu_key) \
    X(vmnet_operation_mode_key) \
    X(vmnet_shared_interface_name_key)
#define VM27_DECLARE_DISABLED_KEY(name) extern const char * const name;
VM27_DISABLED_VMNET_KEYS(VM27_DECLARE_DISABLED_KEY)
#undef VM27_DECLARE_DISABLED_KEY
#ifdef __cplusplus
}
#endif
#endif
