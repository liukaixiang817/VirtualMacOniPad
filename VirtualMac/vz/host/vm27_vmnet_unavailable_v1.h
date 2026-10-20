#ifndef VM27_VMNET_UNAVAILABLE_V1_H
#define VM27_VMNET_UNAVAILABLE_V1_H
#include <stdint.h>
#include <sys/socket.h>
#include <xpc/xpc.h>
// Exact SDK widths and opaque references. This private backend deliberately
// has no network service; its diagnostic VM configuration requires zero NICs.
typedef uint32_t vmnet_return_t;
typedef uint32_t vmnet_mode_t;
typedef struct vmnet_network *vmnet_network_ref;
typedef struct vmnet_network_configuration *vmnet_network_configuration_ref;
#ifdef __cplusplus
extern "C" {
#endif
xpc_object_t vmnet_copy_shared_interface_list(void);
vmnet_network_configuration_ref vmnet_network_configuration_create(vmnet_mode_t mode, vmnet_return_t *status);
vmnet_network_ref vmnet_network_create(vmnet_network_configuration_ref config, vmnet_return_t *status);
xpc_object_t vmnet_network_copy_serialization(vmnet_network_ref network, vmnet_return_t *status);
vmnet_return_t vmnet_network_configuration_add_port_forwarding_rule(vmnet_network_configuration_ref config,
    uint8_t protocol, sa_family_t family, uint16_t internal_port, uint16_t external_port, const void *internal_address);
#ifdef __cplusplus
}
#endif
#endif
