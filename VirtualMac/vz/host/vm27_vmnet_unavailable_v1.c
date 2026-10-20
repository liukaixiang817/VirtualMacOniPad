#include "vm27_vmnet_unavailable_v1.h"
#include <errno.h>
#include <stddef.h>
_Static_assert(sizeof(vmnet_return_t)==4 && sizeof(vmnet_mode_t)==4 && sizeof(sa_family_t)==1 && sizeof(void *)==8,
    "Exact Darwin LP64 public vmnet ABI widths");
#define VM27_VMNET_FAILURE UINT32_C(1001)
static void Unavailable(vmnet_return_t *status) {
    if(status)*status=VM27_VMNET_FAILURE;
    errno=ENOTSUP;
}
xpc_object_t vmnet_copy_shared_interface_list(void) {
    // A real retained empty enumeration of interfaces offered by THIS private
    // disabled backend. It says nothing about physical iPad network interfaces.
    xpc_object_t array=xpc_array_create(NULL,0);
    if(!array)errno=ENOMEM;
    return array;
}
vmnet_network_configuration_ref vmnet_network_configuration_create(vmnet_mode_t mode,vmnet_return_t *status) {
    (void)mode;Unavailable(status);return NULL;
}
vmnet_network_ref vmnet_network_create(vmnet_network_configuration_ref config,vmnet_return_t *status) {
    (void)config;Unavailable(status);return NULL;
}
xpc_object_t vmnet_network_copy_serialization(vmnet_network_ref network,vmnet_return_t *status) {
    (void)network;Unavailable(status);return NULL;
}
vmnet_return_t vmnet_network_configuration_add_port_forwarding_rule(vmnet_network_configuration_ref config,
    uint8_t protocol,sa_family_t family,uint16_t internal_port,uint16_t external_port,const void *internal_address) {
    (void)config;(void)protocol;(void)family;(void)internal_port;(void)external_port;(void)internal_address;
    errno=ENOTSUP;return VM27_VMNET_FAILURE;
}
