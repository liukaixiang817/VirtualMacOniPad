#ifndef VM27_HOST_VSOCK_SSH_OWNER_V3_H
#define VM27_HOST_VSOCK_SSH_OWNER_V3_H
#include "vm27_host_vsock_ssh_owner_v1.h"
enum {VM27SSHLocalV3=0,VM27SSHLANV3=1,VM27SSHInternetV3=2};
enum {VM27SSHIPv4V3=1,VM27SSHIPv6V3=2};
/* Both requested families bind successfully or the creation fails. Scope LAN
 * admits local/private/link-local or directly attached subnet peers. Internet
 * binds available interfaces; upstream routing and firewalls still apply. */
int vm27_host_ssh_owner_v3_create(uint16_t port,unsigned scope,unsigned families,
    uint32_t idle_ms,struct vm27_host_ssh_owner_v1 **out);
#endif
