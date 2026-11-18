#ifndef VM27_NATIVE_NETWORK_V1_H
#define VM27_NATIVE_NETWORK_V1_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct VM27NativeNetworkV1 VM27NativeNetworkV1;
/* Success transfers one connected SOCK_DGRAM descriptor to the caller.
 * It is the actual native Virtualization file-handle attachment endpoint.
 * All slirp operations execute on one private worker. Initialization is
 * asynchronous; a created thread is not a claim of working guest networking. */
int VM27NativeNetworkStartV1(VM27NativeNetworkV1 **owner, int *guestDescriptor);
/* Development guest only: one fixed guest TCP port maps to the owned local
 * Bluetooth Unix socket. No host TCP listener or general loopback access. */
int VM27NativeNetworkStartForRadioDevV1(VM27NativeNetworkV1 **owner, int *guestDescriptor);
/* New-VM radio endpoints use only the App's owned private Unix sockets. */
int VM27NativeNetworkStartWithSharedRadiosV1(VM27NativeNetworkV1 **owner, int *guestDescriptor);
/* A separate 10.0.3.0/24 NAT for the shared Wi-Fi interface. It does not
 * expose the Bluetooth port or change the existing VM Ethernet network. */
int VM27NativeNetworkStartSharedWiFiV1(VM27NativeNetworkV1 **owner, int *guestDescriptor);
/* Consume the caller's owner reference once. Cancellation does not wait on
 * the UIKit thread; the worker drains and frees its own sockets and timers. */
void VM27NativeNetworkStopV1(VM27NativeNetworkV1 *owner);
#ifdef __cplusplus
}
#endif
#endif
