#ifndef VM27_MODERN_XPC_PRIVATE_ENDPOINT_H
#define VM27_MODERN_XPC_PRIVATE_ENDPOINT_H
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>
#include <xpc/xpc.h>
typedef struct {
    char providerUUID[33];
    uint64_t endpointCreateRVA;
    bool exactHostABI;
} VM27PrivateEndpointABI;
/* These only accept the two pinned libxpc versions explicitly tested for the
 * owned endpoint+0x18 shape. No system objects, task ports or special ports. */
int VM27PrivateEndpointCopyABI(VM27PrivateEndpointABI *result);
/* Returns one additional owned send reference; caller must deallocate it. */
int VM27PrivateEndpointCopySendRight(xpc_endpoint_t ownEndpoint,
                                    mach_port_t *ownedSendRight);
/* Borrows a real send reference, constructs only its own endpoint shape,
 * transfers one copied reference to that shape, and releases the old shape
 * port. Returned connection is caller-owned and initially suspended. */
int VM27PrivateEndpointConnectSendRight(mach_port_t borrowedSendRight,
                                       dispatch_queue_t queue,
                                       xpc_connection_t *ownedConnection);
#endif
