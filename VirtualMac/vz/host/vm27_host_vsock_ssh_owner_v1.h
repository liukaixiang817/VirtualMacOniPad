#ifndef VM27_HOST_VSOCK_SSH_OWNER_V1_H
#define VM27_HOST_VSOCK_SSH_OWNER_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct vm27_host_ssh_owner_v1;
struct vm27_host_ssh_snapshot_v1 {
    uint64_t control_generation, last_sequence, streams_started, streams_completed;
    uint64_t rejected_connections, setup_errors, bytes_tcp_to_guest, bytes_guest_to_tcp;
    uint32_t pending, active;
    int ready, stopped, error;
    uint16_t tcp_port;
};
/* Callback follows closing the transferred descriptor and joining any borrower.
 * It executes on the owner thread, never under its mutex. It must not block.
 * A genuine VZ adapter schedules connection.close/release on actual VM.queue.
 */
typedef void (*vm27_host_ssh_release_v1)(void *context);
/* Owns an actual loopback TCP listener and worker. Port0 requests an actual
 * ephemeral loopback port; the App adapter always requests exactly22222.
 * No SSH protocol or permission is synthesized; it only relays real bytes.
 */
int vm27_host_ssh_owner_v1_create(uint16_t tcp_port, uint32_t idle_ms,
                                struct vm27_host_ssh_owner_v1 **out);
/* Transfers a distinct owned SOCK_STREAM FD only on success. Caller supplies
 * a dup of the genuine VZ connection FD and retains that connection until the
 * release callback. Admission is bounded; header parsing happens off VM.queue.
 */
int vm27_host_ssh_owner_v1_admit(struct vm27_host_ssh_owner_v1 *owner, int owned_fd,
                               vm27_host_ssh_release_v1 release, void *context);
int vm27_host_ssh_owner_v1_snapshot(struct vm27_host_ssh_owner_v1 *owner,
                                  struct vm27_host_ssh_snapshot_v1 *out);
void vm27_host_ssh_owner_v1_cancel(struct vm27_host_ssh_owner_v1 *owner);
/* Cancel+join+close all owned descriptors before freeing. Never call from a
 * release callback or the VM control queue: use an independent close worker.
 */
void vm27_host_ssh_owner_v1_destroy(struct vm27_host_ssh_owner_v1 *owner);
#ifdef __cplusplus
}
#endif
#endif
