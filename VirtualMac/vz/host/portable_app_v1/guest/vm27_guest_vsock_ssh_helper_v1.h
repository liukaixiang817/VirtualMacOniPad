#ifndef VM27_GUEST_VSOCK_SSH_HELPER_V1_H
#define VM27_GUEST_VSOCK_SSH_HELPER_V1_H
#include <stdint.h>
#define VM27_SSH_VSOCK_PROTOCOL_VERSION 1u
#define VM27_SSH_VSOCK_HOST_PORT 22223u
#define VM27_SSH_VSOCK_MAX_SESSIONS 16u
#define VM27_SSH_VSOCK_HEADER_BYTES 32u
#define VM27_SSH_VSOCK_CONNECT_MS 5000u
#define VM27_SSH_VSOCK_TYPE_HELLO 1u
#define VM27_SSH_VSOCK_TYPE_START 2u
#define VM27_SSH_VSOCK_TYPE_DATA 3u
#define VM27_SSH_VSOCK_TYPE_ERROR 4u
/* Wire bytes: 0..7 ASCII VM27SSH1; 8..9 BE16 version1; 10..11 BE16 type;
 * 12..15 BE32 errno (only ERROR); 16..31 token. HELLO token is all zero.
 * START/DATA/ERROR token = nonzero host control nonce(8 bytes), followed by
 * strictly increasing nonzero BE64 sequence. Tokens correlate streams;
 * they never grant permissions. A fresh nonce is mandatory per control.
 * START sequence must increase even when setup fails or the 16 slots are full.
 * Every accepted START creates at most one guest-initiated DATA connection.
 */
#ifdef __cplusplus
extern "C" {
#endif
void vm27_ssh_vsock_header_v1(uint8_t out[32], uint16_t type,
                            uint32_t error, const uint8_t token[16]);
int vm27_ssh_vsock_parse_v1(const uint8_t in[32], uint16_t *type,
                          uint32_t *error, uint8_t token[16]);
/* Guest process worker. Exclusively borrows a nonblocking pipe read FD.
 * One byte or EOF cancels control and all actual owned stream workers.
 * Connects only CID_HOST2:22223 and local TCP127.0.0.1:22, never listens.
 * Caller keeps cancellation FD alive until return. Owned sockets/threads
 * are drained and closed before return. idle_ms range1..3600000.
 * HELLO follows a real local TCP22 preflight and real control connection;
 * it does not prove SSH authentication, QGA installation or TCP22222 route.
 */
int vm27_guest_vsock_ssh_helper_v1_run(int cancellation_read_fd,
                                     uint32_t idle_ms);
#ifdef __cplusplus
}
#endif
#endif
