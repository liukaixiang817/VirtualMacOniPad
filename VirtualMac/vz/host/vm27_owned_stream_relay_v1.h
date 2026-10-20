#ifndef VM27_OWNED_STREAM_RELAY_V1_H
#define VM27_OWNED_STREAM_RELAY_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum vm27_stream_relay_v1_stop {
    VM27_STREAM_RELAY_V1_COMPLETE = 1,
    VM27_STREAM_RELAY_V1_CANCELLED = 2,
    VM27_STREAM_RELAY_V1_IDLE = 3,
    VM27_STREAM_RELAY_V1_ERROR = 4
};

struct vm27_stream_relay_v1_result {
    uint64_t bytes_left_to_right;
    uint64_t bytes_right_to_left;
    enum vm27_stream_relay_v1_stop stop;
    int error;
};

/* Worker-thread operation. The caller exclusively lends two distinct,
 * nonblocking SOCK_STREAM descriptors and a nonblocking pipe read descriptor.
 * Cancellation is one byte or EOF on that pipe. The caller retains ownership
 * and keeps all three descriptors alive until this function returns.
 *
 * Each direction has a 16 KiB buffer. EOF is forwarded with SHUT_WR only after
 * buffered bytes have been written, so the opposite direction can finish.
 * An idle timeout in 1..3600000 milliseconds bounds an inactive connection.
 * Return zero means both directions reached EOF and drained. Other returns
 * are errno values. Counts include only bytes actually written to each peer.
 * This function neither closes descriptors nor provides a network or VSOCK
 * connection; those connections must already be real caller-owned sockets.
 */
int vm27_owned_stream_relay_v1_run(
    int left_fd, int right_fd, int cancellation_read_fd,
    uint32_t idle_milliseconds, struct vm27_stream_relay_v1_result *result);

#ifdef __cplusplus
}
#endif
#endif
