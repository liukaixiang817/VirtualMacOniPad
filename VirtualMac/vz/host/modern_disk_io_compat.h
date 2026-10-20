#ifndef VM27_DISK_IO_COMPAT_H
#define VM27_DISK_IO_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Application-private POSIX transport. This is not Apple's io_rings ABI.
 * The caller keeps each buffer alive until its completion has been consumed.
 * Calls may come from different threads, except destroy requires exclusive use.
 */
typedef struct VM27DiskIO VM27DiskIO;
enum VM27DiskIOOperation { VM27DiskRead = 1, VM27DiskWrite = 2, VM27DiskFlush = 3 };
enum VM27DiskIOCompletionFlag { VM27DiskCompletionPresent = 1, VM27DiskCompletionCancelled = 2 };
typedef struct {
    uint64_t cookie;
    int32_t result; /* Actual bytes transferred, or negative errno. */
    uint32_t flags;
} VM27DiskIOCompletion;
typedef struct {
    uint64_t submitted, completed, consumed, cancelled;
    uint64_t bytesRead, bytesWritten;
    uint32_t queued, running, outstanding, capacity;
    int paused, closed;
} VM27DiskIOStats;

/* Return positive errno on failure; never silently select another transport. */
int VM27DiskIOCreate(int fd, uint32_t capacity, VM27DiskIO **out);
int VM27DiskIOSubmit(VM27DiskIO *io, enum VM27DiskIOOperation operation,
                     uint64_t cookie, uint64_t offset, void *buffer, size_t bytes);
/* timeoutMS=0 polls, -1 waits without a deadline, positive values are bounded. */
int VM27DiskIOGetCompletion(VM27DiskIO *io, VM27DiskIOCompletion *out, int timeoutMS);
/* Suspend waits for the running request; submissions may queue while paused. */
int VM27DiskIOSuspend(VM27DiskIO *io);
int VM27DiskIOResume(VM27DiskIO *io);
/* Cancel requires suspend, publishes ECANCELED for every pending cookie. */
int VM27DiskIOCancel(VM27DiskIO *io, uint32_t *cancelled);
/* Close cancels pending work, joins the worker and closes its duplicated fd.
 * Completions remain readable. Destroy returns EBUSY until they are consumed.
 * A failed worker join preserves the handle and fd; no cleanup is claimed. */
int VM27DiskIOClose(VM27DiskIO *io);
int VM27DiskIODestroy(VM27DiskIO *io);
int VM27DiskIOGetStats(VM27DiskIO *io, VM27DiskIOStats *out);

#ifdef __cplusplus
}
#endif
#endif
