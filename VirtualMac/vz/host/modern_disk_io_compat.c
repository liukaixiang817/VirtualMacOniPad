#include "modern_disk_io_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct request {
    enum VM27DiskIOOperation operation;
    uint64_t cookie, offset;
    void *buffer;
    size_t bytes;
};
struct VM27DiskIO {
    pthread_mutex_t mutex;
    pthread_cond_t work, changed;
    pthread_t thread;
    int fd, paused, closing, closed, closeError;
    uint32_t capacity, queueHead, queueCount, completionHead, completionCount, running;
    uint64_t submitted, completed, consumed, cancelled, bytesRead, bytesWritten;
    struct request *queue;
    VM27DiskIOCompletion *completions;
};

static void publish(VM27DiskIO *io, const struct request *request, int32_t result, uint32_t flags) {
    /* outstanding <= capacity reserves a completion slot for every request. */
    uint32_t slot = (io->completionHead + io->completionCount) % io->capacity;
    io->completions[slot] = (VM27DiskIOCompletion){request->cookie, result, flags | VM27DiskCompletionPresent};
    io->completionCount++;
    io->completed++;
    if (flags & VM27DiskCompletionCancelled) io->cancelled++;
    if (result > 0 && request->operation == VM27DiskRead) io->bytesRead += (uint32_t)result;
    if (result > 0 && request->operation == VM27DiskWrite) io->bytesWritten += (uint32_t)result;
    pthread_cond_broadcast(&io->changed);
}

static int32_t perform(int fd, const struct request *request) {
    ssize_t result;
    do {
        if (request->operation == VM27DiskFlush) result = fsync(fd);
        else if (request->operation == VM27DiskRead)
            result = pread(fd, request->buffer, request->bytes, (off_t)request->offset);
        else result = pwrite(fd, request->buffer, request->bytes, (off_t)request->offset);
    } while (result < 0 && errno == EINTR);
    return result < 0 ? -errno : (int32_t)result;
}

static void *worker(void *context) {
    VM27DiskIO *io = context;
    pthread_mutex_lock(&io->mutex);
    for (;;) {
        while (!io->closing && (io->paused || !io->queueCount)) pthread_cond_wait(&io->work, &io->mutex);
        if (io->closing) break;
        struct request request = io->queue[io->queueHead];
        io->queueHead = (io->queueHead + 1) % io->capacity;
        io->queueCount--;
        io->running = 1;
        int fd = io->fd;
        pthread_mutex_unlock(&io->mutex);
        int32_t result = perform(fd, &request);
        pthread_mutex_lock(&io->mutex);
        io->running = 0;
        publish(io, &request, result, 0);
    }
    pthread_cond_broadcast(&io->changed);
    pthread_mutex_unlock(&io->mutex);
    return NULL;
}

int VM27DiskIOCreate(int fd, uint32_t capacity, VM27DiskIO **out) {
    if (!out) return EINVAL;
    *out = NULL;
    if (fd < 0 || capacity < 1 || capacity > 256) return EINVAL;
    struct stat file;
    if (fstat(fd, &file)) return errno;
    if (!S_ISREG(file.st_mode)) return EINVAL;
    VM27DiskIO *io = calloc(1, sizeof(*io));
    if (!io) return ENOMEM;
    io->fd = -1;
    io->capacity = capacity;
    io->queue = calloc(capacity, sizeof(*io->queue));
    io->completions = calloc(capacity, sizeof(*io->completions));
    if (!io->queue || !io->completions) { free(io->queue); free(io->completions); free(io); return ENOMEM; }
    int error = pthread_mutex_init(&io->mutex, NULL);
    if (error) goto allocation_failure;
    error = pthread_cond_init(&io->work, NULL);
    if (error) goto mutex_failure;
    error = pthread_cond_init(&io->changed, NULL);
    if (error) goto work_failure;
    io->fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (io->fd < 0) { error = errno; goto changed_failure; }
    error = pthread_create(&io->thread, NULL, worker, io);
    if (error) { close(io->fd); goto changed_failure; }
    *out = io;
    return 0;
changed_failure:
    pthread_cond_destroy(&io->changed);
work_failure:
    pthread_cond_destroy(&io->work);
mutex_failure:
    pthread_mutex_destroy(&io->mutex);
allocation_failure:
    free(io->queue); free(io->completions); free(io);
    return error;
}

int VM27DiskIOSubmit(VM27DiskIO *io, enum VM27DiskIOOperation operation,
                     uint64_t cookie, uint64_t offset, void *buffer, size_t bytes) {
    if (!io || operation < VM27DiskRead || operation > VM27DiskFlush) return EINVAL;
    if (operation == VM27DiskFlush) { if (buffer || bytes || offset) return EINVAL; }
    else if ((!buffer && bytes) || bytes > INT32_MAX || offset > INT64_MAX || bytes > (uint64_t)INT64_MAX - offset) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    int error = 0;
    if (io->closing || io->closed) error = EBADF;
    else if (io->queueCount + io->running + io->completionCount == io->capacity) error = EAGAIN;
    else {
        uint32_t slot = (io->queueHead + io->queueCount) % io->capacity;
        io->queue[slot] = (struct request){operation, cookie, offset, buffer, bytes};
        io->queueCount++;
        io->submitted++;
        pthread_cond_signal(&io->work);
    }
    pthread_mutex_unlock(&io->mutex);
    return error;
}

int VM27DiskIOGetCompletion(VM27DiskIO *io, VM27DiskIOCompletion *out, int timeoutMS) {
    if (!io || !out || timeoutMS < -1) return EINVAL;
    struct timespec deadline = {0};
    if (timeoutMS > 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &deadline)) return errno;
        deadline.tv_sec += timeoutMS / 1000;
        deadline.tv_nsec += (long)(timeoutMS % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    }
    *out = (VM27DiskIOCompletion){0};
    pthread_mutex_lock(&io->mutex);
    int error = 0;
    while (!io->completionCount) {
        if (!timeoutMS) { error = ENODATA; break; }
        if (io->closed) { error = ENODATA; break; }
        if (timeoutMS < 0) error = pthread_cond_wait(&io->changed, &io->mutex);
        else {
            struct timespec now, remaining;
            if (clock_gettime(CLOCK_MONOTONIC, &now)) { error = errno; break; }
            remaining.tv_sec = deadline.tv_sec - now.tv_sec;
            remaining.tv_nsec = deadline.tv_nsec - now.tv_nsec;
            if (remaining.tv_nsec < 0) { remaining.tv_sec--; remaining.tv_nsec += 1000000000L; }
            if (remaining.tv_sec < 0 || (!remaining.tv_sec && !remaining.tv_nsec)) { error = ETIMEDOUT; break; }
            error = pthread_cond_timedwait_relative_np(&io->changed, &io->mutex, &remaining);
        }
        if (error) break;
    }
    if (!error) {
        *out = io->completions[io->completionHead];
        io->completionHead = (io->completionHead + 1) % io->capacity;
        io->completionCount--;
        io->consumed++;
    }
    pthread_mutex_unlock(&io->mutex);
    return error;
}

int VM27DiskIOSuspend(VM27DiskIO *io) {
    if (!io) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    int error = (io->closing || io->closed) ? EBADF : 0;
    if (!error) {
        io->paused = 1;
        while (io->running) pthread_cond_wait(&io->changed, &io->mutex);
    }
    pthread_mutex_unlock(&io->mutex);
    return error;
}

int VM27DiskIOResume(VM27DiskIO *io) {
    if (!io) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    int error = (io->closing || io->closed) ? EBADF : 0;
    if (!error) { io->paused = 0; pthread_cond_signal(&io->work); }
    pthread_mutex_unlock(&io->mutex);
    return error;
}

static uint32_t cancel_pending(VM27DiskIO *io) {
    uint32_t count = io->queueCount;
    while (io->queueCount) {
        struct request request = io->queue[io->queueHead];
        io->queueHead = (io->queueHead + 1) % io->capacity;
        io->queueCount--;
        publish(io, &request, -ECANCELED, VM27DiskCompletionCancelled);
    }
    return count;
}

int VM27DiskIOCancel(VM27DiskIO *io, uint32_t *cancelled) {
    if (!io || !cancelled) return EINVAL;
    *cancelled = 0;
    pthread_mutex_lock(&io->mutex);
    int error = (io->closing || io->closed) ? EBADF : (!io->paused ? EBUSY : 0);
    if (!error) *cancelled = cancel_pending(io);
    pthread_mutex_unlock(&io->mutex);
    return error;
}

int VM27DiskIOClose(VM27DiskIO *io) {
    if (!io) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    if (io->closed) { pthread_mutex_unlock(&io->mutex); return 0; }
    if (io->closing) {
        while (!io->closed && !io->closeError) pthread_cond_wait(&io->changed, &io->mutex);
        int error = io->closeError;
        pthread_mutex_unlock(&io->mutex);
        return error;
    }
    io->closing = 1;
    /* Finish the running operation first, preserving completion order. */
    while (io->running) pthread_cond_wait(&io->changed, &io->mutex);
    cancel_pending(io);
    pthread_cond_signal(&io->work);
    pthread_mutex_unlock(&io->mutex);
    int error = pthread_join(io->thread, NULL);
    if (error) {
        /* Preserve resources and report the join failure to every waiter. */
        pthread_mutex_lock(&io->mutex);
        io->closeError = error;
        pthread_cond_broadcast(&io->changed);
        pthread_mutex_unlock(&io->mutex);
        return error;
    }
    /* Never retry close(EINTR): the descriptor may already have been released. */
    if (close(io->fd) && errno != EINTR) error = errno;
    pthread_mutex_lock(&io->mutex);
    io->fd = -1;
    io->closed = 1;
    pthread_cond_broadcast(&io->changed);
    pthread_mutex_unlock(&io->mutex);
    return error;
}

int VM27DiskIODestroy(VM27DiskIO *io) {
    if (!io) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    int busy = !io->closed || io->completionCount || io->running || io->queueCount;
    pthread_mutex_unlock(&io->mutex);
    if (busy) return EBUSY;
    pthread_cond_destroy(&io->changed);
    pthread_cond_destroy(&io->work);
    pthread_mutex_destroy(&io->mutex);
    free(io->completions); free(io->queue); free(io);
    return 0;
}

int VM27DiskIOGetStats(VM27DiskIO *io, VM27DiskIOStats *out) {
    if (!io || !out) return EINVAL;
    pthread_mutex_lock(&io->mutex);
    *out = (VM27DiskIOStats){io->submitted, io->completed, io->consumed, io->cancelled,
        io->bytesRead, io->bytesWritten, io->queueCount, io->running,
        io->queueCount + io->running + io->completionCount, io->capacity, io->paused, io->closed};
    pthread_mutex_unlock(&io->mutex);
    return 0;
}
