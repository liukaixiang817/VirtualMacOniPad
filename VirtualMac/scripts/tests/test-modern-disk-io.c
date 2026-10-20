#include "modern_disk_io_compat.h"
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static unsigned checks, failures;
#define CHECK(expression) do { checks++; if (!(expression)) { failures++; fprintf(stderr, "failed:%d:%s\n", __LINE__, #expression); } } while (0)
static VM27DiskIOCompletion completion(VM27DiskIO *io, uint64_t cookie, int32_t result, uint32_t flags) {
    VM27DiskIOCompletion value;
    int error = VM27DiskIOGetCompletion(io, &value, 2000);
    CHECK(error == 0);
    if (error) return (VM27DiskIOCompletion){0};
    CHECK(value.cookie == cookie);
    CHECK(value.result == result);
    CHECK(value.flags == flags);
    return value;
}

struct producer {
    VM27DiskIO *io;
    unsigned first;
    unsigned char (*buffers)[32];
    atomic_int *failure;
};
static void *submit_concurrent(void *context) {
    struct producer *producer = context;
    for (unsigned i = producer->first; i < producer->first + 128; i++) {
        int error;
        do {
            error = VM27DiskIOSubmit(producer->io, VM27DiskWrite, 1000 + i,
                (uint64_t)i * 32, producer->buffers[i], 32);
            if (error == EAGAIN) sched_yield();
        } while (error == EAGAIN);
        if (error) { atomic_store(producer->failure, error); break; }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct timeval begin, end;
    gettimeofday(&begin, NULL);
    unsigned forbiddenImages = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "Virtualization.framework") || strstr(name, "Hypervisor.framework") ||
            strstr(name, "ParavirtualizedGraphics.framework") || strstr(name, "VirtualMachine.xpc"))) forbiddenImages++;
    }
    CHECK(forbiddenImages == 0);
    Dl_info provider = {0};
    CHECK(dladdr((void *)VM27DiskIOCreate, &provider) != 0 && provider.dli_fname != NULL);
    CHECK(provider.dli_fname && strstr(provider.dli_fname, "VM27DiskIO-") != NULL);
    char *path = argv[1];
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { perror("create diagnostic-owned file"); return 74; }
    unsigned char writeBuffer[4096], readBuffer[4096], fileBuffer[4096];
    for (size_t i = 0; i < sizeof(writeBuffer); i++) writeBuffer[i] = (unsigned char)((i * 37 + 19) & 255);
    VM27DiskIO *io = NULL, *invalid = (VM27DiskIO *)1;
    CHECK(VM27DiskIOCreate(fd, 0, &invalid) == EINVAL && invalid == NULL);
    CHECK(VM27DiskIOCreate(fd, 257, &invalid) == EINVAL && invalid == NULL);
    CHECK(VM27DiskIOCreate(-1, 16, &invalid) == EINVAL && invalid == NULL);
    CHECK(VM27DiskIOCreate(fd, 16, &io) == 0 && io != NULL);
    if (!io) { close(fd); unlink(path); return 1; }
    CHECK(VM27DiskIODestroy(io) == EBUSY);
    CHECK(VM27DiskIOSubmit(io, 0, 1, 0, writeBuffer, 1) == EINVAL);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 1, UINT64_MAX, readBuffer, 1) == EINVAL);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 1, INT64_MAX, readBuffer, 1) == EINVAL);
    CHECK(VM27DiskIOSubmit(io, VM27DiskWrite, 1, 0, NULL, 1) == EINVAL);
    CHECK(VM27DiskIOSubmit(io, VM27DiskFlush, 1, 0, writeBuffer, 0) == EINVAL);
    CHECK(VM27DiskIOCancel(io, &(uint32_t){0}) == EBUSY);

    /* FIFO write/flush/read verifies persisted data through a separate fd. */
    for (uint64_t cycle = 0; cycle < 32; cycle++) {
        memset(readBuffer, 0, sizeof(readBuffer));
        uint64_t offset = cycle * sizeof(writeBuffer);
        CHECK(VM27DiskIOSubmit(io, VM27DiskWrite, cycle * 3, offset, writeBuffer, sizeof(writeBuffer)) == 0);
        CHECK(VM27DiskIOSubmit(io, VM27DiskFlush, cycle * 3 + 1, 0, NULL, 0) == 0);
        CHECK(VM27DiskIOSubmit(io, VM27DiskRead, cycle * 3 + 2, offset, readBuffer, sizeof(readBuffer)) == 0);
        completion(io, cycle * 3, sizeof(writeBuffer), VM27DiskCompletionPresent);
        completion(io, cycle * 3 + 1, 0, VM27DiskCompletionPresent);
        completion(io, cycle * 3 + 2, sizeof(readBuffer), VM27DiskCompletionPresent);
        CHECK(memcmp(writeBuffer, readBuffer, sizeof(readBuffer)) == 0);
    }
    CHECK(pread(fd, fileBuffer, sizeof(fileBuffer), 31 * sizeof(fileBuffer)) == sizeof(fileBuffer));
    CHECK(memcmp(writeBuffer, fileBuffer, sizeof(fileBuffer)) == 0);
    VM27DiskIOCompletion empty;
    CHECK(VM27DiskIOGetCompletion(io, &empty, 0) == ENODATA && empty.flags == 0);
    CHECK(VM27DiskIOGetCompletion(io, &empty, 5) == ETIMEDOUT && empty.flags == 0);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 200, 1024 * 1024, readBuffer, sizeof(readBuffer)) == 0);
    completion(io, 200, 0, VM27DiskCompletionPresent); /* True EOF. */

    /* An unconsumed completion also occupies capacity; no CQ overruns. */
    CHECK(VM27DiskIOSuspend(io) == 0);
    for (uint64_t i = 0; i < 16; i++) CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 300 + i, 0, readBuffer, 0) == 0);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 399, 0, readBuffer, 0) == EAGAIN);
    VM27DiskIOStats stats;
    CHECK(VM27DiskIOGetStats(io, &stats) == 0 && stats.queued == 16 && stats.running == 0 && stats.outstanding == 16);
    uint32_t cancelled = 0;
    CHECK(VM27DiskIOCancel(io, &cancelled) == 0 && cancelled == 16);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 399, 0, readBuffer, 0) == EAGAIN);
    for (uint64_t i = 0; i < 16; i++) completion(io, 300 + i, -ECANCELED, VM27DiskCompletionPresent | VM27DiskCompletionCancelled);
    CHECK(VM27DiskIOResume(io) == 0);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 400, 0, readBuffer, sizeof(readBuffer)) == 0);
    completion(io, 400, sizeof(readBuffer), VM27DiskCompletionPresent);
    CHECK(memcmp(writeBuffer, readBuffer, sizeof(readBuffer)) == 0);

    /* Closing only the caller fd proves worker ownership is independent. */
    CHECK(close(fd) == 0);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 401, 0, readBuffer, 4) == 0);
    completion(io, 401, 4, VM27DiskCompletionPresent);
    CHECK(VM27DiskIOSuspend(io) == 0);
    for (uint64_t i = 0; i < 8; i++) CHECK(VM27DiskIOSubmit(io, VM27DiskWrite, 500 + i, 0, writeBuffer, 4) == 0);
    CHECK(VM27DiskIOClose(io) == 0);
    CHECK(VM27DiskIOClose(io) == 0);
    CHECK(VM27DiskIODestroy(io) == EBUSY);
    CHECK(VM27DiskIOSubmit(io, VM27DiskRead, 599, 0, readBuffer, 0) == EBADF);
    CHECK(VM27DiskIOResume(io) == EBADF);
    for (uint64_t i = 0; i < 8; i++) completion(io, 500 + i, -ECANCELED, VM27DiskCompletionPresent | VM27DiskCompletionCancelled);
    CHECK(VM27DiskIOGetCompletion(io, &empty, -1) == ENODATA);
    CHECK(VM27DiskIOGetStats(io, &stats) == 0);
    CHECK(stats.submitted == 123 && stats.completed == 123 && stats.consumed == 123 && stats.cancelled == 24);
    CHECK(stats.bytesWritten == 131072 && stats.bytesRead == 135172 && stats.outstanding == 0 && stats.closed == 1);
    CHECK(VM27DiskIODestroy(io) == 0);

    /* Actual EBADF from a read-only provider must reach completion unchanged. */
    fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    io = NULL;
    CHECK(VM27DiskIOCreate(fd, 1, &io) == 0 && io != NULL);
    if (io) {
        CHECK(VM27DiskIOSubmit(io, VM27DiskWrite, 600, 0, writeBuffer, 1) == 0);
        completion(io, 600, -EBADF, VM27DiskCompletionPresent);
        CHECK(VM27DiskIOClose(io) == 0);
        CHECK(VM27DiskIODestroy(io) == 0);
    }
    if (fd >= 0) CHECK(close(fd) == 0);

    /* Four actual producer threads, unique cookies and persistent buffers. */
    fd = open(path, O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0);
    io = NULL;
    CHECK(VM27DiskIOCreate(fd, 16, &io) == 0 && io != NULL);
    if (io) {
        unsigned char buffers[512][32], actual[32];
        unsigned char seen[512] = {0};
        for (unsigned i = 0; i < 512; i++)
            for (unsigned j = 0; j < 32; j++) buffers[i][j] = (unsigned char)((i * 41 + j * 17) & 255);
        pthread_t threads[4];
        struct producer producers[4];
        atomic_int threadFailure = 0;
        unsigned started = 0;
        for (unsigned i = 0; i < 4; i++) {
            producers[i] = (struct producer){io, i * 128, buffers, &threadFailure};
            int error = pthread_create(&threads[i], NULL, submit_concurrent, &producers[i]);
            CHECK(error == 0);
            if (error) break;
            started++;
        }
        for (unsigned i = 0; i < started * 128; i++) {
            VM27DiskIOCompletion value;
            int error = VM27DiskIOGetCompletion(io, &value, 2000);
            CHECK(error == 0);
            if (error) { atomic_store(&threadFailure, error); break; }
            CHECK(value.cookie >= 1000 && value.cookie < 1512);
            CHECK(value.result == 32 && value.flags == VM27DiskCompletionPresent);
            if (value.cookie >= 1000 && value.cookie < 1512) {
                unsigned index = (unsigned)(value.cookie - 1000);
                CHECK(seen[index] == 0);
                seen[index] = 1;
            }
        }
        CHECK(atomic_load(&threadFailure) == 0);
        if (atomic_load(&threadFailure)) CHECK(VM27DiskIOClose(io) == 0);
        for (unsigned i = 0; i < started; i++) CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(VM27DiskIOClose(io) == 0);
        if (atomic_load(&threadFailure)) while (VM27DiskIOGetCompletion(io, &empty, 0) == 0) {}
        for (unsigned i = 0; i < started * 128; i++) {
            CHECK(seen[i] == 1);
            CHECK(pread(fd, actual, 32, (off_t)i * 32) == 32);
            CHECK(memcmp(actual, buffers[i], 32) == 0);
        }
        CHECK(VM27DiskIOGetStats(io, &stats) == 0 && stats.submitted == started * 128 &&
            stats.completed == started * 128 && stats.consumed == started * 128 && stats.bytesWritten == started * 4096);
        CHECK(VM27DiskIODestroy(io) == 0);
    }
    if (fd >= 0) CHECK(close(fd) == 0);
    struct stat file;
    CHECK(stat(path, &file) == 0 && file.st_size == 131072 && (file.st_mode & 0777) == 0600);
    CHECK(unlink(path) == 0);
    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - begin.tv_sec) * 1000 + (end.tv_usec - begin.tv_usec) / 1000;
    printf("{\"schemaVersion\":1,\"pid\":%d,\"uid\":%d,\"euid\":%d,\"checks\":%u,\"failures\":%u,\"milliseconds\":%ld,\"forbiddenVMImages\":%u,\"ownFileOnly\":true,\"fileRemoved\":%s,\"workerJoined\":%s,\"privateABI\":true,\"appleIORingsABI\":false,\"guestDiskAccessed\":false,\"vmCreated\":false}\n", getpid(), getuid(), geteuid(), checks, failures, elapsed, forbiddenImages,
        access(path, F_OK) == -1 && errno == ENOENT ? "true" : "false", failures ? "false" : "true");
    return failures ? 1 : 0;
}
