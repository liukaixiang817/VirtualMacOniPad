/* Child-only observation of the original POSIX disk calls. No I/O retries,
 * replacement queue, buffer/vector access, fcntl adaptation or guest writes.
 * A watchdog observes up to 64 armed calls over at most 180 one-second sleep attempts.
 * Missing records, overflow, logging failure, or an expired watch window never
 * establish that no host operation is outstanding. */
#define _DARWIN_C_SOURCE 1
#include "vm27_owned_child_disk_io_observer_v1.h"
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OWN_CHILD "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine"
#define OWN_DISK "/private/var/mobile/Media/VirtualMac/Tahoe3.bundle/Disk.img"
#define NS_PER_SECOND UINT64_C(1000000000)
enum { SlotCount = 64, FirstDetailedCalls = 32, ExceptionalCompletions = 32,
       MaximumLogAttempts = 224, WatchSeconds = 180 };
enum { OpPread = 1, OpPreadv, OpPwrite, OpPwritev, OpFsync };
_Static_assert(sizeof(off_t) == 8 && sizeof(ssize_t) == 8, "actual arm64e POSIX ABI");

typedef struct {
    uint64_t id, start, thread, device, inode, fileBytes, count;
    int64_t offset;
    int fd, operation, iovCount;
    unsigned pendingMask;
    bool active, detailed, nativeCallArmed;
} DiskSpanV1;
typedef struct { uint64_t id; unsigned slot; } DiskTokenV1;
static pthread_once_t AdmissionOnceV1 = PTHREAD_ONCE_INIT;
static pthread_mutex_t MutexV1 = PTHREAD_MUTEX_INITIALIZER;
static pid_t AdmittedPIDV1;
static DiskSpanV1 SlotsV1[SlotCount];
static uint64_t StartedV1, CompletedV1;
static unsigned ExceptionalV1;
static _Atomic unsigned LogAttemptsV1, DroppedLogsV1, UntrackedV1;
static _Atomic bool WatchAttemptedV1, IdentityLoggedV1;

static uint64_t NowV1(void) {
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 || value.tv_nsec < 0)
        return 0;
    return (uint64_t)value.tv_sec * NS_PER_SECOND + (uint64_t)value.tv_nsec;
}

static void EmitBytesV1(const char *text, int bytes) {
    if (bytes <= 0) return;
    if (atomic_fetch_add_explicit(&LogAttemptsV1, 1, memory_order_relaxed) >= MaximumLogAttempts) {
        atomic_fetch_add_explicit(&DroppedLogsV1, 1, memory_order_relaxed);
        return;
    }
    size_t count = (size_t)bytes;
    if (count >= 1024) count = 1023;
    if (write(STDERR_FILENO, text, count) != (ssize_t)count)
        atomic_fetch_add_explicit(&DroppedLogsV1, 1, memory_order_relaxed);
}

static const char *OperationV1(int operation) {
    static const char *names[] = {"invalid", "pread", "preadv", "pwrite", "pwritev", "fsync"};
    return operation >= OpPread && operation <= OpFsync ? names[operation] : names[0];
}

static void EmitSpanV1(const char *stage, const DiskSpanV1 *span, uint64_t now,
    bool resultKnown, ssize_t result, int nativeErrno, unsigned threshold) {
    bool durationKnown = span->start && now >= span->start;
    uint64_t elapsed = durationKnown ? now - span->start : 0;
    bool countIsBytes = span->operation == OpPread || span->operation == OpPwrite;
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV1] stage=%s id=%llu op=%s pid=%d tid=%llu fd=%d "
        "dev=%llu inode=%llu fileBytes=%llu offset=%lld byteCountKnown=%u byteCount=%llu "
        "iovCount=%d vectorMemoryNotRead=1 startNS=%llu nowNS=%llu durationKnown=%u elapsedNS=%llu "
        "nativeResultKnown=%u nativeResult=%lld nativeErrnoCaptured=%d errnoMeaningfulOnFailure=%u "
        "pendingThresholdSeconds=%u nativeCallArmed=%u wrapperOutstandingOnly=1 "
        "nativeSyscallEntryNotDirectlyObserved=1 nativeCallRetried=0 nativeCallSubstituted=0\n",
        stage, (unsigned long long)span->id, OperationV1(span->operation), (int)getpid(),
        (unsigned long long)span->thread, span->fd, (unsigned long long)span->device,
        (unsigned long long)span->inode, (unsigned long long)span->fileBytes,
        (long long)span->offset, countIsBytes ? 1U : 0U, (unsigned long long)span->count,
        span->iovCount, (unsigned long long)span->start, (unsigned long long)now,
        durationKnown ? 1U : 0U, (unsigned long long)elapsed, resultKnown ? 1U : 0U,
        (long long)result, nativeErrno, resultKnown && result < 0 ? 1U : 0U, threshold, span->nativeCallArmed ? 1U : 0U);
    EmitBytesV1(text, bytes);
}

static void AdmissionV1(void) {
    static const uint8_t uuid[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
                                    0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    if (getuid() != 501 || geteuid() != 501 || getpid() <= 1) return;
    char path[4096], canonical[4096];
    uint32_t capacity = sizeof(path);
    if (_NSGetExecutablePath(path, &capacity) || !realpath(path, canonical) || strcmp(canonical, OWN_CHILD)) return;
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 2048 || header->sizeofcmds > 65536) return;
    const uint8_t *at = (const uint8_t *)(header + 1), *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(end - at) < 8) return;
        const struct load_command *command = (const struct load_command *)at;
        if (command->cmdsize < 8 || (command->cmdsize & 7) || command->cmdsize > (size_t)(end - at)) return;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) || ++matches != 1 ||
                memcmp(((const struct uuid_command *)command)->uuid, uuid, sizeof(uuid))) return;
        }
        at += command->cmdsize;
    }
    if (at == end && matches == 1) AdmittedPIDV1 = getpid();
}

static bool SelectedV1(int fd, struct stat *actual) {
    pthread_once(&AdmissionOnceV1, AdmissionV1);
    if (!AdmittedPIDV1 || AdmittedPIDV1 != getpid() || getuid() != 501 || geteuid() != 501 || fd < 0) return false;
    struct stat named = {0};
    if (lstat(OWN_DISK, &named) || fstat(fd, actual)) return false;
    return S_ISREG(named.st_mode) && S_ISREG(actual->st_mode) && named.st_uid == 501 &&
        actual->st_uid == 501 && named.st_nlink == 1 && actual->st_nlink == 1 && named.st_size > 0 &&
        named.st_dev == actual->st_dev && named.st_ino == actual->st_ino && named.st_size == actual->st_size;
}

static void EmitSummaryV1(unsigned second, bool expired) {
    uint64_t started = 0, completed = 0;
    unsigned outstanding = 0;
    if (!pthread_mutex_lock(&MutexV1)) {
        started = StartedV1; completed = CompletedV1;
        for (unsigned index = 0; index < SlotCount; ++index) outstanding += SlotsV1[index].active ? 1U : 0U;
        pthread_mutex_unlock(&MutexV1);
    }
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV1] stage=watch-summary watchIteration=%u watchWindowExpired=%u "
        "selectedStarted=%llu selectedCompleted=%llu trackedOutstanding=%u untrackedSelected=%u "
        "logAttempts=%u droppedLogs=%u capacity=%u futureOutstandingObservationUnavailable=%u "
        "noOutstandingConclusionNotProved=1\n", second, expired ? 1U : 0U,
        (unsigned long long)started, (unsigned long long)completed, outstanding,
        atomic_load_explicit(&UntrackedV1, memory_order_relaxed),
        atomic_load_explicit(&LogAttemptsV1, memory_order_relaxed),
        atomic_load_explicit(&DroppedLogsV1, memory_order_relaxed), SlotCount, expired ? 1U : 0U);
    EmitBytesV1(text, bytes);
}

static void *WatchV1(void *unused) {
    (void)unused;
    static const unsigned thresholds[] = {5, 30, 60};
    for (unsigned second = 1; second <= WatchSeconds; ++second) {
        struct timespec delay = {1, 0};
        (void)nanosleep(&delay, NULL);  /* No retry loop; this observer never controls real I/O. */
        DiskSpanV1 pending[SlotCount]; unsigned masks[SlotCount], count = 0;
        uint64_t now = NowV1();
        if (!pthread_mutex_lock(&MutexV1)) {
            for (unsigned index = 0; index < SlotCount; ++index) {
                DiskSpanV1 *span = &SlotsV1[index];
                if (!span->active || !span->nativeCallArmed || !span->start || now < span->start) continue;
                unsigned mask = 0;
                for (unsigned bit = 0; bit < 3; ++bit)
                    if (!(span->pendingMask & (1U << bit)) && now - span->start >= thresholds[bit] * NS_PER_SECOND)
                        mask |= 1U << bit;
                if (mask) { span->pendingMask |= mask; pending[count] = *span; masks[count++] = mask; }
            }
            pthread_mutex_unlock(&MutexV1);
        }
        for (unsigned index = 0; index < count; ++index)
            for (unsigned bit = 0; bit < 3; ++bit)
                if (masks[index] & (1U << bit))
                    EmitSpanV1("outstanding-observed", &pending[index], now, false, 0, 0, thresholds[bit]);
        if (second == 5 || second == 30 || second == 60 || second == WatchSeconds)
            EmitSummaryV1(second, second == WatchSeconds);
    }
    return NULL;
}

static void StartWatchV1(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&WatchAttemptedV1, &expected, true,
                                                 memory_order_relaxed, memory_order_relaxed)) return;
    pthread_t worker;
    int result = pthread_create(&worker, NULL, WatchV1, NULL), detached = -1;
    if (!result) detached = pthread_detach(worker);
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV1] stage=watch-start createResult=%d detachResult=%d "
        "maximumIterations=%u thresholds=5,30,60 watchdogDoesNotCancelIO=1\n", result, detached, WatchSeconds);
    EmitBytesV1(text, bytes);
}

static DiskTokenV1 BeginV1(int operation, int fd, off_t offset, size_t bytes, int iovCount) {
    DiskTokenV1 token = {0};
    struct stat identity = {0};
    if (!SelectedV1(fd, &identity)) return token;
    DiskSpanV1 span = {.fd=fd, .operation=operation, .offset=(int64_t)offset,
        .count=(uint64_t)bytes, .iovCount=iovCount, .start=NowV1(), .active=true,
        .device=(uint64_t)identity.st_dev, .inode=(uint64_t)identity.st_ino, .fileBytes=(uint64_t)identity.st_size};
    (void)pthread_threadid_np(NULL, &span.thread);
    if (pthread_mutex_lock(&MutexV1)) {
        atomic_fetch_add_explicit(&UntrackedV1, 1, memory_order_relaxed); return token;
    }
    span.id = ++StartedV1;
    span.detailed = span.id <= FirstDetailedCalls;
    for (unsigned index = 0; index < SlotCount; ++index)
        if (!SlotsV1[index].active) { SlotsV1[index] = span; token.id = span.id; token.slot = index; break; }
    pthread_mutex_unlock(&MutexV1);
    if (!token.id) atomic_fetch_add_explicit(&UntrackedV1, 1, memory_order_relaxed);
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(&IdentityLoggedV1, &expected, true,
                                               memory_order_relaxed, memory_order_relaxed))
        EmitSpanV1("owned-disk-identity", &span, NowV1(), false, 0, 0, 0);
    if (token.id && span.detailed) EmitSpanV1("begin-observed", &span, NowV1(), false, 0, 0, 0);
    StartWatchV1();
    return token;
}

/* No log, selector, thread creation or buffer work follows this arming point.
 * The direct delegate call follows after restoring incoming errno. This marks
 * wrapper call-boundary evidence, not a kernel syscall-entry trace. */
static void ArmV1(DiskTokenV1 token) {
    if (!token.id) return;
    if (pthread_mutex_lock(&MutexV1)) {
        atomic_fetch_add_explicit(&UntrackedV1, 1, memory_order_relaxed); return;
    }
    if (token.slot < SlotCount && SlotsV1[token.slot].active && SlotsV1[token.slot].id == token.id) {
        SlotsV1[token.slot].start = NowV1(); SlotsV1[token.slot].nativeCallArmed = true;
    }
    pthread_mutex_unlock(&MutexV1);
}

static void EndV1(DiskTokenV1 token, ssize_t result, int nativeErrno) {
    if (!token.id) return;
    uint64_t now = NowV1();
    DiskSpanV1 span = {0}; bool emit = false;
    if (pthread_mutex_lock(&MutexV1)) return;
    if (token.slot < SlotCount && SlotsV1[token.slot].active && SlotsV1[token.slot].id == token.id) {
        span = SlotsV1[token.slot]; SlotsV1[token.slot].active = false; ++CompletedV1;
        bool slow = span.start && now >= span.start && now - span.start >= NS_PER_SECOND;
        emit = span.detailed || span.pendingMask || ((result < 0 || slow) && ExceptionalV1++ < ExceptionalCompletions);
    }
    pthread_mutex_unlock(&MutexV1);
    if (emit) EmitSpanV1("completion-observed", &span, now, true, result, nativeErrno, 0);
}

ssize_t VM27OwnedChildDiskPreadV1(int fd, void *buffer, size_t count, off_t offset) {
    int incoming = errno; DiskTokenV1 token = BeginV1(OpPread, fd, offset, count, 0);
    ArmV1(token); errno = incoming; ssize_t result = pread(fd, buffer, count, offset); int nativeErrno = errno;
    EndV1(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPreadvV1(int fd, const struct iovec *vectors, int count, off_t offset) {
    int incoming = errno; DiskTokenV1 token = BeginV1(OpPreadv, fd, offset, 0, count);
    ArmV1(token); errno = incoming; ssize_t result = preadv(fd, vectors, count, offset); int nativeErrno = errno;
    EndV1(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPwriteV1(int fd, const void *buffer, size_t count, off_t offset) {
    int incoming = errno; DiskTokenV1 token = BeginV1(OpPwrite, fd, offset, count, 0);
    ArmV1(token); errno = incoming; ssize_t result = pwrite(fd, buffer, count, offset); int nativeErrno = errno;
    EndV1(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPwritevV1(int fd, const struct iovec *vectors, int count, off_t offset) {
    int incoming = errno; DiskTokenV1 token = BeginV1(OpPwritev, fd, offset, 0, count);
    ArmV1(token); errno = incoming; ssize_t result = pwritev(fd, vectors, count, offset); int nativeErrno = errno;
    EndV1(token, result, nativeErrno); errno = nativeErrno; return result;
}
int VM27OwnedChildDiskFsyncV1(int fd) {
    int incoming = errno; DiskTokenV1 token = BeginV1(OpFsync, fd, 0, 0, 0);
    ArmV1(token); errno = incoming; int result = fsync(fd); int nativeErrno = errno;
    EndV1(token, result, nativeErrno); errno = nativeErrno; return result;
}
