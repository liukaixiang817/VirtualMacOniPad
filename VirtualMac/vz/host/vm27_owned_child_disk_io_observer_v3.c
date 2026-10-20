/* V3 adds bounded exact original completion/used-ring call observers.
 * V2 fixed descriptor identity is pinned by Root read-only guest configuration:
 * independent27-app99-current-guest-readonly-v11-attempt1/configuration.json.
 * Child-only observation of the original POSIX disk calls. No I/O retries,
 * replacement queue, buffer/vector access, fcntl adaptation or guest writes.
 * A watchdog observes up to 64 armed calls over at most 180 one-second sleep attempts.
 * Missing records, overflow, logging failure, or an expired watch window never
 * establish that no host operation is outstanding. */
#define _DARWIN_C_SOURCE 1
#include "vm27_owned_child_disk_io_observer_v3.h"
#include <errno.h>
#include <dlfcn.h>
#include <ptrauth.h>
#include <fcntl.h>
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
enum { SlotCount = 64, FirstDetailedCalls = 8, ExceptionalCompletions = 32,
       MaximumLogAttempts = 224, WatchSeconds = 180 };
enum { OpPread = 1, OpPreadv, OpPwrite, OpPwritev, OpFsync };
_Static_assert(sizeof(off_t) == 8 && sizeof(ssize_t) == 8, "actual arm64e POSIX ABI");

typedef struct {
    uint64_t id, start, thread, device, inode, fileBytes, count;
    int64_t offset;
    int fd, operation, iovCount;
    unsigned pendingMask;
    bool active, detailed, nativeCallArmed;
} DiskSpanV2;
typedef struct { uint64_t id; unsigned slot; } DiskTokenV2;
static pthread_mutex_t MutexV2 = PTHREAD_MUTEX_INITIALIZER;
static DiskSpanV2 SlotsV2[SlotCount];
static uint64_t StartedV2, CompletedV2;
static unsigned ExceptionalV2;
static _Atomic unsigned LogAttemptsV2, DroppedLogsV2, UntrackedV2, WrapperEntriesV2;
static _Atomic bool WatchAttemptedV2, IdentityLoggedV2;

static uint64_t NowV2(void) {
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 || value.tv_nsec < 0)
        return 0;
    return (uint64_t)value.tv_sec * NS_PER_SECOND + (uint64_t)value.tv_nsec;
}

/* The original consumer already proves this owned log identity at spawn.
 * Recheck the inherited raw stderr descriptor, without any pathname lookup. */
static void EmitBytesV2(const char *text, int bytes) {
    int saved = errno;
    struct stat st = {0};
    int flags = fcntl(STDERR_FILENO, F_GETFL);
    bool verified = flags >= 0 && !fstat(STDERR_FILENO, &st) && S_ISREG(st.st_mode) &&
        (uint64_t)st.st_dev == UINT64_C(16777223) && (uint64_t)st.st_ino == UINT64_C(48200252) &&
        st.st_uid == 501 && st.st_gid == 501 && (st.st_mode & 07777) == 0600 && st.st_nlink == 1 &&
        st.st_size >= 0 && st.st_size <= 2097152 && (flags & O_APPEND) && (flags & O_ACCMODE) != O_RDONLY;
    if (bytes <= 0 || !verified ||
        atomic_fetch_add_explicit(&LogAttemptsV2, 1, memory_order_relaxed) >= MaximumLogAttempts) {
        atomic_fetch_add_explicit(&DroppedLogsV2, 1, memory_order_relaxed); errno = saved; return;
    }
    size_t count = (size_t)bytes;
    if (count >= 1024) count = 1023;
    if (write(STDERR_FILENO, text, count) != (ssize_t)count)
        atomic_fetch_add_explicit(&DroppedLogsV2, 1, memory_order_relaxed);
    errno = saved;
}

static const char *OperationV2(int operation) {
    static const char *names[] = {"invalid", "pread", "preadv", "pwrite", "pwritev", "fsync"};
    return operation >= OpPread && operation <= OpFsync ? names[operation] : names[0];
}

static void EmitSpanV2(const char *stage, const DiskSpanV2 *span, uint64_t now,
    bool resultKnown, ssize_t result, int nativeErrno, unsigned threshold) {
    bool durationKnown = span->start && now >= span->start;
    uint64_t elapsed = durationKnown ? now - span->start : 0;
    bool countIsBytes = span->operation == OpPread || span->operation == OpPwrite;
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV2] stage=%s id=%llu op=%s pid=%d tid=%llu fd=%d "
        "dev=%llu inode=%llu fileBytes=%llu offset=%lld byteCountKnown=%u byteCount=%llu "
        "iovCount=%d vectorMemoryNotRead=1 startNS=%llu nowNS=%llu durationKnown=%u elapsedNS=%llu "
        "nativeResultKnown=%u nativeResult=%lld nativeErrnoCaptured=%d errnoMeaningfulOnFailure=%u "
        "pendingThresholdSeconds=%u nativeCallArmed=%u wrapperOutstandingOnly=1 "
        "nativeSyscallEntryNotDirectlyObserved=1 nativeCallRetried=0 nativeCallSubstituted=0\n",
        stage, (unsigned long long)span->id, OperationV2(span->operation), (int)getpid(),
        (unsigned long long)span->thread, span->fd, (unsigned long long)span->device,
        (unsigned long long)span->inode, (unsigned long long)span->fileBytes,
        (long long)span->offset, countIsBytes ? 1U : 0U, (unsigned long long)span->count,
        span->iovCount, (unsigned long long)span->start, (unsigned long long)now,
        durationKnown ? 1U : 0U, (unsigned long long)elapsed, resultKnown ? 1U : 0U,
        (long long)result, nativeErrno, resultKnown && result < 0 ? 1U : 0U, threshold, span->nativeCallArmed ? 1U : 0U);
    EmitBytesV2(text, bytes);
}

/* Reason values: 0 selected; 1 UID/PID; 2 dladdr; 3 image path;
 * 4 Mach-O shape; 5 UUID; 6 native fstat failure; 7 fixed FD metadata mismatch.
 * The pathname lookup is diagnostic only and can never reject an inherited FD. */
typedef struct {
    unsigned reason, admissionReason, headerMagic, fileType, ncmds;
    int fdStatResult, fdStatErrno, pathStatResult, pathStatErrno;
    bool pathMatched, uuidMatched, fdMetadataMatched;
    uintptr_t caller, callerRVA;
    const char *callerPath;
} DiskAdmissionV2;
static unsigned AdmissionV2(void *caller, DiskAdmissionV2 *gate) {
    static const uint8_t uuid[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
                                    0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    gate->caller = (uintptr_t)caller;
    if (getuid() != 501 || geteuid() != 501 || getpid() <= 1) return 1;
    Dl_info image = {0};
    if (!caller || !dladdr(caller, &image) || !image.dli_fname || !image.dli_fbase) return 2;
    gate->callerPath = image.dli_fname;
    gate->callerRVA = (uintptr_t)caller - (uintptr_t)image.dli_fbase;
    gate->pathMatched = !strcmp(image.dli_fname, OWN_CHILD);
    if (!gate->pathMatched) return 3;
    const struct mach_header_64 *header = image.dli_fbase;
    gate->headerMagic = header->magic; gate->fileType = header->filetype; gate->ncmds = header->ncmds;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_EXECUTE ||
        !header->ncmds || header->ncmds > 2048 || header->sizeofcmds > 65536) return 4;
    const uint8_t *at = (const uint8_t *)(header + 1), *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if ((size_t)(end - at) < 8) return 4;
        const struct load_command *command = (const struct load_command *)at;
        if (command->cmdsize < 8 || (command->cmdsize & 7) || command->cmdsize > (size_t)(end - at)) return 4;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) || ++matches != 1) return 5;
            gate->uuidMatched = !memcmp(((const struct uuid_command *)command)->uuid, uuid, sizeof(uuid));
        }
        at += command->cmdsize;
    }
    return at == end && matches == 1 && gate->uuidMatched ? 0 : 5;
}
#include "vm27_owned_child_completion_observer_v1.inc"

static bool SelectedV2(int fd, void *caller, struct stat *actual, bool diagnose, DiskAdmissionV2 *gate) {
    gate->fdStatResult = gate->pathStatResult = -2;
    gate->admissionReason = AdmissionV2(caller, gate);
    gate->reason = gate->admissionReason;
    if (!gate->admissionReason || diagnose) {
        gate->fdStatResult = fstat(fd, actual); gate->fdStatErrno = errno;
        if (!gate->fdStatResult) {
            gate->fdMetadataMatched = S_ISREG(actual->st_mode) &&
                (uint64_t)actual->st_dev == UINT64_C(16777223) &&
                (uint64_t)actual->st_ino == UINT64_C(45558518) &&
                actual->st_uid == 501 && actual->st_gid == 501 &&
                (actual->st_mode & 07777) == 0600 && actual->st_nlink == 1 &&
                (uint64_t)actual->st_size == UINT64_C(274877906944);
        }
        if (!gate->admissionReason)
            gate->reason = gate->fdStatResult ? 6 : gate->fdMetadataMatched ? 0 : 7;
    }
    if (diagnose) {
        struct stat named = {0};
        gate->pathStatResult = lstat(OWN_DISK, &named); gate->pathStatErrno = errno;
    }
    return gate->reason == 0;
}
static void EmitAdmissionV2(unsigned entry, int operation, int fd, const struct stat *st,
                            const DiskAdmissionV2 *gate) {
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV2] stage=wrapper-entry entry=%u op=%s fd=%d selected=%u reason=%u "
        "admissionReason=%u fdStatResult=%d fdStatErrno=%d fdStatKnown=%u dev=%llu inode=%llu "
        "uid=%u gid=%u mode=0%o nlink=%llu fileBytes=%lld fdMetadataMatched=%u "
        "optionalPathStatResult=%d optionalPathStatErrno=%d pathStatIsNotAGate=1 "
        "caller=0x%llx callerRVA=0x%llx callerPathMatched=%u callerUUIDMatched=%u "
        "headerMagic=0x%x fileType=%u ncmds=%u callerPathPrefix=%.160s nativeCallNotYetDelegated=1\n",
        entry, OperationV2(operation), fd, gate->reason == 0 ? 1U : 0U, gate->reason,
        gate->admissionReason, gate->fdStatResult, gate->fdStatErrno, gate->fdStatResult == 0 ? 1U : 0U,
        (unsigned long long)st->st_dev, (unsigned long long)st->st_ino, (unsigned)st->st_uid,
        (unsigned)st->st_gid, (unsigned)st->st_mode, (unsigned long long)st->st_nlink,
        (long long)st->st_size, gate->fdMetadataMatched ? 1U : 0U,
        gate->pathStatResult, gate->pathStatErrno, (unsigned long long)gate->caller,
        (unsigned long long)gate->callerRVA, gate->pathMatched ? 1U : 0U, gate->uuidMatched ? 1U : 0U,
        gate->headerMagic, gate->fileType, gate->ncmds, gate->callerPath ? gate->callerPath : "(unavailable)");
    EmitBytesV2(text, bytes);
}

static void EmitSummaryV2(unsigned second, bool expired) {
    uint64_t started = 0, completed = 0;
    unsigned outstanding = 0;
    if (!pthread_mutex_lock(&MutexV2)) {
        started = StartedV2; completed = CompletedV2;
        for (unsigned index = 0; index < SlotCount; ++index) outstanding += SlotsV2[index].active ? 1U : 0U;
        pthread_mutex_unlock(&MutexV2);
    }
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV2] stage=watch-summary watchIteration=%u watchWindowExpired=%u "
        "selectedStarted=%llu selectedCompleted=%llu trackedOutstanding=%u untrackedSelected=%u "
        "logAttempts=%u droppedLogs=%u capacity=%u futureOutstandingObservationUnavailable=%u "
        "noOutstandingConclusionNotProved=1\n", second, expired ? 1U : 0U,
        (unsigned long long)started, (unsigned long long)completed, outstanding,
        atomic_load_explicit(&UntrackedV2, memory_order_relaxed),
        atomic_load_explicit(&LogAttemptsV2, memory_order_relaxed),
        atomic_load_explicit(&DroppedLogsV2, memory_order_relaxed), SlotCount, expired ? 1U : 0U);
    EmitBytesV2(text, bytes);
}

static void *WatchV2(void *unused) {
    (void)unused;
    static const unsigned thresholds[] = {5, 30, 60};
    for (unsigned second = 1; second <= WatchSeconds; ++second) {
        struct timespec delay = {1, 0};
        (void)nanosleep(&delay, NULL);  /* No retry loop; this observer never controls real I/O. */
        DiskSpanV2 pending[SlotCount]; unsigned masks[SlotCount], count = 0;
        uint64_t now = NowV2();
        if (!pthread_mutex_lock(&MutexV2)) {
            for (unsigned index = 0; index < SlotCount; ++index) {
                DiskSpanV2 *span = &SlotsV2[index];
                if (!span->active || !span->nativeCallArmed || !span->start || now < span->start) continue;
                unsigned mask = 0;
                for (unsigned bit = 0; bit < 3; ++bit)
                    if (!(span->pendingMask & (1U << bit)) && now - span->start >= thresholds[bit] * NS_PER_SECOND)
                        mask |= 1U << bit;
                if (mask) { span->pendingMask |= mask; pending[count] = *span; masks[count++] = mask; }
            }
            pthread_mutex_unlock(&MutexV2);
        }
        for (unsigned index = 0; index < count; ++index)
            for (unsigned bit = 0; bit < 3; ++bit)
                if (masks[index] & (1U << bit))
                    EmitSpanV2("outstanding-observed", &pending[index], now, false, 0, 0, thresholds[bit]);
        if (second == 5 || second == 30 || second == 60 || second == WatchSeconds)
            EmitSummaryV2(second, second == WatchSeconds);
        if (second == 5 || second == 30 || second == 60) CompletionSummaryV1(second);
    }
    return NULL;
}

static void StartWatchV2(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(&WatchAttemptedV2, &expected, true,
                                                 memory_order_relaxed, memory_order_relaxed)) return;
    pthread_t worker;
    int result = pthread_create(&worker, NULL, WatchV2, NULL), detached = -1;
    if (!result) detached = pthread_detach(worker);
    char text[1024];
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedDiskIOV2] stage=watch-start createResult=%d detachResult=%d "
        "maximumIterations=%u thresholds=5,30,60 watchdogDoesNotCancelIO=1\n", result, detached, WatchSeconds);
    EmitBytesV2(text, bytes);
}

static DiskTokenV2 BeginV2(int operation, int fd, off_t offset, size_t bytes, int iovCount, void *caller) {
    DiskTokenV2 token = {0};
    struct stat identity = {0};
    unsigned entry = atomic_fetch_add_explicit(&WrapperEntriesV2, 1, memory_order_relaxed) + 1;
    DiskAdmissionV2 gate = {0}; bool selected = SelectedV2(fd, caller, &identity, entry <= 8, &gate);
    if (entry <= 8) EmitAdmissionV2(entry, operation, fd, &identity, &gate);
    if (!selected) return token;
    DiskSpanV2 span = {.fd=fd, .operation=operation, .offset=(int64_t)offset,
        .count=(uint64_t)bytes, .iovCount=iovCount, .start=NowV2(), .active=true,
        .device=(uint64_t)identity.st_dev, .inode=(uint64_t)identity.st_ino, .fileBytes=(uint64_t)identity.st_size};
    (void)pthread_threadid_np(NULL, &span.thread);
    if (pthread_mutex_lock(&MutexV2)) {
        atomic_fetch_add_explicit(&UntrackedV2, 1, memory_order_relaxed); return token;
    }
    span.id = ++StartedV2;
    span.detailed = span.id <= FirstDetailedCalls;
    for (unsigned index = 0; index < SlotCount; ++index)
        if (!SlotsV2[index].active) { SlotsV2[index] = span; token.id = span.id; token.slot = index; break; }
    pthread_mutex_unlock(&MutexV2);
    if (!token.id) atomic_fetch_add_explicit(&UntrackedV2, 1, memory_order_relaxed);
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(&IdentityLoggedV2, &expected, true,
                                               memory_order_relaxed, memory_order_relaxed))
        EmitSpanV2("owned-disk-identity", &span, NowV2(), false, 0, 0, 0);
    if (token.id && span.detailed) EmitSpanV2("begin-observed", &span, NowV2(), false, 0, 0, 0);
    StartWatchV2();
    return token;
}

/* No log, selector, thread creation or buffer work follows this arming point.
 * The direct delegate call follows after restoring incoming errno. This marks
 * wrapper call-boundary evidence, not a kernel syscall-entry trace. */
static void ArmV2(DiskTokenV2 token) {
    if (!token.id) return;
    if (pthread_mutex_lock(&MutexV2)) {
        atomic_fetch_add_explicit(&UntrackedV2, 1, memory_order_relaxed); return;
    }
    if (token.slot < SlotCount && SlotsV2[token.slot].active && SlotsV2[token.slot].id == token.id) {
        SlotsV2[token.slot].start = NowV2(); SlotsV2[token.slot].nativeCallArmed = true;
    }
    pthread_mutex_unlock(&MutexV2);
}

static void EndV2(DiskTokenV2 token, ssize_t result, int nativeErrno) {
    if (!token.id) return;
    uint64_t now = NowV2();
    DiskSpanV2 span = {0}; bool emit = false;
    if (pthread_mutex_lock(&MutexV2)) return;
    if (token.slot < SlotCount && SlotsV2[token.slot].active && SlotsV2[token.slot].id == token.id) {
        span = SlotsV2[token.slot]; SlotsV2[token.slot].active = false; ++CompletedV2;
        bool slow = span.start && now >= span.start && now - span.start >= NS_PER_SECOND;
        emit = span.detailed || span.pendingMask || ((result < 0 || slow) && ExceptionalV2++ < ExceptionalCompletions);
    }
    pthread_mutex_unlock(&MutexV2);
    if (emit) EmitSpanV2("completion-observed", &span, now, true, result, nativeErrno, 0);
}

ssize_t VM27OwnedChildDiskPreadV1(int fd, void *buffer, size_t count, off_t offset) {
    int incoming = errno; DiskTokenV2 token = BeginV2(OpPread, fd, offset, count, 0, ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address));
    ArmV2(token); errno = incoming; ssize_t result = pread(fd, buffer, count, offset); int nativeErrno = errno;
    EndV2(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPreadvV1(int fd, const struct iovec *vectors, int count, off_t offset) {
    int incoming = errno; DiskTokenV2 token = BeginV2(OpPreadv, fd, offset, 0, count, ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address));
    ArmV2(token); errno = incoming; ssize_t result = preadv(fd, vectors, count, offset); int nativeErrno = errno;
    EndV2(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPwriteV1(int fd, const void *buffer, size_t count, off_t offset) {
    int incoming = errno; DiskTokenV2 token = BeginV2(OpPwrite, fd, offset, count, 0, ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address));
    ArmV2(token); errno = incoming; ssize_t result = pwrite(fd, buffer, count, offset); int nativeErrno = errno;
    EndV2(token, result, nativeErrno); errno = nativeErrno; return result;
}
ssize_t VM27OwnedChildDiskPwritevV1(int fd, const struct iovec *vectors, int count, off_t offset) {
    int incoming = errno; DiskTokenV2 token = BeginV2(OpPwritev, fd, offset, 0, count, ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address));
    ArmV2(token); errno = incoming; ssize_t result = pwritev(fd, vectors, count, offset); int nativeErrno = errno;
    EndV2(token, result, nativeErrno); errno = nativeErrno; return result;
}
int VM27OwnedChildDiskFsyncV1(int fd) {
    int incoming = errno; DiskTokenV2 token = BeginV2(OpFsync, fd, 0, 0, 0, ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address));
    ArmV2(token); errno = incoming; int result = fsync(fd); int nativeErrno = errno;
    EndV2(token, result, nativeErrno); errno = nativeErrno; return result;
}
