/* Read-only counters for one exact owned VMM child; no process enumeration.
 * libproc ABI: Apple xnu-8792.41.9 bsd/sys/proc_info.h and
 * libsyscall/wrappers/libproc/libproc.h. The iPhoneOS SDK omits these two
 * headers, so only the two needed fixed-size records are declared here.
 * rusage_info_v4 comes from the actual iPhoneOS SDK sys/resource.h.
 * Build and device execution are separate from source preparation.
 */
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum { VM27BSDInfoV1 = 3, VM27TaskInfoV1 = 4, VM27OwnedUIDV1 = 501 };
static const char ChildPathV1[] =
    "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/"
    "VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/"
    "Contents/MacOS/com.apple.Virtualization.VirtualMachine";
static const char ParentPathV1[] =
    "/private/preboot/3BAC96003F990D2A2530F3FB8BF9293399970140D40FBF3A5A9A6CCCCF018C0C30F94334FCD17DF3DC7434C1EA34FC3E/"
    "dopamine-FUG16w/procursus/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27";

typedef struct {
    uint32_t flags, status, xstatus, pid, ppid;
    uid_t uid; gid_t gid; uid_t ruid; gid_t rgid; uid_t svuid; gid_t svgid;
    uint32_t reserved;
    char comm[16], name[32];
    uint32_t nfiles, pgid, pjobc, tdev, tpgid;
    int32_t nice;
    uint64_t startSec, startUsec;
} VM27BSDV1;
typedef struct {
    uint64_t virtualSize, residentSize, totalUser, totalSystem;
    uint64_t threadsUser, threadsSystem;
    int32_t policy, faults, pageins, cowFaults, messagesSent, messagesReceived;
    int32_t syscallsMach, syscallsUnix, contextSwitches, threads, running, priority;
} VM27TaskV1;
_Static_assert(sizeof(VM27BSDV1) == 136, "proc_bsdinfo ABI");
_Static_assert(offsetof(VM27BSDV1, startSec) == 120, "proc start seconds ABI");
_Static_assert(offsetof(VM27BSDV1, startUsec) == 128, "proc start useconds ABI");
_Static_assert(sizeof(VM27TaskV1) == 96, "proc_taskinfo ABI");
_Static_assert(offsetof(VM27TaskV1, contextSwitches) == 80, "proc csw ABI");
_Static_assert(sizeof(struct rusage_info_v4) == 296, "rusage V4 ABI");

typedef int (*PidInfoV1)(int, int, uint64_t, void *, int);
typedef int (*PidPathV1)(int, void *, uint32_t);
typedef int (*PidRusageV1)(int, int, rusage_info_t *);
static PidInfoV1 PIDInfo;
static PidPathV1 PIDPath;
static PidRusageV1 PIDRusage;

static void TimeoutV1(int sig) { (void)sig; _exit(124); }
static int ParsePIDV1(const char *text, pid_t *value) {
    char *end = NULL;
    if (!text[0] || text[0] == '-' || text[0] == '+') return 0;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !end || *end || n < 2 || n > INT_MAX) return 0;
    *value = (pid_t)n;
    return 1;
}
static int SameIdentityV1(const VM27BSDV1 *a, const VM27BSDV1 *b) {
    return a->pid == b->pid && a->ppid == b->ppid && a->uid == b->uid &&
        a->ruid == b->ruid && a->svuid == b->svuid &&
        a->startSec == b->startSec && a->startUsec == b->startUsec;
}
static int ReadIdentityV1(pid_t pid, pid_t ppid, const char *expected,
                          const VM27BSDV1 *pinned, VM27BSDV1 *result) {
    VM27BSDV1 first = {0}, last = {0};
    char path[4096] = {0};
    errno = 0;
    int firstBytes = PIDInfo(pid, VM27BSDInfoV1, 0, &first, sizeof(first));
    int firstErrno = errno;
    errno = 0;
    int pathBytes = PIDPath(pid, path, sizeof(path));
    int pathErrno = errno;
    errno = 0;
    int lastBytes = PIDInfo(pid, VM27BSDInfoV1, 0, &last, sizeof(last));
    int lastErrno = errno;
    int valid = firstBytes == (int)sizeof(first) && lastBytes == (int)sizeof(last)
        && pathBytes > 0 && pathBytes < (int)sizeof(path)
        && memchr(path, 0, sizeof(path)) != NULL && strcmp(path, expected) == 0
        && SameIdentityV1(&first, &last) && last.pid == (uint32_t)pid
        && last.ppid == (uint32_t)ppid && last.uid == VM27OwnedUIDV1
        && last.ruid == VM27OwnedUIDV1 && last.svuid == VM27OwnedUIDV1
        && last.startSec > 0 && last.startUsec < 1000000
        && !(last.flags & 4U) && last.status != 5U
        && (!pinned || SameIdentityV1(pinned, &last));
    if (!valid) {
        printf("OWN_IO_IDENTITY known=0 pid=%d firstBytes=%d firstErrno=%d "
               "pathBytes=%d pathErrno=%d lastBytes=%d lastErrno=%d\n",
               pid, firstBytes, firstErrno, pathBytes, pathErrno, lastBytes, lastErrno);
        return 0;
    }
    *result = last;
    return 1;
}
static int PairIdentityV1(pid_t child, pid_t parent, const VM27BSDV1 *childPin,
                          const VM27BSDV1 *parentPin, VM27BSDV1 *childOut,
                          VM27BSDV1 *parentOut) {
    return ReadIdentityV1(parent, 1, ParentPathV1, parentPin, parentOut)
        && ReadIdentityV1(child, parent, ChildPathV1, childPin, childOut);
}
static double ElapsedV1(const struct timespec *start) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (double)(now.tv_sec - start->tv_sec)
        + (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}
static int WaitUntilV1(const struct timespec *start, unsigned seconds) {
    for (;;) {
        double elapsed = ElapsedV1(start);
        if (elapsed < 0 || elapsed >= 90) return 0;
        double left = (double)seconds - elapsed;
        if (left <= 0) return 1;
        if (left > 0.5) left = 0.5;
        struct timespec delay = {0, (long)(left * 1000000000.0)};
        if (nanosleep(&delay, NULL) && errno != EINTR) return 0;
    }
}

int main(int argc, char **argv) {
    pid_t child, parent;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5 || strcmp(argv[1], "--owned-child") ||
        strcmp(argv[3], "--owned-parent") || !ParsePIDV1(argv[2], &child) ||
        !ParsePIDV1(argv[4], &parent) || child == parent || child == getpid() ||
        parent == getpid() || (getuid() != 0 && getuid() != VM27OwnedUIDV1)) {
        fprintf(stderr, "usage: probe --owned-child CAPTURED_PID --owned-parent CAPTURED_APP_PID\n");
        return 64;
    }
    if (signal(SIGALRM, TimeoutV1) == SIG_ERR) return 70;
    alarm(90); /* Signals this observer only; never targets the child or parent. */
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 70;
    PIDInfo = (PidInfoV1)dlsym(RTLD_DEFAULT, "proc_pidinfo");
    PIDPath = (PidPathV1)dlsym(RTLD_DEFAULT, "proc_pidpath");
    PIDRusage = (PidRusageV1)dlsym(RTLD_DEFAULT, "proc_pid_rusage");
    printf("OWN_IO_CAPABILITY pidinfo=%d pidpath=%d rusage=%d uid=%u euid=%u "
           "samples=0,5,30,60 maximumSeconds=90 rawProcessCountersOnly=1\n",
           PIDInfo != NULL, PIDPath != NULL, PIDRusage != NULL,
           (unsigned)getuid(), (unsigned)geteuid());
    if (!PIDInfo || !PIDPath || !PIDRusage) return 69;
    VM27BSDV1 childPin, parentPin, childNow, parentNow;
    if (!PairIdentityV1(child, parent, NULL, NULL, &childPin, &parentPin) ||
        !PairIdentityV1(child, parent, &childPin, &parentPin, &childNow, &parentNow)) return 77;
    printf("OWN_IO_ENROLLED child=%d parent=%d uid=501 childStartSec=%" PRIu64
           " childStartUsec=%" PRIu64 " parentStartSec=%" PRIu64
           " parentStartUsec=%" PRIu64 " childPath=%s parentPath=%s\n",
           child, parent, childPin.startSec, childPin.startUsec,
           parentPin.startSec, parentPin.startUsec, ChildPathV1, ParentPathV1);
    const unsigned schedule[] = {0, 5, 30, 60};
    unsigned complete = 0;
    for (unsigned i = 0; i < sizeof(schedule) / sizeof(schedule[0]); ++i) {
        if (!WaitUntilV1(&start, schedule[i])) return 75;
        if (!PairIdentityV1(child, parent, &childPin, &parentPin, &childNow, &parentNow)) return 77;
        struct rusage_info_v4 usage = {0};
        VM27TaskV1 task = {0};
        errno = 0;
        int usageResult = PIDRusage(child, RUSAGE_INFO_V4, (rusage_info_t *)&usage);
        int usageErrno = errno;
        errno = 0;
        int taskBytes = PIDInfo(child, VM27TaskInfoV1, 0, &task, sizeof(task));
        int taskErrno = errno;
        if (!PairIdentityV1(child, parent, &childPin, &parentPin, &childNow, &parentNow)) return 77;
        double elapsed = ElapsedV1(&start);
        if (elapsed < 0 || elapsed >= 90) return 75;
        int usageKnown = usageResult == 0;
        int taskKnown = taskBytes == (int)sizeof(task);
        printf("OWN_IO_SAMPLE targetSeconds=%u elapsedSeconds=%.6f child=%d parent=%d "
               "identityBeforeAfter=1 nonAtomic=1 rusageKnown=%d rusageResult=%d "
               "rusageErrno=%d taskKnown=%d taskBytes=%d taskErrno=%d\n",
               schedule[i], elapsed, child, parent, usageKnown, usageResult,
               usageErrno, taskKnown, taskBytes, taskErrno);
        if (usageKnown) printf("OWN_IO_RUSAGE targetSeconds=%u diskReadBytes=%" PRIu64
               " diskWrittenBytes=%" PRIu64 " userTimeRaw=%" PRIu64
               " systemTimeRaw=%" PRIu64 " startAbstime=%" PRIu64
               " pageins=%" PRIu64 " logicalWrites=%" PRIu64 "\n",
               schedule[i], usage.ri_diskio_bytesread, usage.ri_diskio_byteswritten,
               usage.ri_user_time, usage.ri_system_time, usage.ri_proc_start_abstime,
               usage.ri_pageins, usage.ri_logical_writes);
        if (taskKnown) printf("OWN_IO_TASK targetSeconds=%u contextSwitches=%" PRId32
               " syscallsMach=%" PRId32 " syscallsUnix=%" PRId32
               " threads=%" PRId32 " running=%" PRId32 " pageins=%" PRId32
               " totalUserRaw=%" PRIu64 " totalSystemRaw=%" PRIu64 "\n",
               schedule[i], task.contextSwitches, task.syscallsMach, task.syscallsUnix,
               task.threads, task.running, task.pageins, task.totalUser, task.totalSystem);
        complete += usageKnown && taskKnown;
    }
    printf("OWN_IO_DONE samples=4 completeCounterSamples=%u maximumSeconds=90 "
           "guestRAMReads=0 taskPorts=0 targetSignals=0 targetWrites=0\n", complete);
    alarm(0);
    return complete == 4 ? 0 : 78;
}
