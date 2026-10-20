#include "modern_xpc_private_consumer.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
struct VM27PrivateServiceConsumer {
    pthread_mutex_t mutex;
    VM27PrivateServicePlan *plan;
    VM27ApprovedCodePolicy *approved;
    VM27PrivateServiceInfo info;
    VM27PrivateConsumerState state;
    VM27PrivateConsumerMode mode;
    uint32_t childVersion;
    bool waiting;
};
static _Atomic uint64_t Created, Destroyed, Spawns, Reaps, MessageChecks;
static int Authenticate(const VM27PrivateServiceInfo *info, const char *SHA, const char *CD) {
    if (strlen(SHA) != 64 || strlen(CD) != 40 || strcmp(SHA, info->executableSHA256) || info->flags != 2) return EACCES;
    int fd = open(info->executablePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); struct stat st;
    if (fd < 0) return errno;
    int result = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 || st.st_mode & 0022 || !(st.st_mode & 0100) || st.st_size <= 0 || st.st_size > 2 * 1024 * 1024 || (uint64_t)st.st_size != info->executableBytes) result = EACCES;
    unsigned char *bytes = result ? NULL : malloc((size_t)st.st_size);
    if (!result && !bytes) result = ENOMEM;
    size_t at = 0;
    while (!result && at < (size_t)st.st_size) { ssize_t count = read(fd, bytes + at, (size_t)st.st_size - at); if (count < 0 && errno == EINTR) continue; if (count <= 0) { result = EIO; break; } at += (size_t)count; }
    if (close(fd) && !result) result = EIO;
    VM27ApprovedCodeInfo code = {0};
    if (!result) result = VM27ApprovedCodeInspectBytes(bytes, at, &code);
    if (!result && (strcmp(code.fileSHA256, SHA) || strcmp(code.CDHash, CD) || strcmp(code.UUID, info->executableUUID) || !code.pagesVerified || !code.embeddedSlotsVerified)) result = EACCES;
    free(bytes); return result;
}
int VM27PrivateServiceConsumerCreate(VM27BundleRegistry *registry, const char *service,
                                    const char *SHA, const char *CD, xpc_object_t requirement,
                                    VM27PrivateConsumerMode mode, VM27PrivateServiceConsumer **out) {
    if (!out) return EINVAL; *out = NULL;
    if (!registry || !service || !SHA || !CD || !requirement || (mode != VM27ConsumerStrictNative && mode != VM27ConsumerExplicitApprovedCode)) return EINVAL;
    VM27LWCRPolicy *constraint = NULL; int status = VM27LWCRPolicyCreate(requirement, &constraint);
    if (status) return status;
    VM27LWCRPolicyRelease(constraint);
    VM27PrivateServiceConsumer *consumer = calloc(1, sizeof(*consumer)); if (!consumer) return ENOMEM;
    status = VM27BundleRegistryCopyServicePlan(registry, service, &consumer->plan);
    if (!status) status = VM27PrivateServicePlanCopyInfo(consumer->plan, &consumer->info);
    if (!status) status = VM27PrivateServicePlanVerify(consumer->plan);
    if (!status) status = Authenticate(&consumer->info, SHA, CD);
    if (!status && mode == VM27ConsumerExplicitApprovedCode) status = VM27ApprovedCodePolicyCreate(consumer->info.executablePath, SHA, CD, requirement, &consumer->approved);
    if (!status) status = pthread_mutex_init(&consumer->mutex, NULL);
    if (status) { if (consumer->plan) VM27PrivateServicePlanRelease(consumer->plan); if (consumer->approved) VM27ApprovedCodePolicyRelease(consumer->approved); free(consumer); return status; }
    consumer->mode = mode; consumer->state.observedWaitExit = -1; *out = consumer; atomic_fetch_add(&Created, 1); return 0;
}
int VM27PrivateServiceConsumerRelease(VM27PrivateServiceConsumer *consumer) {
    if (!consumer) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    if (consumer->state.started && !consumer->state.reaped) { pthread_mutex_unlock(&consumer->mutex); return EBUSY; }
    pthread_mutex_unlock(&consumer->mutex);
    VM27PrivateServicePlanRelease(consumer->plan); if (consumer->approved) VM27ApprovedCodePolicyRelease(consumer->approved);
    pthread_mutex_destroy(&consumer->mutex); free(consumer); atomic_fetch_add(&Destroyed, 1); return 0;
}
static int ReleasePorts(mach_port_array_t ports, mach_msg_type_number_t count) {
    int result = 0;
    if (!ports) return count ? EIO : 0;
    for (unsigned i = 0; i < count; ++i) if (MACH_PORT_VALID(ports[i]) && mach_port_deallocate(mach_task_self(), ports[i])) result = EIO;
    if (ports && vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof(mach_port_t))) result = EIO;
    return result;
}
static bool BoundedStrings(char *const values[], unsigned max, size_t length, bool environment) {
    if (!values) return false;
    for (unsigned i = 0; i < max; ++i) {
        if (!values[i]) return true;
        if (strnlen(values[i], length + 1) > length || (environment && !strncmp(values[i], "DYLD_", 5))) return false;
    }
    return false;
}
int VM27PrivateServiceConsumerSpawn(VM27PrivateServiceConsumer *consumer, xpc_endpoint_t endpoint,
                                   char *const argv[], char *const env[], pid_t *out) {
    if (!out) return EINVAL; *out = 0;
    if (!consumer || !endpoint || !BoundedStrings(argv, 17, 4096, false) || !argv[0] || strcmp(argv[0], consumer->info.executablePath) || !BoundedStrings(env, 129, 16384, true)) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    int status = consumer->state.started ? EALREADY : VM27PrivateServicePlanVerify(consumer->plan);
    mach_port_array_t before = NULL, after = NULL; mach_msg_type_number_t count = 0, afterCount = 0;
    mach_port_t inherited = MACH_PORT_NULL; posix_spawnattr_t attr; bool hasAttr = false;
    if (!status && (mach_ports_lookup(mach_task_self(), &before, &count) || count != 3 || before[2] != MACH_PORT_NULL)) status = ENOTSUP;
    if (!status) status = VM27PrivateEndpointCopySendRight(endpoint, &inherited);
    if (!status) { status = posix_spawnattr_init(&attr); hasAttr = !status; }
    if (!status) { mach_port_t registered[3] = {before[0], before[1], inherited}; status = posix_spawnattr_set_registered_ports_np(&attr, registered, 3); }
    if (!status) {
        pid_t child = 0; status = posix_spawn(&child, consumer->info.executablePath, NULL, &attr, argv, env);
        if (!status) { consumer->state.childPID = child; consumer->state.started = true; *out = child; atomic_fetch_add(&Spawns, 1); }
    }
    if (hasAttr && posix_spawnattr_destroy(&attr) && !status) status = EIO;
    if (MACH_PORT_VALID(inherited) && mach_port_deallocate(mach_task_self(), inherited) && !status) status = EIO;
    if (before) {
        bool unchanged = !mach_ports_lookup(mach_task_self(), &after, &afterCount) && afterCount == count;
        for (unsigned i = 0; unchanged && i < count; ++i) unchanged = before[i] == after[i];
        consumer->state.parentRegisteredPortsUnchanged = unchanged;
        if (!unchanged && !status) status = EIO;
    }
    int first = ReleasePorts(before, count), second = ReleasePorts(after, afterCount);
    if (!status && (first || second)) status = EIO;
    pthread_mutex_unlock(&consumer->mutex); return status;
}
int VM27PrivateServiceConsumerCheckMessage(VM27PrivateServiceConsumer *consumer, xpc_object_t message, VM27ApprovedCodeMessageResult *out) {
    if (!out) return EINVAL; memset(out, 0, sizeof(*out));
    if (!consumer || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return EINVAL;
    pthread_mutex_lock(&consumer->mutex); ++consumer->state.messageChecks; atomic_fetch_add(&MessageChecks, 1);
    audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(message, &token);
    int status = !consumer->state.started || consumer->state.reaped || token.val[5] != (uint32_t)consumer->state.childPID || !token.val[7] || (consumer->childVersion && token.val[7] != consumer->childVersion) ? EACCES : VM27PrivateServicePlanVerify(consumer->plan);
    if (!status) {
        consumer->childVersion = token.val[7];
        if (consumer->mode == VM27ConsumerExplicitApprovedCode) status = VM27ApprovedCodeCheckReceivedMessage(consumer->approved, message, out);
        else status = VM27PrivateServicePlanCheckReceivedMessage(consumer->plan, message, &out->nativePolicy);
    }
    out->result = status; out->auditPID = token.val[5]; out->auditPIDVersion = token.val[7];
    if (!status) ++consumer->state.messagesAccepted;
    pthread_mutex_unlock(&consumer->mutex); return status;
}
int VM27PrivateServiceConsumerCopyState(VM27PrivateServiceConsumer *consumer, VM27PrivateConsumerState *out) {
    if (!consumer || !out) return EINVAL;
    pthread_mutex_lock(&consumer->mutex); *out = consumer->state; pthread_mutex_unlock(&consumer->mutex); return 0;
}
int VM27PrivateServiceConsumerWait(VM27PrivateServiceConsumer *consumer, bool block, VM27PrivateConsumerState *out) {
    if (!consumer || !out) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    if (!consumer->state.started || consumer->state.reaped || consumer->waiting) { pthread_mutex_unlock(&consumer->mutex); return EALREADY; }
    consumer->waiting = true; pid_t child = consumer->state.childPID; pthread_mutex_unlock(&consumer->mutex);
    int state = 0; pid_t actual; do { actual = waitpid(child, &state, block ? 0 : WNOHANG); } while (actual < 0 && errno == EINTR);
    int status = actual < 0 ? errno : actual == 0 ? EAGAIN : 0;
    pthread_mutex_lock(&consumer->mutex); consumer->waiting = false;
    if (!status) {
        consumer->state.reaped = actual == child; consumer->state.observedWaitExit = WIFEXITED(state) ? WEXITSTATUS(state) : -1;
        consumer->state.absent = kill(child, 0) == -1 && errno == ESRCH; atomic_fetch_add(&Reaps, 1);
    }
    *out = consumer->state; pthread_mutex_unlock(&consumer->mutex); return status;
}
void VM27PrivateServiceConsumerCopyStats(VM27PrivateConsumerStats *out) { if (out) *out = (VM27PrivateConsumerStats){atomic_load(&Created), atomic_load(&Destroyed), atomic_load(&Spawns), atomic_load(&Reaps), atomic_load(&MessageChecks)}; }
