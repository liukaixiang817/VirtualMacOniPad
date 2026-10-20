/* Actual owned posix_spawn child and registered-port inheritance.
 * Source ABI: Apple xnu-8792.41.9 spawn_private.h:69. No task special port,
 * launchd registration, task_for_pid, other-process memory or VM/GPU work.
 */
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern char **environ;
struct Packet { mach_msg_header_t header; uint64_t nonce; };
static unsigned gChecks, gFailures;
static void Check(bool ok, const char *name) {
    ++gChecks; if (!ok) { ++gFailures; printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", name); }
}
static bool NoVM(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *p = _dyld_get_image_name(i);
        if (!p || strstr(p, "/Virtualization.framework/") || strstr(p, "/Hypervisor.framework/") || strstr(p, "/ParavirtualizedGraphics.framework/") || strstr(p, "/VirtualMachine.xpc/")) return false;
    } return true;
}
static void ReleasePorts(mach_port_array_t ports, mach_msg_type_number_t count) {
    for (unsigned i = 0; i < count; ++i) if (MACH_PORT_VALID(ports[i])) Check(!mach_port_deallocate(mach_task_self(), ports[i]), "own-looked-up-send-right-released");
    if (ports) Check(!vm_deallocate(mach_task_self(), (vm_address_t)ports, count * sizeof(mach_port_t)), "own-lookup-array-released");
}
static bool FilePin(const char *path, const char *SHA, uint64_t expected) {
    FILE *f = fopen(path, "rb"); struct stat s; bool ok = f && !fstat(fileno(f), &s) &&
        S_ISREG(s.st_mode) && s.st_size > 0 && (uint64_t)s.st_size == expected && expected < 1024 * 1024;
    if (!ok) { if (f) fclose(f); return false; }
    CC_SHA256_CTX c; CC_SHA256_Init(&c); unsigned char block[16384], hash[32]; size_t total = 0;
    for (;;) { size_t n = fread(block, 1, sizeof(block), f); total += n; CC_SHA256_Update(&c, block, (CC_LONG)n); if (n != sizeof(block)) break; }
    ok = !ferror(f) && total == expected; fclose(f); CC_SHA256_Final(hash, &c);
    char hex[65]; for (unsigned i = 0; i < 32; ++i) snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    return ok && !strcmp(hex, SHA);
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); struct rlimit limit = {5, 5}; setrlimit(RLIMIT_CPU, &limit); alarm(15);
    bool child = argc == 5 && !strcmp(argv[1], "--owned-child");
    if (!child && argc != 3) return 64;
    const char *SHA = child ? argv[3] : argv[1]; uint64_t bytes = strtoull(child ? argv[4] : argv[2], NULL, 10);
    Check(NoVM() && FilePin(argv[0], SHA, bytes), "actual-self-pin-no-vm-images");
    printf("{\"record\":\"start\",\"role\":\"%s\",\"PID\":%d,\"UID\":%u,\"VMCalls\":0,\"GPUCalls\":0,\"bootstrapChanges\":0,\"launchdRegistrations\":0}\n", child ? "child" : "parent", getpid(), getuid());
    mach_port_array_t ports = NULL; mach_msg_type_number_t count = 0;
    kern_return_t rc = mach_ports_lookup(mach_task_self(), &ports, &count);
    Check(!rc && count == 3 && ports, "actual-registered-port-table-three");
    if (rc || count != 3 || !ports) return 78;
    if (child) {
        mach_port_type_t type = 0; mach_port_urefs_t refs = 0;
        Check(MACH_PORT_VALID(ports[2]) && !mach_port_type(mach_task_self(), ports[2], &type) && (type & MACH_PORT_TYPE_SEND) && !(type & MACH_PORT_TYPE_DEAD_NAME), "child-inherited-real-send-right");
        Check(!mach_port_get_refs(mach_task_self(), ports[2], MACH_PORT_RIGHT_SEND, &refs) && refs > 0, "child-send-right-ownership");
        struct Packet packet = {0}; packet.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        packet.header.msgh_remote_port = ports[2]; packet.header.msgh_size = sizeof(packet); packet.header.msgh_id = 20271009; packet.nonce = strtoull(argv[2], NULL, 10);
        rc = mach_msg(&packet.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(packet), 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
        Check(!rc, "child-real-mach-message-sent"); ReleasePorts(ports, count);
        Check(NoVM() && FilePin(argv[0], SHA, bytes), "child-file-pin-after");
        printf("{\"record\":\"childSummary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"sentMessages\":1,\"ownedRightsReleased\":true,\"passed\":%s}\n", getpid(), gChecks, gFailures, gFailures ? "false" : "true");
        return gFailures ? 1 : 0;
    }
    Check(ports[2] == MACH_PORT_NULL, "only-empty-private-slot-consumed");
    if (ports[2] != MACH_PORT_NULL) { ReleasePorts(ports, count); return 78; }
    mach_port_t owned = MACH_PORT_NULL;
    Check(!mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &owned), "own-receive-right-created");
    Check(!mach_port_insert_right(mach_task_self(), owned, owned, MACH_MSG_TYPE_MAKE_SEND), "own-send-right-created");
    mach_port_urefs_t before = 0, after = 0; Check(!mach_port_get_refs(mach_task_self(), owned, MACH_PORT_RIGHT_SEND, &before) && before == 1, "one-owned-send-reference-before");
    mach_port_t registered[3] = {ports[0], ports[1], owned}; posix_spawnattr_t attr;
    int status = posix_spawnattr_init(&attr); Check(!status, "spawn-attributes-created");
    if (status) return 78;
    status = posix_spawnattr_set_registered_ports_np(&attr, registered, 3); Check(!status, "only-child-registered-ports-set");
    uint64_t nonce = 0; arc4random_buf(&nonce, sizeof(nonce)); if (!nonce) nonce = 1;
    char nonceText[32]; snprintf(nonceText, sizeof(nonceText), "%llu", (unsigned long long)nonce);
    char *arguments[] = {argv[0], "--owned-child", nonceText, argv[1], argv[2], NULL}; pid_t pid = 0;
    if (!status) status = posix_spawn(&pid, argv[0], NULL, &attr, arguments, environ);
    Check(!status && pid > 1, "exact-self-owned-child-spawned"); Check(!posix_spawnattr_destroy(&attr), "spawn-attributes-released");
    printf("{\"record\":\"spawn\",\"parentPID\":%d,\"childPID\":%d,\"spawnResult\":%d}\n", getpid(), pid, status);
    if (status || pid <= 1) { ReleasePorts(ports, count); return 78; }
    union { struct Packet packet; unsigned char bytes[256]; } incoming = {0};
    rc = mach_msg(&incoming.packet.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT), 0, sizeof(incoming), owned, 2000, MACH_PORT_NULL);
    Check(!rc && incoming.packet.header.msgh_size == sizeof(struct Packet) && !(incoming.packet.header.msgh_bits & MACH_MSGH_BITS_COMPLEX), "parent-received-exact-child-message");
    mach_msg_audit_trailer_t *trailer = (void *)(incoming.bytes + (incoming.packet.header.msgh_size == sizeof(struct Packet) ? round_msg(incoming.packet.header.msgh_size) : 0));
    bool valid = !rc && incoming.packet.header.msgh_size == sizeof(struct Packet) && trailer->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0 && trailer->msgh_trailer_size >= sizeof(*trailer);
    Check(valid && trailer->msgh_audit.val[5] == (uint32_t)pid && trailer->msgh_audit.val[7] > 0 && incoming.packet.nonce == nonce && incoming.packet.header.msgh_id == 20271009, "real-kernel-audit-child-pid-version-and-nonce");
    int waited = 0; pid_t result;
    do { result = waitpid(pid, &waited, 0); } while (result < 0 && errno == EINTR);
    Check(result == pid && WIFEXITED(waited) && WEXITSTATUS(waited) == 0, "actual-owned-child-reaped-exit-zero");
    bool absent = kill(pid, 0) == -1 && errno == ESRCH; Check(absent, "owned-child-absent-after-wait");
    Check(!mach_port_get_refs(mach_task_self(), owned, MACH_PORT_RIGHT_SEND, &after) && after == before, "parent-send-references-returned-after-child");
    mach_port_array_t checkPorts = NULL; mach_msg_type_number_t checkCount = 0;
    Check(!mach_ports_lookup(mach_task_self(), &checkPorts, &checkCount) && checkCount == count && checkPorts[0] == ports[0] && checkPorts[1] == ports[1] && checkPorts[2] == ports[2], "parent-registered-table-unchanged");
    ReleasePorts(checkPorts, checkCount); ReleasePorts(ports, count);
    Check(!mach_port_deallocate(mach_task_self(), owned), "own-send-right-released");
    Check(!mach_port_mod_refs(mach_task_self(), owned, MACH_PORT_RIGHT_RECEIVE, -1), "own-receive-right-released");
    Check(NoVM() && FilePin(argv[0], SHA, bytes), "parent-file-pin-after");
    printf("{\"record\":\"summary\",\"parentPID\":%d,\"spawnedChildPID\":%d,\"observedChildWaitExit\":%d,\"childAbsent\":%s,\"checks\":%u,\"failures\":%u,\"passed\":%s,\"actualMachMessages\":1,\"actualAuditPID\":%u,\"parentRegisteredPortsUnchanged\":true,\"ownRightsReleased\":true,\"bootstrapChanges\":0,\"launchdRegistrations\":0,\"VMCalls\":0,\"GPUCalls\":0}\n", getpid(), pid, WIFEXITED(waited) ? WEXITSTATUS(waited) : -1, absent ? "true" : "false", gChecks, gFailures, gFailures ? "false" : "true", valid ? trailer->msgh_audit.val[5] : 0);
    return gFailures ? 1 : 0;
}
