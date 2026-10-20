/* Keep frozen V3 actual external1/3 reader and every V2 ownership/native gate.
 * New Spawn overrides only the parent-slot2-null restriction; its three child
 * attributes and full parent before/after equality remain exact. Apple XNU
 * xnu-8792.41.9 posix_spawn.c1971 / kern_exec.c2252 sets new child task only. */
#include "modern_xpc_large_private_consumer_v2.h"
#include <stdio.h>
__attribute__((visibility("hidden")))
int VM27LargePrivateServiceConsumerInheritedSpawnV3(VM27LargePrivateServiceConsumerV2 *,
    xpc_endpoint_t, char *const [], char *const [], pid_t *);
#define VM27LargePrivateServiceConsumerV2Spawn VM27LargePrivateServiceConsumerInheritedSpawnV3
#include "modern_xpc_large_private_consumer_v3.c"
#undef VM27LargePrivateServiceConsumerV2Spawn
int VM27LargePrivateServiceConsumerV2Spawn(VM27LargePrivateServiceConsumerV2 *consumer, xpc_endpoint_t endpoint,
                                   char *const argv[], char *const env[], pid_t *out) {
    if (!out) return EINVAL; *out = 0;
    if (!consumer || !endpoint || !BoundedStrings(argv, 17, 4096, false) || !argv[0] || strcmp(argv[0], consumer->info.executablePath) || !BoundedStrings(env, 129, 16384, true)) return EINVAL;
    pthread_mutex_lock(&consumer->mutex);
    int status = consumer->state.started ? EALREADY : VM27LargeServicePlanVerify(consumer->plan);
    mach_port_array_t before = NULL, after = NULL; mach_msg_type_number_t count = 0, afterCount = 0;
    mach_port_t inherited = MACH_PORT_NULL; posix_spawnattr_t attr; bool hasAttr = false;
    if (!status) {
        kern_return_t lookup = mach_ports_lookup(mach_task_self(), &before, &count);
        bool slot2Valid = lookup == KERN_SUCCESS && count == 3 && before && MACH_PORT_VALID(before[2]);
        fprintf(stderr, "[Independent27] consumer-spawn lookupKR=%d count=%u parentSlot2Valid=%d\n", lookup, count, slot2Valid);
        if (lookup != KERN_SUCCESS || count != 3 || !before) status = ENOTSUP;
    }
    if (!status) status = VM27PrivateEndpointCopySendRight(endpoint, &inherited);
    if (!status) { status = posix_spawnattr_init(&attr); hasAttr = !status; }
    if (!status) {
        mach_port_t registered[3] = {before[0], before[1], inherited};
        status = posix_spawnattr_set_registered_ports_np(&attr, registered, 3);
        fprintf(stderr, "[Independent27] consumer-spawn set-registered-ports status=%d\n", status);
    }
    if (!status) {
        pid_t child = 0; status = posix_spawn(&child, consumer->info.executablePath, NULL, &attr, argv, env);
        fprintf(stderr, "[Independent27] consumer-spawn posix-spawn status=%d child=%d\n", status, (int)child);
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
