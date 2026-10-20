#include "modern_cpu_config_os_object_v1.h"
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void VM27CPUConfigTestCountsV1(uint64_t *, uint64_t *);
static unsigned Checks;
#define CHECK(v) do { ++Checks; if (!(v)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #v); abort(); } } while (0)
static VM27CPUConfigSnapshotV1 Snapshot(VM27CPUConfigHandleV1 h) {
    VM27CPUConfigSnapshotV1 s;
    memset(&s, 0xa5, sizeof(s));
    CHECK(VM27CPUConfigCopyV1(h, &s) == 0);
    CHECK(s.schemaVersion == 1 && s.generation == h.generation &&
        !s.trapTLBISW && !s.supportKnown);
    return s;
}
typedef struct { VM27CPUConfigHandleV1 handle; unsigned failures; } Work;
static void *Worker(void *arg) {
    Work *w = arg;
    for (unsigned i = 0; i < 1024; ++i) {
        VM27CPUConfigSnapshotV1 s;
        if (VM27CPUConfigSetVMKeyV1(w->handle, i, ~((uint64_t)i)) ||
            VM27CPUConfigSetFGTV1(w->handle, i & 1) ||
            VM27CPUConfigCopyV1(w->handle, &s) ||
            s.vmKeyHigh != ~s.vmKeyLow || s.fineGrainedTraps > 1 ||
            s.trapTLBISW || s.supportKnown) ++w->failures;
    }
    CFRelease((CFTypeRef)w->handle.object);
    return NULL;
}
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("MAIN ordinary own OS_object config lifecycle; nativeHV=0\n");
    uint64_t beforeCreated, beforeDestroyed;
    VM27CPUConfigTestCountsV1(&beforeCreated, &beforeDestroyed);
    CHECK(beforeCreated == 0 && beforeDestroyed == 0);
    CHECK(VM27CPUConfigCreateV1(NULL) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
    VM27CPUConfigSnapshotV1 untouched, out;
    memset(&untouched, 0xa5, sizeof(untouched)); out = untouched;
    VM27CPUConfigHandleV1 foreign = {(void *)(uintptr_t)1, 1};
    CHECK(VM27CPUConfigCopyV1(foreign, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
    CHECK(!memcmp(&out, &untouched, sizeof(out)));
    CHECK(VM27CPUConfigSetTLBIV1(foreign, 1) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
    uint64_t previousGeneration = 0;
    for (unsigned i = 0; i < 128; ++i) {
        VM27CPUConfigHandleV1 h = {0};
        CHECK(VM27CPUConfigCreateV1(&h) == 0 && h.object &&
            h.generation > previousGeneration);
        previousGeneration = h.generation;
        CHECK(object_getClass((id)h.object) == objc_getClass("OS_VM27CPUConfigV1"));
        CHECK(class_getSuperclass(object_getClass((id)h.object)) == objc_getClass("OS_object"));
        CHECK(class_getInstanceSize(object_getClass((id)h.object)) == 8);
        VM27CPUConfigSnapshotV1 initial = Snapshot(h);
        CHECK(!initial.vmKeyLow && !initial.vmKeyHigh && !initial.fineGrainedTraps);
        CHECK(VM27CPUConfigSetVMKeyV1(h, i, UINT64_MAX-i) == 0);
        CHECK(VM27CPUConfigSetFGTV1(h, 1) == 0);
        VM27CPUConfigSnapshotV1 set = Snapshot(h);
        CHECK(set.vmKeyLow == i && set.vmKeyHigh == UINT64_MAX-i && set.fineGrainedTraps == 1);
        CHECK(VM27CPUConfigSetFGTV1(h, 2) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        CHECK(VM27CPUConfigSetTLBIV1(h, 2) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        CHECK(VM27CPUConfigSetTLBIV1(h, 1) == VM27_CPU_CONFIG_UNSUPPORTED_V1);
        CHECK(VM27CPUConfigSetTLBIV1(h, 0) == 0);
        VM27CPUConfigSnapshotV1 same = Snapshot(h);
        CHECK(!memcmp(&set, &same, sizeof(set)));
        CHECK(VM27CPUConfigCreateV1((VM27CPUConfigHandleV1 *)(uintptr_t)h.object) ==
            VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        CHECK(VM27CPUConfigCopyV1(h, (VM27CPUConfigSnapshotV1 *)((char *)h.object+8)) ==
            VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        VM27CPUConfigHandleV1 wrong = h; ++wrong.generation; out = untouched;
        CHECK(VM27CPUConfigCopyV1(wrong, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        CHECK(!memcmp(&out, &untouched, sizeof(out)));
        CHECK(CFRetain((CFTypeRef)h.object) == h.object);
        CFRelease((CFTypeRef)h.object);
        same = Snapshot(h); CHECK(!memcmp(&set, &same, sizeof(set)));
        CFRelease((CFTypeRef)h.object);
        out = untouched;
        CHECK(VM27CPUConfigCopyV1(h, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V1);
        CHECK(!memcmp(&out, &untouched, sizeof(out)));
    }
    VM27CPUConfigHandleV1 shared = {0}; CHECK(VM27CPUConfigCreateV1(&shared) == 0);
    CHECK(VM27CPUConfigSetVMKeyV1(shared, 0, UINT64_MAX) == 0);
    pthread_t threads[4]; Work works[4];
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(CFRetain((CFTypeRef)shared.object) == shared.object);
        works[i] = (Work){shared, 0};
        CHECK(pthread_create(&threads[i], NULL, Worker, &works[i]) == 0);
    }
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0); CHECK(!works[i].failures);
    }
    VM27CPUConfigSnapshotV1 sharedState = Snapshot(shared);
    CHECK(sharedState.vmKeyHigh == ~sharedState.vmKeyLow);
    CFRelease((CFTypeRef)shared.object);
    uint64_t created, destroyed; VM27CPUConfigTestCountsV1(&created, &destroyed);
    CHECK(created == 129 && destroyed == 129);
    printf("{\"checks\":%u,\"created\":%llu,\"destroyed\":%llu,"
        "\"realCFReferences\":true,\"realOSObjectAllocation\":true,"
        "\"actualPthreads\":4,\"nativeHVCalls\":0,\"deviceOperations\":0,"
        "\"currentTLBISupportKnown\":false,\"full27Backend\":false}\n",
        Checks, (unsigned long long)created, (unsigned long long)destroyed);
    return 0;
}
