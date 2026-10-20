#include "modern_cpu_config_os_object_v2.h"
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void VM27CPUConfigTestCountsV2(uint64_t *, uint64_t *);
static unsigned Checks;
#define CHECK(v) do { ++Checks; if (!(v)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #v); abort(); } } while (0)
static VM27CPUConfigSnapshotV2 Snapshot(VM27CPUConfigHandleV2 h) {
    VM27CPUConfigSnapshotV2 s;
    memset(&s, 0xa5, sizeof(s));
    CHECK(VM27CPUConfigCopyV2(h, &s) == 0);
    CHECK(s.schemaVersion == 1 && s.generation == h.generation &&
        !s.trapTLBISW && !s.supportKnown);
    return s;
}
typedef struct { VM27CPUConfigHandleV2 handle; unsigned failures; } Work;
static void *Worker(void *arg) {
    Work *w = arg;
    for (unsigned i = 0; i < 1024; ++i) {
        VM27CPUConfigSnapshotV2 s;
        if (VM27CPUConfigSetVMKeyV2(w->handle, i, ~((uint64_t)i)) ||
            VM27CPUConfigSetFGTV2(w->handle, i & 1) ||
            VM27CPUConfigCopyV2(w->handle, &s) ||
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
    VM27CPUConfigTestCountsV2(&beforeCreated, &beforeDestroyed);
    CHECK(beforeCreated == 0 && beforeDestroyed == 0);
    CHECK(VM27CPUConfigCreateV2(NULL) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
    VM27CPUConfigSnapshotV2 untouched, out;
    memset(&untouched, 0xa5, sizeof(untouched)); out = untouched;
    VM27CPUConfigHandleV2 foreign = {(void *)(uintptr_t)1, 1};
    CHECK(VM27CPUConfigCopyV2(foreign, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
    CHECK(!memcmp(&out, &untouched, sizeof(out)));
    CHECK(VM27CPUConfigSetTLBIV2(foreign, 1) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
    // Two live allocations are needed: protecting only the input handle leaves
    // a foreign own object's ISA and reference counts exposed to output writes.
    VM27CPUConfigHandleV2 first = {0}, second = {0};
    CHECK(VM27CPUConfigCreateV2(&first) == 0);
    CHECK(VM27CPUConfigCreateV2(&second) == 0);
    unsigned char firstBytes[48], secondBytes[48];
    memcpy(firstBytes, first.object, sizeof(firstBytes));
    memcpy(secondBytes, second.object, sizeof(secondBytes));
    const unsigned aliases[] = {0, 8, 16, 32, 40};
    for (unsigned i = 0; i < sizeof(aliases)/sizeof(aliases[0]); ++i) {
        CHECK(VM27CPUConfigCopyV2(first, (VM27CPUConfigSnapshotV2 *)
            ((unsigned char *)second.object + aliases[i])) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(!memcmp(secondBytes, second.object, sizeof(secondBytes)));
        CHECK(!memcmp(firstBytes, first.object, sizeof(firstBytes)));
        CHECK(VM27CPUConfigCopyV2(second, (VM27CPUConfigSnapshotV2 *)
            ((unsigned char *)first.object + aliases[i])) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(!memcmp(secondBytes, second.object, sizeof(secondBytes)));
        CHECK(!memcmp(firstBytes, first.object, sizeof(firstBytes)));
    }
    CHECK(VM27CPUConfigCreateV2((VM27CPUConfigHandleV2 *)second.object) ==
        VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
    CHECK(!memcmp(secondBytes, second.object, sizeof(secondBytes)));
    out = untouched;
    CHECK(VM27CPUConfigCopyV2(first, &out) == 0 && out.generation == first.generation);
    CFRelease((CFTypeRef)first.object); CFRelease((CFTypeRef)second.object);
    uint64_t previousGeneration = 0;
    for (unsigned i = 0; i < 128; ++i) {
        VM27CPUConfigHandleV2 h = {0};
        CHECK(VM27CPUConfigCreateV2(&h) == 0 && h.object &&
            h.generation > previousGeneration);
        previousGeneration = h.generation;
        CHECK(object_getClass((id)h.object) == objc_getClass("OS_VM27CPUConfigV2"));
        CHECK(class_getSuperclass(object_getClass((id)h.object)) == objc_getClass("OS_object"));
        CHECK(class_getInstanceSize(object_getClass((id)h.object)) == 8);
        VM27CPUConfigSnapshotV2 initial = Snapshot(h);
        CHECK(!initial.vmKeyLow && !initial.vmKeyHigh && !initial.fineGrainedTraps);
        CHECK(VM27CPUConfigSetVMKeyV2(h, i, UINT64_MAX-i) == 0);
        CHECK(VM27CPUConfigSetFGTV2(h, 1) == 0);
        VM27CPUConfigSnapshotV2 set = Snapshot(h);
        CHECK(set.vmKeyLow == i && set.vmKeyHigh == UINT64_MAX-i && set.fineGrainedTraps == 1);
        CHECK(VM27CPUConfigSetFGTV2(h, 2) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(VM27CPUConfigSetTLBIV2(h, 2) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(VM27CPUConfigSetTLBIV2(h, 1) == VM27_CPU_CONFIG_UNSUPPORTED_V2);
        CHECK(VM27CPUConfigSetTLBIV2(h, 0) == 0);
        VM27CPUConfigSnapshotV2 same = Snapshot(h);
        CHECK(!memcmp(&set, &same, sizeof(set)));
        CHECK(VM27CPUConfigCreateV2((VM27CPUConfigHandleV2 *)(uintptr_t)h.object) ==
            VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(VM27CPUConfigCopyV2(h, (VM27CPUConfigSnapshotV2 *)((char *)h.object+8)) ==
            VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        VM27CPUConfigHandleV2 wrong = h; ++wrong.generation; out = untouched;
        CHECK(VM27CPUConfigCopyV2(wrong, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(!memcmp(&out, &untouched, sizeof(out)));
        CHECK(CFRetain((CFTypeRef)h.object) == h.object);
        CFRelease((CFTypeRef)h.object);
        same = Snapshot(h); CHECK(!memcmp(&set, &same, sizeof(set)));
        CFRelease((CFTypeRef)h.object);
        out = untouched;
        CHECK(VM27CPUConfigCopyV2(h, &out) == VM27_CPU_CONFIG_BAD_ARGUMENT_V2);
        CHECK(!memcmp(&out, &untouched, sizeof(out)));
    }
    VM27CPUConfigHandleV2 shared = {0}; CHECK(VM27CPUConfigCreateV2(&shared) == 0);
    CHECK(VM27CPUConfigSetVMKeyV2(shared, 0, UINT64_MAX) == 0);
    pthread_t threads[4]; Work works[4];
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(CFRetain((CFTypeRef)shared.object) == shared.object);
        works[i] = (Work){shared, 0};
        CHECK(pthread_create(&threads[i], NULL, Worker, &works[i]) == 0);
    }
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0); CHECK(!works[i].failures);
    }
    VM27CPUConfigSnapshotV2 sharedState = Snapshot(shared);
    CHECK(sharedState.vmKeyHigh == ~sharedState.vmKeyLow);
    CFRelease((CFTypeRef)shared.object);
    uint64_t created, destroyed; VM27CPUConfigTestCountsV2(&created, &destroyed);
    CHECK(created == 131 && destroyed == 131);
    printf("{\"checks\":%u,\"created\":%llu,\"destroyed\":%llu,"
        "\"realCFReferences\":true,\"realOSObjectAllocation\":true,"
        "\"actualPthreads\":4,\"nativeHVCalls\":0,\"deviceOperations\":0,"
        "\"currentTLBISupportKnown\":false,\"full27Backend\":false}\n",
        Checks, (unsigned long long)created, (unsigned long long)destroyed);
    return 0;
}
