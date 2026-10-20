#include "modern_cpu_config_os_object_v2.h"
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <os/object.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

extern id _os_object_alloc(Class, size_t);

// No ivars: inherited OS_object's private +8/+12 reference counts must never
// be replaced by compiler ivars. The genuine allocator requests 48 bytes.
@interface OS_VM27CPUConfigV2 : OS_object
@end

typedef struct {
    uintptr_t isaForLayoutOnly;
    uint32_t internalRefsForLayoutOnly, externalRefsForLayoutOnly;
    uint64_t vmKeyLow, vmKeyHigh;
    uint8_t fineGrainedTraps, trapTLBISW;
    uint8_t reserved[6];
    uint64_t generation;
} OwnedConfigBytesV2;
_Static_assert(sizeof(OwnedConfigBytesV2) == 48, "Owned 48-byte allocation");
_Static_assert(offsetof(OwnedConfigBytesV2, vmKeyLow) == 16 &&
    offsetof(OwnedConfigBytesV2, fineGrainedTraps) == 32 &&
    offsetof(OwnedConfigBytesV2, trapTLBISW) == 33 &&
    offsetof(OwnedConfigBytesV2, generation) == 40, "Explicit owned payload");

typedef struct EntryV2 {
    struct EntryV2 *next;
    const void *object;
    uint64_t generation;
} EntryV2;
static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static EntryV2 *Registry;
static uint64_t NextGeneration = 1;
#if VM27_CPU_CONFIG_TESTING
static _Atomic uint64_t TestCreated, TestDestroyed;
void VM27CPUConfigTestCountsV2(uint64_t *created, uint64_t *destroyed) {
    *created = atomic_load_explicit(&TestCreated, memory_order_relaxed);
    *destroyed = atomic_load_explicit(&TestDestroyed, memory_order_relaxed);
}
#endif

static bool Overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return !a || !b || x > UINTPTR_MAX - an || y > UINTPTR_MAX - bn ||
        (x < y + bn && y < x + an);
}
// RegistryMutex is held by the caller. Every live own allocation is protected,
// including a different configuration from the one being read.
static bool OutputDisjointLocked(const void *out, size_t bytes) {
    for (EntryV2 *entry = Registry; entry; entry = entry->next)
        if (Overlap(out, bytes, entry->object, 48) ||
            Overlap(out, bytes, entry, sizeof(*entry))) return false;
    return true;
}
static EntryV2 *Find(VM27CPUConfigHandleV2 handle) {
    if (!handle.object || !handle.generation) return NULL;
    for (EntryV2 *e = Registry; e; e = e->next)
        if (e->object == handle.object && e->generation == handle.generation)
            return e;
    return NULL;
}

@implementation OS_VM27CPUConfigV2
- (void)dealloc {
    // The object remains allocated while waiting for this lock. Ordinary API
    // operations hold the same lock; removal precedes super's actual free.
    if (pthread_mutex_lock(&RegistryMutex)) abort();
    EntryV2 **p = &Registry;
    while (*p && (*p)->object != self) p = &(*p)->next;
    EntryV2 *entry = *p;
    if (entry) *p = entry->next;
    OwnedConfigBytesV2 *bytes = (OwnedConfigBytesV2 *)(void *)self;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    free(entry);
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestDestroyed, 1, memory_order_relaxed);
#endif
    [super dealloc];
}
@end

VM27CPUConfigStatusV2 VM27CPUConfigCreateV2(VM27CPUConfigHandleV2 *out) {
    if (!out || (uintptr_t)out > UINTPTR_MAX - sizeof(*out))
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V2;
    bool aliased = !OutputDisjointLocked(out, sizeof(*out));
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    if (aliased) return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    EntryV2 *entry = calloc(1, sizeof(*entry));
    if (!entry) return VM27_CPU_CONFIG_ERROR_V2;
    // The exact own class has 8 bytes of runtime instance storage; allocation
    // adds 40 bytes. No -init call is made (genuine OS_object init traps).
    Class cls = [OS_VM27CPUConfigV2 class];
    if (class_getInstanceSize(cls) != 8) {
        free(entry); return VM27_CPU_CONFIG_UNSUPPORTED_V2;
    }
    id object = _os_object_alloc(cls, 48);
    if (!object) { free(entry); return VM27_CPU_CONFIG_ERROR_V2; }
    OwnedConfigBytesV2 *bytes = (OwnedConfigBytesV2 *)(void *)object;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_lock(&RegistryMutex)) {
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_ERROR_V2;
    }
    if (!NextGeneration || NextGeneration == UINT64_MAX) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_UNSUPPORTED_V2;
    }
    entry->object = object; entry->generation = NextGeneration++;
    bytes->generation = entry->generation;
    entry->next = Registry; Registry = entry;
    VM27CPUConfigHandleV2 handle = {object, entry->generation};
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestCreated, 1, memory_order_relaxed);
#endif
    *out = handle;
    return VM27_CPU_CONFIG_OK_V2;
}

static VM27CPUConfigStatusV2 Enter(VM27CPUConfigHandleV2 handle,
    EntryV2 **entry, OwnedConfigBytesV2 **bytes) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V2;
    *entry = Find(handle);
    if (!*entry || object_getClass((id)handle.object) !=
        [OS_VM27CPUConfigV2 class]) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    }
    *bytes = (OwnedConfigBytesV2 *)(void *)handle.object;
    if ((*bytes)->generation != handle.generation) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    }
    return VM27_CPU_CONFIG_OK_V2;
}
static void Leave(void) {
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
}
VM27CPUConfigStatusV2 VM27CPUConfigCopyV2(VM27CPUConfigHandleV2 handle,
    VM27CPUConfigSnapshotV2 *out) {
    if (!out) return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    EntryV2 *entry; OwnedConfigBytesV2 *bytes;
    VM27CPUConfigStatusV2 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (!OutputDisjointLocked(out, sizeof(*out))) {
        Leave(); return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    }
    VM27CPUConfigSnapshotV2 value = {1, bytes->fineGrainedTraps,
        bytes->trapTLBISW, 0, bytes->vmKeyLow, bytes->vmKeyHigh,
        bytes->generation};
    *out = value;
    Leave(); return VM27_CPU_CONFIG_OK_V2;
}
VM27CPUConfigStatusV2 VM27CPUConfigSetVMKeyV2(VM27CPUConfigHandleV2 handle,
    uint64_t low, uint64_t high) {
    EntryV2 *entry; OwnedConfigBytesV2 *bytes;
    VM27CPUConfigStatusV2 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->vmKeyLow = low; bytes->vmKeyHigh = high;
    Leave(); return VM27_CPU_CONFIG_OK_V2;
}
VM27CPUConfigStatusV2 VM27CPUConfigSetFGTV2(VM27CPUConfigHandleV2 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    EntryV2 *entry; OwnedConfigBytesV2 *bytes;
    VM27CPUConfigStatusV2 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->fineGrainedTraps = (uint8_t)enabled;
    Leave(); return VM27_CPU_CONFIG_OK_V2;
}
VM27CPUConfigStatusV2 VM27CPUConfigSetTLBIV2(VM27CPUConfigHandleV2 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V2;
    EntryV2 *entry; OwnedConfigBytesV2 *bytes;
    VM27CPUConfigStatusV2 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (enabled) { Leave(); return VM27_CPU_CONFIG_UNSUPPORTED_V2; }
    bytes->trapTLBISW = 0;
    Leave(); return VM27_CPU_CONFIG_OK_V2;
}
