#include "modern_cpu_config_os_object_v1.h"
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
@interface OS_VM27CPUConfigV1 : OS_object
@end

typedef struct {
    uintptr_t isaForLayoutOnly;
    uint32_t internalRefsForLayoutOnly, externalRefsForLayoutOnly;
    uint64_t vmKeyLow, vmKeyHigh;
    uint8_t fineGrainedTraps, trapTLBISW;
    uint8_t reserved[6];
    uint64_t generation;
} OwnedConfigBytesV1;
_Static_assert(sizeof(OwnedConfigBytesV1) == 48, "Owned 48-byte allocation");
_Static_assert(offsetof(OwnedConfigBytesV1, vmKeyLow) == 16 &&
    offsetof(OwnedConfigBytesV1, fineGrainedTraps) == 32 &&
    offsetof(OwnedConfigBytesV1, trapTLBISW) == 33 &&
    offsetof(OwnedConfigBytesV1, generation) == 40, "Explicit owned payload");

typedef struct EntryV1 {
    struct EntryV1 *next;
    const void *object;
    uint64_t generation;
} EntryV1;
static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static EntryV1 *Registry;
static uint64_t NextGeneration = 1;
#if VM27_CPU_CONFIG_TESTING
static _Atomic uint64_t TestCreated, TestDestroyed;
void VM27CPUConfigTestCountsV1(uint64_t *created, uint64_t *destroyed) {
    *created = atomic_load_explicit(&TestCreated, memory_order_relaxed);
    *destroyed = atomic_load_explicit(&TestDestroyed, memory_order_relaxed);
}
#endif

static bool Overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return !a || !b || x > UINTPTR_MAX - an || y > UINTPTR_MAX - bn ||
        (x < y + bn && y < x + an);
}
static EntryV1 *Find(VM27CPUConfigHandleV1 handle) {
    if (!handle.object || !handle.generation) return NULL;
    for (EntryV1 *e = Registry; e; e = e->next)
        if (e->object == handle.object && e->generation == handle.generation)
            return e;
    return NULL;
}

@implementation OS_VM27CPUConfigV1
- (void)dealloc {
    // The object remains allocated while waiting for this lock. Ordinary API
    // operations hold the same lock; removal precedes super's actual free.
    if (pthread_mutex_lock(&RegistryMutex)) abort();
    EntryV1 **p = &Registry;
    while (*p && (*p)->object != self) p = &(*p)->next;
    EntryV1 *entry = *p;
    if (entry) *p = entry->next;
    OwnedConfigBytesV1 *bytes = (OwnedConfigBytesV1 *)(void *)self;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    free(entry);
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestDestroyed, 1, memory_order_relaxed);
#endif
    [super dealloc];
}
@end

VM27CPUConfigStatusV1 VM27CPUConfigCreateV1(VM27CPUConfigHandleV1 *out) {
    if (!out || (uintptr_t)out > UINTPTR_MAX - sizeof(*out))
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V1;
    bool aliased = false;
    for (EntryV1 *e = Registry; e; e = e->next)
        if (Overlap(out, sizeof(*out), e->object, 48) ||
            Overlap(out, sizeof(*out), e, sizeof(*e))) { aliased = true; break; }
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    if (aliased) return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    EntryV1 *entry = calloc(1, sizeof(*entry));
    if (!entry) return VM27_CPU_CONFIG_ERROR_V1;
    // The exact own class has 8 bytes of runtime instance storage; allocation
    // adds 40 bytes. No -init call is made (genuine OS_object init traps).
    Class cls = [OS_VM27CPUConfigV1 class];
    if (class_getInstanceSize(cls) != 8) {
        free(entry); return VM27_CPU_CONFIG_UNSUPPORTED_V1;
    }
    id object = _os_object_alloc(cls, 48);
    if (!object) { free(entry); return VM27_CPU_CONFIG_ERROR_V1; }
    OwnedConfigBytesV1 *bytes = (OwnedConfigBytesV1 *)(void *)object;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_lock(&RegistryMutex)) {
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_ERROR_V1;
    }
    if (!NextGeneration || NextGeneration == UINT64_MAX) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_UNSUPPORTED_V1;
    }
    entry->object = object; entry->generation = NextGeneration++;
    bytes->generation = entry->generation;
    entry->next = Registry; Registry = entry;
    VM27CPUConfigHandleV1 handle = {object, entry->generation};
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestCreated, 1, memory_order_relaxed);
#endif
    *out = handle;
    return VM27_CPU_CONFIG_OK_V1;
}

static VM27CPUConfigStatusV1 Enter(VM27CPUConfigHandleV1 handle,
    EntryV1 **entry, OwnedConfigBytesV1 **bytes) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V1;
    *entry = Find(handle);
    if (!*entry || object_getClass((id)handle.object) !=
        [OS_VM27CPUConfigV1 class]) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    }
    *bytes = (OwnedConfigBytesV1 *)(void *)handle.object;
    if ((*bytes)->generation != handle.generation) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    }
    return VM27_CPU_CONFIG_OK_V1;
}
static void Leave(void) {
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
}
VM27CPUConfigStatusV1 VM27CPUConfigCopyV1(VM27CPUConfigHandleV1 handle,
    VM27CPUConfigSnapshotV1 *out) {
    if (!out) return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    EntryV1 *entry; OwnedConfigBytesV1 *bytes;
    VM27CPUConfigStatusV1 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (Overlap(out, sizeof(*out), handle.object, sizeof(*bytes)) ||
        Overlap(out, sizeof(*out), entry, sizeof(*entry))) {
        Leave(); return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    }
    VM27CPUConfigSnapshotV1 value = {1, bytes->fineGrainedTraps,
        bytes->trapTLBISW, 0, bytes->vmKeyLow, bytes->vmKeyHigh,
        bytes->generation};
    *out = value;
    Leave(); return VM27_CPU_CONFIG_OK_V1;
}
VM27CPUConfigStatusV1 VM27CPUConfigSetVMKeyV1(VM27CPUConfigHandleV1 handle,
    uint64_t low, uint64_t high) {
    EntryV1 *entry; OwnedConfigBytesV1 *bytes;
    VM27CPUConfigStatusV1 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->vmKeyLow = low; bytes->vmKeyHigh = high;
    Leave(); return VM27_CPU_CONFIG_OK_V1;
}
VM27CPUConfigStatusV1 VM27CPUConfigSetFGTV1(VM27CPUConfigHandleV1 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    EntryV1 *entry; OwnedConfigBytesV1 *bytes;
    VM27CPUConfigStatusV1 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->fineGrainedTraps = (uint8_t)enabled;
    Leave(); return VM27_CPU_CONFIG_OK_V1;
}
VM27CPUConfigStatusV1 VM27CPUConfigSetTLBIV1(VM27CPUConfigHandleV1 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V1;
    EntryV1 *entry; OwnedConfigBytesV1 *bytes;
    VM27CPUConfigStatusV1 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (enabled) { Leave(); return VM27_CPU_CONFIG_UNSUPPORTED_V1; }
    bytes->trapTLBISW = 0;
    Leave(); return VM27_CPU_CONFIG_OK_V1;
}
