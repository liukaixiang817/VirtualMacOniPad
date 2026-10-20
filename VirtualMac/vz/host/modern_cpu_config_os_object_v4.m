#include "modern_cpu_config_os_object_v3.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include "modern_cpu_config_os_object_v4_private.h"
#include "modern_cpu_config_capability_acquisition_v1.h"
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
@interface OS_VM27CPUConfigV3 : OS_object
@end

typedef struct {
    uintptr_t isaForLayoutOnly;
    uint32_t internalRefsForLayoutOnly, externalRefsForLayoutOnly;
    uint64_t vmKeyLow, vmKeyHigh;
    uint8_t fineGrainedTraps, trapTLBISW;
    uint8_t reserved[6];
    uint64_t generation;
} OwnedConfigBytesV3;
_Static_assert(sizeof(OwnedConfigBytesV3) == 48, "Owned 48-byte allocation");
_Static_assert(offsetof(OwnedConfigBytesV3, vmKeyLow) == 16 &&
    offsetof(OwnedConfigBytesV3, fineGrainedTraps) == 32 &&
    offsetof(OwnedConfigBytesV3, trapTLBISW) == 33 &&
    offsetof(OwnedConfigBytesV3, generation) == 40, "Explicit owned payload");

typedef struct EntryV3 {
    struct EntryV3 *next;
    const void *object;
    uint64_t generation;
    bool queryInProgress, supportKnown;
} EntryV3;
struct VM27CPUConfigBorrowV3 {
    struct VM27CPUConfigBorrowV3 *next;
    const void *object;
    pthread_t owner;
    VM27CPUConfigSnapshotV3 snapshot;
};
static VM27CPUConfigBorrowV3 *Borrows;
static pthread_mutex_t RegistryMutex = PTHREAD_MUTEX_INITIALIZER;
static EntryV3 *Registry;
static uint64_t NextGeneration = 1;
#if VM27_CPU_CONFIG_TESTING
static _Atomic uint64_t TestCreated, TestDestroyed;
void VM27CPUConfigTestCountsV3(uint64_t *created, uint64_t *destroyed) {
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
    if (!out || (uintptr_t)out > UINTPTR_MAX - bytes) return false;
    for (EntryV3 *entry = Registry; entry; entry = entry->next)
        if (Overlap(out, bytes, entry->object, 48) ||
            Overlap(out, bytes, entry, sizeof(*entry))) return false;
    for (VM27CPUConfigBorrowV3 *borrow = Borrows; borrow; borrow = borrow->next)
        if (Overlap(out, bytes, borrow, sizeof(*borrow))) return false;
    return true;
}
__attribute__((visibility("hidden")))
bool VM27CPUConfigOutputRangeDisjointV3(const void *out, size_t bytes) {
    if (pthread_mutex_lock(&RegistryMutex)) return false;
    bool valid = OutputDisjointLocked(out,bytes);
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    return valid;
}
static EntryV3 *Find(VM27CPUConfigHandleV3 handle) {
    if (!handle.object || !handle.generation) return NULL;
    for (EntryV3 *e = Registry; e; e = e->next)
        if (e->object == handle.object && e->generation == handle.generation)
            return e;
    return NULL;
}

@implementation OS_VM27CPUConfigV3
- (void)dealloc {
    // The object remains allocated while waiting for this lock. Ordinary API
    // operations hold the same lock; removal precedes super's actual free.
    if (pthread_mutex_lock(&RegistryMutex)) abort();
    EntryV3 **p = &Registry;
    while (*p && (*p)->object != self) p = &(*p)->next;
    EntryV3 *entry = *p;
    if (entry) *p = entry->next;
    OwnedConfigBytesV3 *bytes = (OwnedConfigBytesV3 *)(void *)self;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    free(entry);
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestDestroyed, 1, memory_order_relaxed);
#endif
    [super dealloc];
}
@end

VM27CPUConfigStatusV3 VM27CPUConfigCreateV3(VM27CPUConfigHandleV3 *out) {
    if (!out || (uintptr_t)out > UINTPTR_MAX - sizeof(*out))
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    if (!VM27CPUFactoryOutputRangeDisjointV3(out,sizeof(*out))) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V3;
    bool aliased = !OutputDisjointLocked(out, sizeof(*out));
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
    if (aliased) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    EntryV3 *entry = calloc(1, sizeof(*entry));
    if (!entry) return VM27_CPU_CONFIG_ERROR_V3;
    // The exact own class has 8 bytes of runtime instance storage; allocation
    // adds 40 bytes. No -init call is made (genuine OS_object init traps).
    Class cls = [OS_VM27CPUConfigV3 class];
    if (class_getInstanceSize(cls) != 8) {
        free(entry); return VM27_CPU_CONFIG_UNSUPPORTED_V3;
    }
    id object = _os_object_alloc(cls, 48);
    if (!object) { free(entry); return VM27_CPU_CONFIG_ERROR_V3; }
    OwnedConfigBytesV3 *bytes = (OwnedConfigBytesV3 *)(void *)object;
    memset((unsigned char *)bytes + 16, 0, sizeof(*bytes) - 16);
    if (pthread_mutex_lock(&RegistryMutex)) {
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_ERROR_V3;
    }
    if (!NextGeneration || NextGeneration == UINT64_MAX) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        CFRelease((CFTypeRef)object); free(entry);
        return VM27_CPU_CONFIG_UNSUPPORTED_V3;
    }
    entry->object = object; entry->generation = NextGeneration++;
    bytes->generation = entry->generation;
    entry->next = Registry; Registry = entry;
    VM27CPUConfigHandleV3 handle = {object, entry->generation};
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
#if VM27_CPU_CONFIG_TESTING
    atomic_fetch_add_explicit(&TestCreated, 1, memory_order_relaxed);
#endif
    *out = handle;
    return VM27_CPU_CONFIG_OK_V3;
}

static VM27CPUConfigStatusV3 Enter(VM27CPUConfigHandleV3 handle,
    EntryV3 **entry, OwnedConfigBytesV3 **bytes) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V3;
    *entry = Find(handle);
    if (!*entry || object_getClass((id)handle.object) !=
        [OS_VM27CPUConfigV3 class]) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    }
    if ((*entry)->queryInProgress) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BUSY_V3;
    }
    *bytes = (OwnedConfigBytesV3 *)(void *)handle.object;
    if ((*bytes)->generation != handle.generation) {
        if (pthread_mutex_unlock(&RegistryMutex)) abort();
        return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    }
    return VM27_CPU_CONFIG_OK_V3;
}
static void Leave(void) {
    if (pthread_mutex_unlock(&RegistryMutex)) abort();
}
VM27CPUConfigStatusV3 VM27CPUConfigCopyV3(VM27CPUConfigHandleV3 handle,
    VM27CPUConfigSnapshotV3 *out) {
    if (!VM27CPUFactoryOutputRangeDisjointV3(out,sizeof(*out))) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    EntryV3 *entry; OwnedConfigBytesV3 *bytes;
    VM27CPUConfigStatusV3 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (!OutputDisjointLocked(out, sizeof(*out))) {
        Leave(); return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    }
    VM27CPUConfigSnapshotV3 value = {1, bytes->fineGrainedTraps,
        bytes->trapTLBISW, entry->supportKnown, bytes->vmKeyLow, bytes->vmKeyHigh,
        bytes->generation};
    *out = value;
    Leave(); return VM27_CPU_CONFIG_OK_V3;
}
VM27CPUConfigStatusV3 VM27CPUConfigSetVMKeyV3(VM27CPUConfigHandleV3 handle,
    uint64_t low, uint64_t high) {
    EntryV3 *entry; OwnedConfigBytesV3 *bytes;
    VM27CPUConfigStatusV3 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->vmKeyLow = low; bytes->vmKeyHigh = high;
    Leave(); return VM27_CPU_CONFIG_OK_V3;
}
VM27CPUConfigStatusV3 VM27CPUConfigSetFGTV3(VM27CPUConfigHandleV3 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    EntryV3 *entry; OwnedConfigBytesV3 *bytes;
    VM27CPUConfigStatusV3 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    bytes->fineGrainedTraps = (uint8_t)enabled;
    Leave(); return VM27_CPU_CONFIG_OK_V3;
}
VM27CPUConfigStatusV3 VM27CPUConfigSetTLBIV3(VM27CPUConfigHandleV3 handle,
    uint32_t enabled) {
    if (enabled > 1) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    EntryV3 *entry; OwnedConfigBytesV3 *bytes;
    VM27CPUConfigStatusV3 status = Enter(handle, &entry, &bytes);
    if (status) return status;
    if (!enabled) { bytes->trapTLBISW = 0; Leave(); return VM27_CPU_CONFIG_OK_V3; }
    entry->queryInProgress = true;
    Leave();
    VM27CPUTLBICapabilityValueV1 capability = {false,false};
    VM27CPUConfigAcquireTLBICapabilityV1(&capability);
    if (pthread_mutex_lock(&RegistryMutex)) abort();
    // The API contract requires the caller's real CF reference throughout.
    EntryV3 *current = Find(handle);
    if (current != entry || !entry->queryInProgress) abort();
    entry->queryInProgress = false;
    if (!capability.known || !capability.supported) {
        Leave(); return VM27_CPU_CONFIG_UNSUPPORTED_V3;
    }
    bytes->trapTLBISW = 1; entry->supportKnown = true;
    Leave(); return VM27_CPU_CONFIG_OK_V3;
}

static EntryV3 *FindObjectLocked(const void *object) {
    if (!object) return NULL;
    for (EntryV3 *entry = Registry; entry; entry = entry->next)
        if (entry->object == object) return entry;
    return NULL;
}
const void *VM27CPUConfigCreateObjectV3(void) {
    VM27CPUConfigHandleV3 handle = {0};
    return VM27CPUConfigCreateV3(&handle) == 0 ? handle.object : NULL;
}
VM27CPUConfigStatusV3 VM27CPUConfigSetTLBIObjectV3(const void *object, bool enabled) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V3;
    EntryV3 *entry = FindObjectLocked(object);
    VM27CPUConfigHandleV3 handle = {object, entry ? entry->generation : 0};
    Leave();
    return VM27CPUConfigSetTLBIV3(handle, enabled ? 1 : 0);
}
VM27CPUConfigStatusV3 VM27CPUConfigBorrowObjectV3(const void *object,
    VM27CPUConfigBorrowV3 **out) {
    if (!VM27CPUFactoryOutputRangeDisjointV3(out,sizeof(*out))) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    VM27CPUConfigBorrowV3 *borrow = calloc(1, sizeof(*borrow));
    if (!borrow) return VM27_CPU_CONFIG_ERROR_V3;
    if (pthread_mutex_lock(&RegistryMutex)) { free(borrow); return VM27_CPU_CONFIG_ERROR_V3; }
    EntryV3 *entry = FindObjectLocked(object);
    VM27CPUConfigStatusV3 status = !entry ? VM27_CPU_CONFIG_BAD_ARGUMENT_V3 :
        entry->queryInProgress ? VM27_CPU_CONFIG_BUSY_V3 : VM27_CPU_CONFIG_OK_V3;
    if (!status && (!OutputDisjointLocked(out, sizeof(*out)) ||
        object_getClass((id)object) != [OS_VM27CPUConfigV3 class])) status = VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    if (!status) {
        OwnedConfigBytesV3 *bytes = (OwnedConfigBytesV3 *)(void *)object;
        if (bytes->generation != entry->generation) status = VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
        else {
            // The actual own class has no retain override. This is the closed
            // CF type0/ObjC xref path, with a caller-owned real CF reference.
            if (CFRetain((CFTypeRef)object) != object) abort();
            borrow->object = object; borrow->owner = pthread_self();
            borrow->snapshot = (VM27CPUConfigSnapshotV3){1,bytes->fineGrainedTraps,
                bytes->trapTLBISW,entry->supportKnown,bytes->vmKeyLow,bytes->vmKeyHigh,entry->generation};
            borrow->next = Borrows; Borrows = borrow; *out = borrow;
        }
    }
    Leave(); if (status) free(borrow); return status;
}
static VM27CPUConfigBorrowV3 **BorrowLinkLocked(VM27CPUConfigBorrowV3 *borrow) {
    VM27CPUConfigBorrowV3 **link = &Borrows;
    while (*link && *link != borrow) link = &(*link)->next;
    return *link ? link : NULL;
}
VM27CPUConfigStatusV3 VM27CPUConfigReadBorrowV3(VM27CPUConfigBorrowV3 *borrow,
    VM27CPUConfigSnapshotV3 *out) {
    if (!VM27CPUFactoryOutputRangeDisjointV3(out,sizeof(*out)) || pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_BAD_ARGUMENT_V3;
    VM27CPUConfigBorrowV3 **link = BorrowLinkLocked(borrow);
    VM27CPUConfigStatusV3 status = !link || !pthread_equal(borrow->owner,pthread_self()) ||
        !OutputDisjointLocked(out,sizeof(*out)) ? VM27_CPU_CONFIG_BAD_ARGUMENT_V3 : VM27_CPU_CONFIG_OK_V3;
    if (!status) *out = borrow->snapshot;
    Leave(); return status;
}
VM27CPUConfigStatusV3 VM27CPUConfigReleaseBorrowV3(VM27CPUConfigBorrowV3 *borrow) {
    if (pthread_mutex_lock(&RegistryMutex)) return VM27_CPU_CONFIG_ERROR_V3;
    VM27CPUConfigBorrowV3 **link = BorrowLinkLocked(borrow);
    if (!link || !pthread_equal(borrow->owner,pthread_self())) { Leave(); return VM27_CPU_CONFIG_BAD_ARGUMENT_V3; }
    *link = borrow->next; const void *object = borrow->object;
    memset(borrow,0,sizeof(*borrow)); Leave(); free(borrow); CFRelease((CFTypeRef)object);
    return VM27_CPU_CONFIG_OK_V3;
}
