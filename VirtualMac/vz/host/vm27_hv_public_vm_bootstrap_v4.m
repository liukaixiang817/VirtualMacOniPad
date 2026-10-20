#include "vm27_hv_public_vm_bootstrap_v4.h"
#include "modern_cpu_config_os_object_v4_private.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <os/object.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

extern id _os_object_alloc(Class, size_t);
@interface OS_VM27VMConfigV1 : OS_object
@end
typedef struct ConfigEntry {
    struct ConfigEntry *next;
    const void *object;
    uint64_t generation;
    VZKernelVMOptions options;
    bool inUse;
} ConfigEntry;
typedef struct {
    uintptr_t isaLayoutOnly;
    uint32_t internalRefsLayoutOnly, externalRefsLayoutOnly;
    uint64_t generation;
    VZKernelVMOptions options;
    unsigned char reserved[24];
} OwnConfigStorage;
_Static_assert(sizeof(OwnConfigStorage) == 64 && offsetof(OwnConfigStorage, generation) == 16,
    "Own OS object counts are untouched; exact64B allocation");
static pthread_mutex_t Mutex = PTHREAD_MUTEX_INITIALIZER;
static ConfigEntry *Configs;
typedef struct MapEntry {
    struct MapEntry *next;
    VM27CPUFactoryRAMV5 *ram;
    void *host;
    uint64_t guestAddress, bytes;
    bool cleanupOnly;
} MapEntry;
static MapEntry *Maps;
static uint64_t NextGeneration = 1;
static struct {
    VZKernelLifecycleOps ops;
    VZKernelInitWriter writer;
    VM27CPUFactoryVMV2 *vm;
    pthread_t owner;
    bool installed, vmDestroyed;
} Backend;
static _Atomic bool Admission;
#if VM27_HV_VM_TESTING
static _Atomic uint64_t Created, Destroyed;
void VM27HVVMTestConfigCountsV1(uint64_t *created, uint64_t *destroyed) {
    *created = atomic_load(&Created); *destroyed = atomic_load(&Destroyed);
}
#endif
static hv_return_t Error(uint32_t code) { return (hv_return_t)(UINT32_C(0xfae94000) | code); }
static void Lock(void) { if (pthread_mutex_lock(&Mutex)) abort(); }
static void Unlock(void) { if (pthread_mutex_unlock(&Mutex)) abort(); }
static bool Begin(void) {
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(&Admission, &expected, true,
        memory_order_acquire, memory_order_relaxed);
}
static void End(void) { atomic_store_explicit(&Admission, false, memory_order_release); }
static bool Disjoint(const void *a, size_t n, const void *b, size_t m) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x && y && n <= UINTPTR_MAX - x && m <= UINTPTR_MAX - y && (x + n <= y || y + m <= x);
}
static bool OutputLocked(const void *out, size_t n) {
    if (!out || !n || n > UINTPTR_MAX - (uintptr_t)out ||
        !Disjoint(out, n, &Backend, sizeof(Backend)) || !Disjoint(out, n, &Admission, sizeof(Admission)) ||
        !Disjoint(out, n, &NextGeneration, sizeof(NextGeneration)) ||
        !Disjoint(out, n, &Configs, sizeof(Configs)) || !Disjoint(out, n, &Maps, sizeof(Maps)) ||
        !Disjoint(out, n, &Mutex, sizeof(Mutex))) return false;
    for (ConfigEntry *entry = Configs; entry; entry = entry->next)
        if (!Disjoint(out, n, entry, sizeof(*entry)) || !Disjoint(out, n, entry->object, 64)) return false;
    for (MapEntry *entry = Maps; entry; entry = entry->next)
        if (!Disjoint(out, n, entry, sizeof(*entry)) || !Disjoint(out, n, entry->host, (size_t)entry->bytes)) return false;
    return true;
}
bool VM27HVVMOutputRangeDisjointV1(const void *out, size_t n) {
    Lock(); bool ok = OutputLocked(out, n); Unlock(); return ok;
}
// Never call this with Mutex held: Factory7 in turn checks this own guard.
static bool OutputBeforeLock(const void *out, size_t n) {
    return VM27CPUFactoryOutputRangeDisjointV3(out, n) &&
        VM27CPUConfigOutputRangeDisjointV3(out, n);
}
static ConfigEntry *FindLocked(const void *object) {
    for (ConfigEntry *entry = Configs; entry; entry = entry->next)
        if (entry->object == object) return entry;
    return NULL;
}
static VZKernelVMOptions Defaults(void) { return (VZKernelVMOptions){36, 0, 1, false, false}; }
@implementation OS_VM27VMConfigV1
- (void)dealloc {
    Lock(); ConfigEntry **link = &Configs;
    while (*link && (*link)->object != self) link = &(*link)->next;
    ConfigEntry *entry = *link;
    if (entry) { if (entry->inUse) abort(); *link = entry->next; }
    memset((unsigned char *)(void *)self + 16, 0, 48);
    Unlock(); free(entry);
#if VM27_HV_VM_TESTING
    atomic_fetch_add(&Destroyed, 1);
#endif
    [super dealloc];
}
@end
hv_vm_config_t hv_vm_config_create(void) {
    // SDK declares a retained nonnull object without an error channel.
    // An unguarded product must never expose writable own object storage.
    if (!VM27CPUFactoryVMOutputGuardLinkedV7()) abort();
    Class cls = [OS_VM27VMConfigV1 class];
    if (class_getInstanceSize(cls) != 8) abort();
    ConfigEntry *entry = calloc(1, sizeof(*entry));
    if (!entry) abort();
    id object = _os_object_alloc(cls, 64);
    if (!object) { free(entry); abort(); }
    memset((unsigned char *)(void *)object + 16, 0, 48);
    Lock();
    if (NextGeneration == UINT64_MAX) { Unlock(); CFRelease((CFTypeRef)object); free(entry); abort(); }
    entry->object = object; entry->generation = NextGeneration++; entry->options = Defaults();
    OwnConfigStorage *storage = (void *)object;
    storage->generation = entry->generation; storage->options = entry->options;
    entry->next = Configs; Configs = entry;
    Unlock();
#if VM27_HV_VM_TESTING
    atomic_fetch_add(&Created, 1);
#endif
    return (hv_vm_config_t)(void *)object;
}
static hv_return_t SetOption(hv_vm_config_t object, uint32_t field, uint32_t value) {
    Lock(); ConfigEntry *entry = FindLocked(object);
    if (!entry) { Unlock(); return Error(3); }
    if (entry->inUse) { Unlock(); return Error(2); }
    if ((field == 0 && value != 36) || (field == 1 && value != 0) ||
        (field == 2 && value != 1 && value != 2) || ((field == 3 || field == 4) && value != 0)) {
        Unlock(); return Error(15);
    }
    if (field == 0) entry->options.ipaBits = value;
    else if (field == 1) entry->options.ipaGranule = value;
    else if (field == 2) entry->options.nativeHVISA = value;
    else if (field == 3) entry->options.el2Enabled = false;
    else if (field == 4) entry->options.vheEnabled = false;
    else { Unlock(); return Error(3); }
    ((OwnConfigStorage *)(void *)object)->options = entry->options;
    Unlock(); return 0;
}
hv_return_t hv_vm_config_set_ipa_size(hv_vm_config_t config, uint32_t bits) { return SetOption(config, 0, bits); }
hv_return_t hv_vm_config_set_ipa_granule(hv_vm_config_t config, hv_ipa_granule_t granule) { return SetOption(config, 1, (uint32_t)granule); }
hv_return_t _hv_vm_config_set_isa(hv_vm_config_t config, uint32_t nativeISA) { return SetOption(config, 2, nativeISA); }
hv_return_t hv_vm_config_set_el2_enabled(hv_vm_config_t config, bool enabled) { return SetOption(config, 3, enabled); }
hv_return_t _hv_vm_config_set_vhe_enabled(hv_vm_config_t config, bool enabled) { return SetOption(config, 4, enabled); }
hv_return_t hv_vm_config_get_ipa_size(hv_vm_config_t config, uint32_t *out) {
    if (!OutputBeforeLock(out, sizeof(*out))) return Error(3);
    Lock(); ConfigEntry *entry = FindLocked(config);
    hv_return_t status = !entry || !OutputLocked(out, sizeof(*out)) ? Error(3) : entry->inUse ? Error(2) : 0;
    if (!status) *out = entry->options.ipaBits;
    Unlock(); return status;
}
hv_return_t VM27HVVMInstallNativeOpsV1(const VZKernelLifecycleOps *ops, const VZKernelInitWriter *writer) {
    if (!VM27CPUFactoryVMOutputGuardLinkedV7() || !ops || !writer || ops->schemaVersion != 1 ||
        ops->validatedKernelProfile != VZ_KERNEL_PROFILE_IPADOS_16_1_1 || !ops->nativeTrap ||
        !ops->currentThread || !ops->readMemory || !writer->writeMemory || writer->context != ops->context) return Error(3);
    if (!Begin()) return Error(2);
    uint64_t owner = ops->currentThread(ops->context);
    if (!owner) { End(); return Error(3); }
    Lock();
    hv_return_t status = Backend.installed || Backend.vm ? Error(2) : 0;
    if (!status) { Backend.ops = *ops; Backend.writer = *writer; Backend.owner = pthread_self(); Backend.installed = true; }
    Unlock(); End(); return status;
}
hv_return_t VM27HVVMUninstallNativeOpsV1(void) {
    if (!Begin()) return Error(2);
    Lock(); hv_return_t status = !Backend.installed ? Error(3) :
        Backend.vm || Configs || Maps ? Error(2) : !pthread_equal(Backend.owner, pthread_self()) ? Error(3) : 0;
    if (!status) memset(&Backend, 0, sizeof(Backend));
    Unlock(); End(); return status;
}
hv_return_t hv_vm_config_get_max_ipa_size(uint32_t *out) {
    if (!OutputBeforeLock(out, sizeof(*out))) return Error(3);
    if (!Begin()) return Error(2);
    Lock();
    bool installed = Backend.installed, valid = OutputLocked(out, sizeof(*out));
    Unlock();
    if (!installed || !valid) { End(); return Error(3); }
    VM27CPURawIPAPairV2 pair = {0};
    VM27CPUConfigAcquireRawIPAPairV2(&pair);
    // Shared once-only native response; raw provenance is not support. The
    // genuine fields are packed uint64 values and require zero high halves.
    hv_return_t status = Error(15);
    if (pair.known && !(pair.rawFieldA >> 32) && !(pair.rawFieldB >> 32)) {
        uint32_t a = (uint32_t)pair.rawFieldA, b = (uint32_t)pair.rawFieldB;
        uint32_t nativeMax = a < b ? a : b;
        // Own lifecycle currently implements only36. A native failure or a
        // native limit below36 preserves output, never receiving fallback36.
        if (nativeMax >= 36) status = 0;
    }
    if (!status) { Lock(); if (!OutputLocked(out, sizeof(*out))) status = Error(3); else *out = 36; Unlock(); }
    End(); return status;
}
hv_return_t hv_vm_config_get_default_ipa_size(uint32_t *out) {
    if (!OutputBeforeLock(out, sizeof(*out))) return Error(3);
    Lock(); hv_return_t status = !OutputLocked(out, sizeof(*out)) ? Error(3) : 0;
    // Exact original old default getter7ba8..7bcc; not a max/capability claim.
    if (!status) *out = 36;
    Unlock(); return status;
}
hv_return_t hv_vm_create(hv_vm_config_t config) {
    if (!Begin()) return Error(2);
    Lock(); ConfigEntry *entry = config ? FindLocked(config) : NULL;
    hv_return_t status = !Backend.installed || (config && !entry) ||
        !pthread_equal(Backend.owner, pthread_self()) ? Error(3) :
        Backend.vm || (entry && entry->inUse) ? Error(2) : 0;
    VZKernelVMOptions options = entry ? entry->options : Defaults();
    VZKernelLifecycleOps ops = Backend.ops; VZKernelInitWriter writer = Backend.writer;
    if (!status && entry) { entry->inUse = true; CFRetain((CFTypeRef)config); }
    Unlock();
    if (status) { End(); return status; }
    VM27CPUFactoryVMV2 *created = NULL; VM27CPUFactoryDiagnosticV2 diagnostic = {0};
    status = VM27CPUFactoryVMCreateV2(&ops, &options, &writer, &created, &diagnostic);
    Lock(); if (!status) { Backend.vm = created; Backend.vmDestroyed = false; Backend.owner = pthread_self(); }
    if (entry) entry->inUse = false;
    Unlock(); if (entry) CFRelease((CFTypeRef)config);
    End(); return status;
}
hv_return_t hv_vm_destroy(void) {
    if (!Begin()) return Error(2);
    Lock(); VM27CPUFactoryVMV2 *vm = Backend.vm; bool destroyed = Backend.vmDestroyed;
    bool owner = pthread_equal(Backend.owner, pthread_self()); Unlock();
    if (!vm || !owner) { End(); return Error(3); }
    hv_return_t status = 0;
    if (!destroyed) {
        status = VM27CPUFactoryVMDestroyV2(vm, NULL);
        if (!status) { Lock(); Backend.vmDestroyed = true; Unlock(); }
    }
    if (!status) {
        status = VM27CPUFactoryVMFreeV2(vm);
        if (!status) { Lock(); Backend.vm = NULL; Backend.vmDestroyed = false; Unlock(); }
    }
    // Native2 failure retains the live handle. Free failure retains the
    // destroyed handle so a retry only frees, never repeats native2.
    End(); return status;
}
hv_return_t VM27HVVMGetOwnedVMV1(VM27CPUFactoryVMV2 **out) {
    if (!OutputBeforeLock(out, sizeof(*out))) return Error(3);
    Lock(); hv_return_t status = !OutputLocked(out, sizeof(*out)) || !Backend.vm || Backend.vmDestroyed ||
        !pthread_equal(Backend.owner, pthread_self()) ? Error(3) : atomic_load(&Admission) ? Error(2) : 0;
    if (!status) *out = Backend.vm;
    Unlock(); return status;
}
static hv_return_t MapVMBeforeLock(VM27CPUFactoryVMV2 **out) {
    Lock(); hv_return_t status = !Backend.vm || Backend.vmDestroyed ||
        !pthread_equal(Backend.owner, pthread_self()) ? Error(3) : 0;
    if (!status) *out = Backend.vm;
    Unlock(); return status;
}
static MapEntry *FindMapLocked(hv_ipa_t ipa, size_t bytes) {
    for (MapEntry *entry = Maps; entry; entry = entry->next)
        if (entry->guestAddress == ipa && entry->bytes == bytes) return entry;
    return NULL;
}
static void RemoveMap(MapEntry *entry) {
    Lock(); MapEntry **link = &Maps;
    while (*link && *link != entry) link = &(*link)->next;
    if (!*link) abort();
    *link = entry->next; Unlock(); free(entry);
}
hv_return_t hv_vm_map(void *host,hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {
    if (!OutputBeforeLock(host,bytes)) return Error(3);
    VZKernelMemoryPacket packet;
    if (VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,VZKernelMemoryMap,
        (uintptr_t)host,ipa,bytes,flags,0,&packet)) return Error(3);
    if (!Begin()) return Error(2);
    VM27CPUFactoryVMV2 *vm = NULL; hv_return_t status = MapVMBeforeLock(&vm);
    if (status) { End(); return status; }
    MapEntry *entry = calloc(1,sizeof(*entry));
    if (!entry) { End(); return Error(5); }
    entry->host = host; entry->guestAddress = ipa; entry->bytes = bytes;
    VZKernelRAMResultV9 receipt = {0};
    status = VM27CPUFactoryRAMAdoptHostV9(vm,host,bytes,&entry->ram,&receipt);
    if (status) { free(entry); End(); return status; }
    Lock(); entry->next = Maps; Maps = entry; Unlock();
    status = VM27CPUFactoryRAMMapV5(entry->ram,ipa,flags,&receipt);
    if (status && !receipt.nativeInvoked) {
        // Validation failure cannot have mapped guest RAM. Free only the own
        // handle; the caller retains its original host allocation throughout.
        entry->cleanupOnly = true;
        if (!VM27CPUFactoryRAMFreeV5(entry->ram)) RemoveMap(entry);
    }
    // Once native3 was invoked, even a failing return keeps the exact IPA
    // and caller-host lease until successful native4 and own-handle release.
    End(); return status;
}
hv_return_t hv_vm_unmap(hv_ipa_t ipa,size_t bytes) {
    if (!Begin()) return Error(2);
    VM27CPUFactoryVMV2 *vm = NULL; hv_return_t status = MapVMBeforeLock(&vm);
    Lock(); MapEntry *entry = !status ? FindMapLocked(ipa,bytes) : NULL; Unlock();
    if (status || !entry) { End(); return status ? status : Error(15); }
    VZKernelRAMResultV9 receipt = {0};
    if (!entry->cleanupOnly) {
        status = VM27CPUFactoryRAMUnmapV5(entry->ram,&receipt);
        if (!status) entry->cleanupOnly = true;
    }
    if (!status) { status = VM27CPUFactoryRAMFreeV5(entry->ram); if (!status) RemoveMap(entry); }
    End(); return status;
}
hv_return_t hv_vm_protect(hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {
    VZKernelMemoryPacket packet;
    if (VZKernelMemoryPacketEncode(VZ_KERNEL_PROFILE_IPADOS_16_1_1,VZKernelMemoryProtect,
        0,ipa,bytes,flags,0,&packet)) return Error(3);
    if (!Begin()) return Error(2);
    VM27CPUFactoryVMV2 *vm = NULL; hv_return_t status = MapVMBeforeLock(&vm);
    Lock(); MapEntry *entry = !status ? FindMapLocked(ipa,bytes) : NULL; Unlock();
    if (status || !entry || entry->cleanupOnly) { End(); return status ? status : Error(15); }
    VZKernelRAMResultV9 receipt = {0};status = VM27CPUFactoryRAMProtectV5(entry->ram,flags,&receipt);
    End(); return status;
}
