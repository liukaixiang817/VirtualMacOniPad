/* Retain the current generic V1 API implementation from source V2 verbatim,
 * including its page-derived budget for fragmented 8 GiB RAM mappings. Only
 * Life66/Production11 private call sites use the live native6 admission. */
#include "modern_cpu_native_self_memory_v2.c"
#include "modern_cpu_owned_mapping_cache_v1.h"
#include <pthread.h>
#include <stdatomic.h>

_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "ARM64 lock-free mapping epochs");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "ARM64 lock-free mapping addresses");

/* Slots are never freed. All metadata is atomic, so invalidation from a second
 * CPU cannot race a reader or turn an old admission into a dangling pointer.
 * Writers are serialized by ProductionMutex; only the matching real owner
 * thread may use a ready slot. Odd epochs are never usable. */
typedef struct __attribute__((aligned(128))) {
    _Atomic uint64_t epoch, thread;
    _Atomic pid_t taskPID;
    _Atomic uintptr_t token, context, stackStart;
    _Atomic size_t stackBytes;
    _Atomic unsigned readPages, writePages;
    _Atomic uint64_t contextHits, stackHits, fallbacks;
} OwnedMappingV1;
static OwnedMappingV1 mappings[64];
static void CountOwnedMappingV1(_Atomic uint64_t *counter) {
    uint64_t old=atomic_load_explicit(counter,memory_order_relaxed);
    while (old!=UINT64_MAX && !atomic_compare_exchange_weak_explicit(counter,
        &old,old+1,memory_order_relaxed,memory_order_relaxed)) {}
}

static bool InsideOwnedMappingV1(uintptr_t at, size_t bytes,
    uintptr_t base, size_t length) {
    return base && length && at >= base && at-base < length &&
        bytes <= length-(at-base);
}

bool VM27CPUOwnedMappingPublishV1(uint64_t slot, uintptr_t token,
    uint64_t thread, uintptr_t context, unsigned reads, unsigned writes,
    uintptr_t stack, size_t stackBytes, bool wholeStackWritable) {
    uint64_t actualThread=0;
    if (slot>=64 || !token || !thread ||
        pthread_threadid_np(NULL,&actualThread) || thread!=actualThread ||
        !context || (context&0x3fff) || context>UINTPTR_MAX-0x8000 ||
        (reads&~3u) || (writes&~reads) || !(reads&2u)) return false;
    OwnedMappingV1 *m=&mappings[slot];
    uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
    if ((epoch&1) || epoch>UINT64_MAX-2 ||
        atomic_load_explicit(&m->token,memory_order_relaxed)) return false;
    /* Recheck the real pages at publication. These checks always use V1,
     * before any cache can be used; no synthetic region receipt is created. */
    for (unsigned page=0;page<2;++page) {
        const void *p=(const void *)(context+(uintptr_t)page*0x4000);
        if ((reads&(1u<<page)) && !VM27CPUSelfMappedRangeV1(p,0x4000,false,NULL)) return false;
        if ((writes&(1u<<page)) && !VM27CPUSelfMappedRangeV1(p,0x4000,true,NULL)) return false;
    }
    unsigned char local=0;
    uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    size_t actualBytes=pthread_get_stacksize_np(pthread_self());
    bool stackOK=wholeStackWritable && stack && stackBytes &&
        stackBytes<=UINTPTR_MAX-stack && top>=actualBytes &&
        stack==top-actualBytes && stackBytes==actualBytes &&
        InsideOwnedMappingV1((uintptr_t)&local,1,stack,stackBytes) &&
        VM27CPUSelfMappedRangeV1((const void *)stack,stackBytes,true,NULL);
    (void)atomic_exchange_explicit(&m->epoch,epoch+1,memory_order_acq_rel);
    atomic_store_explicit(&m->taskPID,getpid(),memory_order_relaxed);
    atomic_store_explicit(&m->token,token,memory_order_relaxed);
    atomic_store_explicit(&m->thread,thread,memory_order_relaxed);
    atomic_store_explicit(&m->context,context,memory_order_relaxed);
    atomic_store_explicit(&m->readPages,reads,memory_order_relaxed);
    atomic_store_explicit(&m->writePages,writes,memory_order_relaxed);
    atomic_store_explicit(&m->stackStart,stackOK?stack:0,memory_order_relaxed);
    atomic_store_explicit(&m->stackBytes,stackOK?stackBytes:0,memory_order_relaxed);
    atomic_store_explicit(&m->contextHits,0,memory_order_relaxed);
    atomic_store_explicit(&m->stackHits,0,memory_order_relaxed);
    atomic_store_explicit(&m->fallbacks,0,memory_order_relaxed);
    atomic_store_explicit(&m->epoch,epoch+2,memory_order_release);
    return true;
}

void VM27CPUOwnedMappingWithdrawV1(uint64_t slot, uintptr_t token,
    VM27CPUOwnedMappingCountsV1 *counts) {
    if (counts) *counts=(VM27CPUOwnedMappingCountsV1){0};
    if (slot>=64 || !token) return;
    OwnedMappingV1 *m=&mappings[slot];
    uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
    if (!epoch || (epoch&1) ||
        atomic_load_explicit(&m->token,memory_order_relaxed)!=token) return;
    (void)atomic_exchange_explicit(&m->epoch,epoch+1,memory_order_acq_rel);
    if (counts) {
        counts->contextHits=atomic_load_explicit(&m->contextHits,memory_order_relaxed);
        counts->stackHits=atomic_load_explicit(&m->stackHits,memory_order_relaxed);
        counts->fallbacks=atomic_load_explicit(&m->fallbacks,memory_order_relaxed);
    }
    atomic_store_explicit(&m->token,0,memory_order_relaxed);
    atomic_store_explicit(&m->thread,0,memory_order_relaxed);
    atomic_store_explicit(&m->epoch,epoch<=UINT64_MAX-2?epoch+2:UINT64_MAX,memory_order_release);
}

bool VM27CPUSelfOwnedMappedRangeV1(const void *address, size_t bytes,
    bool writable, VM27CPUSelfMappedReceiptV1 *receipt) {
    uintptr_t at=(uintptr_t)address;
    uint64_t thread=0;
    /* Receipt callers still receive a fresh genuine Mach query. The bounded
     * hot path validates memory; it does not read, write, or invent a result. */
    if (receipt || !at || !bytes || bytes>0x8000 || bytes>UINTPTR_MAX-at ||
        pthread_threadid_np(NULL,&thread) || !thread)
        return VM27CPUSelfMappedRangeV1(address,bytes,writable,receipt);
    for (unsigned slot=0;slot<64;++slot) {
        OwnedMappingV1 *m=&mappings[slot];
        uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
        if (!epoch || (epoch&1) ||
            atomic_load_explicit(&m->thread,memory_order_relaxed)!=thread ||
            !atomic_load_explicit(&m->token,memory_order_relaxed)) continue;
        uintptr_t context=atomic_load_explicit(&m->context,memory_order_relaxed);
        unsigned pages=atomic_load_explicit(writable?&m->writePages:&m->readPages,memory_order_relaxed);
        uintptr_t stack=atomic_load_explicit(&m->stackStart,memory_order_relaxed);
        size_t stackBytes=atomic_load_explicit(&m->stackBytes,memory_order_relaxed);
        bool inContext=InsideOwnedMappingV1(at,bytes,context,0x8000);
        if (inContext) {
            unsigned first=(unsigned)((at-context)>>14);
            unsigned last=(unsigned)((at-context+bytes-1)>>14);
            unsigned required=(1u<<first)|(1u<<last);
            inContext=(pages&required)==required;
        }
        bool inStack=InsideOwnedMappingV1(at,bytes,stack,stackBytes);
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(&m->epoch,memory_order_relaxed)!=epoch) break;
        if (inContext || inStack) {
            CountOwnedMappingV1(inContext?&m->contextHits:&m->stackHits);
            return true;
        }
        CountOwnedMappingV1(&m->fallbacks);
        break;
    }
    return VM27CPUSelfMappedRangeV1(address,bytes,writable,receipt);
}

/* Only the exact real native6 version word into this same CPU pthread's
 * prechecked stack. Ownership lasts until native7 on that owning pthread;
 * foreign wakes retain ProductionReadV1's original locked Mach path. */
__attribute__((visibility("hidden"))) bool VM27CPUOwnedVersionReadV2(
    const void *address,void *output) {
    uint64_t thread=0;
    if(!address || !output || pthread_threadid_np(NULL,&thread) || !thread)return false;
    const uintptr_t at=(uintptr_t)address,to=(uintptr_t)output;
    for(unsigned i=0;i<64;++i) {
        OwnedMappingV1 *m=&mappings[i];
        uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
        if(!epoch || (epoch&1) || atomic_load_explicit(&m->thread,memory_order_relaxed)!=thread ||
           atomic_load_explicit(&m->taskPID,memory_order_relaxed)!=getpid() ||
           !atomic_load_explicit(&m->token,memory_order_relaxed))continue;
        uintptr_t context=atomic_load_explicit(&m->context,memory_order_relaxed);
        uintptr_t stack=atomic_load_explicit(&m->stackStart,memory_order_relaxed);
        size_t stackBytes=atomic_load_explicit(&m->stackBytes,memory_order_relaxed);
        unsigned readable=atomic_load_explicit(&m->readPages,memory_order_relaxed);
        if(at!=context+0x4000 || !(readable&2u) || (at&7) ||
           !InsideOwnedMappingV1(to,8,stack,stackBytes))return false;
        atomic_thread_fence(memory_order_acquire);
        if(atomic_load_explicit(&m->epoch,memory_order_relaxed)!=epoch)return false;
        uint64_t value=*(const volatile uint64_t *)address;
        atomic_thread_fence(memory_order_acquire);
        if(atomic_load_explicit(&m->epoch,memory_order_relaxed)!=epoch)return false;
        memcpy(output,&value,8);
        return true;
    }
    return false;
}
