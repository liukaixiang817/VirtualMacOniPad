/* Keep native6 page admission, native7 withdrawal, exact version reads and the
 * generic Mach query path from mapping3. The version5 width path retains the same-owner scalar
 * read into the already checked real pthread stack; writes remain unchanged. */
#include "modern_cpu_owned_mapping_cache_v3_full_context.c"
__attribute__((visibility("hidden"))) bool VM27CPUOwnedScalarReadV4(
    const void *address,size_t bytes,void *output) {
    uint64_t thread=0;
    if(!address || !output || !bytes || bytes>16 ||
        pthread_threadid_np(NULL,&thread) || !thread)return false;
    uintptr_t at=(uintptr_t)address,to=(uintptr_t)output;
    for(unsigned i=0;i<64;++i) {
        OwnedMappingV1 *m=&mappings[i];
        uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
        if(!epoch || (epoch&1) || atomic_load_explicit(&m->thread,memory_order_relaxed)!=thread ||
            atomic_load_explicit(&m->taskPID,memory_order_relaxed)!=getpid() ||
            !atomic_load_explicit(&m->token,memory_order_relaxed))continue;
        uintptr_t context=atomic_load_explicit(&m->context,memory_order_relaxed);
        uintptr_t stack=atomic_load_explicit(&m->stackStart,memory_order_relaxed);
        size_t stackBytes=atomic_load_explicit(&m->stackBytes,memory_order_relaxed);
        unsigned pages=atomic_load_explicit(&m->readPages,memory_order_relaxed);
        if(!InsideOwnedMappingV1(at,bytes,context,0x8000) ||
            !InsideOwnedMappingV1(to,bytes,stack,stackBytes))return false;
        unsigned first=(unsigned)((at-context)>>14),last=(unsigned)((at-context+bytes-1)>>14);
        unsigned required=(1u<<first)|(1u<<last);
        if((pages&required)!=required)return false;
        atomic_thread_fence(memory_order_acquire);
        if(atomic_load_explicit(&m->epoch,memory_order_relaxed)!=epoch)return false;
        unsigned char staged[16];
        // Keep each naturally aligned scalar as one volatile native load.
        // Staging and both epoch checks remain; an arbitrary output may be
        // unaligned, so memcpy below still publishes only the admitted bytes.
        if(bytes==8 && !(at&7)) {
            uint64_t value=*(const volatile uint64_t *)address;
            memcpy(staged,&value,8);
        } else if(bytes==4 && !(at&3)) {
            uint32_t value=*(const volatile uint32_t *)address;
            memcpy(staged,&value,4);
        } else if(bytes==2 && !(at&1)) {
            uint16_t value=*(const volatile uint16_t *)address;
            memcpy(staged,&value,2);
        } else {
            const volatile unsigned char *source=address;
            for(size_t n=0;n<bytes;++n)staged[n]=source[n];
        }
        atomic_thread_fence(memory_order_acquire);
        if(atomic_load_explicit(&m->epoch,memory_order_relaxed)!=epoch)return false;
        memcpy(output,staged,bytes);CountOwnedMappingV1(&m->contextHits);return true;
    }
    return false;
}
