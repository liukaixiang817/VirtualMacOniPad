#ifndef VM27_PG_IMAGE_IDENTITY_CACHE_V1_H
#define VM27_PG_IMAGE_IDENTITY_CACHE_V1_H
#include <stdint.h>

/* Immutable records avoid a lock on the display thread. A dyld image change
 * invalidates every prior record. Saturation falls back to full validation.
 * Process identity is always checked, including after fork. */
#define VM27_PG_IDENTITY_CACHE_CAPACITY_V1 16u
typedef struct {
    uint32_t ready;
    int64_t pid;
    uint64_t generation;
    uintptr_t imageBase;
} VM27PGImageIdentityRecordV1;
typedef struct {
    uint64_t generation;
    uint32_t active, next, head;
    VM27PGImageIdentityRecordV1 records[VM27_PG_IDENTITY_CACHE_CAPACITY_V1];
} VM27PGImageIdentityCacheV1;

static inline void VM27PGImageIdentityInvalidateV1(VM27PGImageIdentityCacheV1 *cache) {
    uint64_t old=__atomic_fetch_add(&cache->generation,1,__ATOMIC_ACQ_REL);
    if(old==UINT64_MAX)__atomic_store_n(&cache->active,0,__ATOMIC_RELEASE);
}
static inline uint64_t VM27PGImageIdentityGenerationV1(VM27PGImageIdentityCacheV1 *cache) {
    return __atomic_load_n(&cache->generation,__ATOMIC_ACQUIRE);
}
static inline int VM27PGImageIdentityLookupV1(VM27PGImageIdentityCacheV1 *cache,
    int64_t pid,uint64_t generation,uintptr_t *imageBase) {
    if(pid<=1 || !__atomic_load_n(&cache->active,__ATOMIC_ACQUIRE))return 0;
    uint32_t head=__atomic_load_n(&cache->head,__ATOMIC_ACQUIRE);
    if(!head || head>VM27_PG_IDENTITY_CACHE_CAPACITY_V1)return 0;
    VM27PGImageIdentityRecordV1 *row=&cache->records[head-1];
    if(!__atomic_load_n(&row->ready,__ATOMIC_ACQUIRE) || row->pid!=pid ||
       row->generation!=generation || !row->imageBase ||
       generation!=VM27PGImageIdentityGenerationV1(cache))return 0;
    *imageBase=row->imageBase;return 1;
}
static inline void VM27PGImageIdentityPublishV1(VM27PGImageIdentityCacheV1 *cache,
    int64_t pid,uint64_t generation,uintptr_t imageBase) {
    if(pid<=1 || !imageBase || !__atomic_load_n(&cache->active,__ATOMIC_ACQUIRE) ||
       generation!=VM27PGImageIdentityGenerationV1(cache))return;
    uint32_t index=__atomic_load_n(&cache->next,__ATOMIC_RELAXED);
    do {
        if(index>=VM27_PG_IDENTITY_CACHE_CAPACITY_V1)return;
    } while(!__atomic_compare_exchange_n(&cache->next,&index,index+1,0,
        __ATOMIC_RELAXED,__ATOMIC_RELAXED));
    VM27PGImageIdentityRecordV1 *row=&cache->records[index];
    row->pid=pid;row->generation=generation;row->imageBase=imageBase;
    __atomic_store_n(&row->ready,1,__ATOMIC_RELEASE);
    __atomic_store_n(&cache->head,index+1,__ATOMIC_RELEASE);
}
#endif
