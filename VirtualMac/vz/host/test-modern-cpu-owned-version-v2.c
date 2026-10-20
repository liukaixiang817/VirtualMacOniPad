/* Real Mach mapping boundary tests of the private cache only. These do not
 * create a CPU and are not evidence of native6 or guest execution. */
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "modern_cpu_owned_mapping_cache_v2.c"

static void *other_thread(void *context) {
    VM27CPUSelfMappedReceiptV1 receipt={0};
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,false,&receipt));
    assert(receipt.queries>0 && receipt.requestedRangeMapped);
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,false,NULL));
    uint64_t value=999;assert(!VM27CPUOwnedVersionReadV2((unsigned char *)context+0x4000,&value));assert(value==999);
    return NULL;
}

int main(void) {
    assert(sysconf(_SC_PAGESIZE)==0x4000);
    unsigned char *context=mmap(NULL,0xc000,PROT_NONE,
        MAP_ANON|MAP_PRIVATE,-1,0);
    assert(context!=MAP_FAILED);
    assert(!mprotect(context,0x4000,PROT_READ|PROT_WRITE));
    assert(!mprotect(context+0x4000,0x4000,PROT_READ|PROT_WRITE));
    *(uint64_t *)(context+0x4000)=123456;
    assert(!mprotect(context+0x4000,0x4000,PROT_READ));
    uint64_t thread=0;
    assert(!pthread_threadid_np(NULL,&thread) && thread);
    uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    size_t bytes=pthread_get_stacksize_np(pthread_self());
    assert(!VM27CPUOwnedMappingPublishV1(64,1,thread,(uintptr_t)context,3,1,0,0,false));
    assert(!VM27CPUOwnedMappingPublishV1(0,0,thread,(uintptr_t)context,3,1,0,0,false));
    assert(!VM27CPUOwnedMappingPublishV1(0,1,thread+1,(uintptr_t)context,3,1,0,0,false));
    assert(!VM27CPUOwnedMappingPublishV1(0,1,thread,(uintptr_t)context,1,2,0,0,false));
    assert(VM27CPUOwnedMappingPublishV1(0,1,thread,(uintptr_t)context,3,1,top-bytes,bytes,true));
    uint64_t version=0;assert(VM27CPUOwnedVersionReadV2(context+0x4000,&version));assert(version==123456);
    assert(!VM27CPUOwnedVersionReadV2(context,&version));assert(version==123456);
    assert(!mprotect(context+0x4000,0x4000,PROT_READ|PROT_WRITE));
    *(uint64_t *)(context+0x4000)=123457;
    assert(!mprotect(context+0x4000,0x4000,PROT_READ));
    assert(VM27CPUOwnedVersionReadV2(context+0x4000,&version));assert(version==123457);
    atomic_store_explicit(&mappings[0].taskPID,getpid()+1,memory_order_relaxed);
    assert(!VM27CPUOwnedVersionReadV2(context+0x4000,&version));assert(version==123457);
    atomic_store_explicit(&mappings[0].taskPID,getpid(),memory_order_relaxed);
    assert(!VM27CPUOwnedVersionReadV2(context+0x4000,context));
    assert(!VM27CPUOwnedMappingPublishV1(0,2,thread,(uintptr_t)context,3,1,0,0,false));
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,true,NULL));
    assert(VM27CPUSelfOwnedMappedRangeV1(context+0x3ffc,8,false,NULL));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context+0x4000,8,true,NULL));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context+0x3ffc,8,true,NULL));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context+0x7ffc,8,false,NULL));
    VM27CPUSelfMappedReceiptV1 receipt={0};
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,false,&receipt));
    assert(receipt.queries>0 && receipt.requestedRangeMapped);
    unsigned char local=0;
    assert(VM27CPUSelfOwnedMappedRangeV1(&local,1,true,NULL));
    VM27CPUOwnedMappingCountsV1 counts={0};
    VM27CPUOwnedMappingWithdrawV1(0,2,&counts);
    assert(!counts.contextHits && !counts.stackHits && !counts.fallbacks);
    pthread_t other;
    assert(!pthread_create(&other,NULL,other_thread,context));
    assert(!pthread_join(other,NULL));
    VM27CPUOwnedMappingWithdrawV1(0,1,&counts);
    assert(!VM27CPUOwnedVersionReadV2(context+0x4000,&version));assert(version==123457);
    assert(!mprotect(context+0x4000,0x4000,PROT_NONE));
    assert(!VM27CPUOwnedVersionReadV2(context+0x4000,&version));
    assert(!mprotect(context+0x4000,0x4000,PROT_READ));
    assert(counts.contextHits==2); /* foreign thread and receipt never hit */
    assert(counts.fallbacks>=3);
    assert(!mprotect(context,0x4000,PROT_NONE));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context,8,false,NULL));
    assert(!VM27CPUOwnedMappingPublishV1(0,3,thread,(uintptr_t)context,3,1,0,0,false));
    assert(!mprotect(context,0x4000,PROT_READ|PROT_WRITE));
    assert(VM27CPUOwnedMappingPublishV1(0,3,thread,(uintptr_t)context,3,1,0,0,false));
    /* Exhaustion must disable acceleration permanently rather than leave an
     * admission to an unmapped native context after destruction. */
    atomic_store_explicit(&mappings[0].epoch,UINT64_MAX-1,memory_order_release);
    VM27CPUOwnedMappingWithdrawV1(0,3,NULL);
    assert(atomic_load_explicit(&mappings[0].epoch,memory_order_acquire)==UINT64_MAX);
    assert(!mprotect(context,0x4000,PROT_NONE));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context,8,false,NULL));
    assert(!VM27CPUOwnedMappingPublishV1(0,4,thread,(uintptr_t)context,3,1,0,0,false));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context,0,false,NULL));
    assert(!munmap(context,0xc000));
    puts("PASS: real mappings, permissions, crossing pages, raw receipts, foreign owner, withdrawal, republish and epoch exhaustion");
    return 0;
}
