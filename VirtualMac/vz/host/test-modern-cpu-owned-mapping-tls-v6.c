/* Real Mach mapping boundary tests of the private cache only. These do not
 * create a CPU and are not evidence of native6 or guest execution. */
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "modern_cpu_owned_mapping_cache_v6_owner_tls.c"
#include <sys/wait.h>
#include <stdlib.h>

static void *other_thread(void *context) {
    VM27CPUSelfMappedReceiptV1 receipt={0};
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,false,&receipt));
    assert(receipt.queries>0 && receipt.requestedRangeMapped);
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,false,NULL));
    return NULL;
}

static void *foreign_withdraw(void *context) {
 uint64_t output=0;
 assert(!VM27CPUOwnedVersionReadV2((unsigned char *)context+0x4000,&output));
 assert(!VM27CPUOwnedScalarReadV4(context,8,&output));
 VM27CPUOwnedMappingWithdrawV1(3,77,NULL);return NULL;
}
static void extended(void) {
 unsigned char *context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
 assert(context!=MAP_FAILED);uint64_t thread=0;assert(!pthread_threadid_np(NULL,&thread));
 uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t bytes=pthread_get_stacksize_np(pthread_self());
 assert(VM27CPUOwnedMappingPublishV1(3,77,thread,(uintptr_t)context,3,3,top-bytes,bytes,true));
 uint64_t expected=0x123456789abcdef0,actual=0;memcpy(context+0x4000,&expected,8);
 assert(VM27CPUOwnedVersionReadV2(context+0x4000,&actual)&&actual==expected);
 expected=~expected;memcpy(context+0x4000,&expected,8);
 assert(VM27CPUOwnedVersionReadV2(context+0x4000,&actual)&&actual==expected);
 for(size_t width=1;width<=16;++width)for(unsigned offset=0;offset<16;++offset){
  for(unsigned i=0;i<32;++i)context[i]=(unsigned char)(i*17);unsigned char output[32];memset(output,0x37,sizeof(output));
  assert(VM27CPUOwnedScalarReadV4(context+offset,width,output+1));assert(!memcmp(context+offset,output+1,width));
  assert(output[0]==0x37&&output[width+1]==0x37);
 }
 uint64_t *heap=malloc(8);assert(heap);assert(!VM27CPUOwnedVersionReadV2(context+0x4000,heap));free(heap);
 pid_t child=fork();assert(child>=0);
 if(!child){uint64_t childOutput=0;_exit(VM27CPUOwnedVersionReadV2(context+0x4000,&childOutput)?91:0);}
 int status=0;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&!WEXITSTATUS(status));
 pthread_t other;assert(!pthread_create(&other,NULL,foreign_withdraw,context));assert(!pthread_join(other,NULL));
 assert(!mprotect(context,0x8000,PROT_NONE));assert(!VM27CPUOwnedVersionReadV2(context+0x4000,&actual));
 assert(!VM27CPUOwnedScalarReadV4(context,8,&actual));assert(!munmap(context,0x8000));
 assert(_Alignof(OwnedMappingV1)>=128&&sizeof(OwnedMappingV1)%128==0);
 puts("PASS: fresh version, scalar widths, unaligned output, foreign withdrawal, PID fork boundary and cache-line separation");
}

int main(void) {
    assert(sysconf(_SC_PAGESIZE)==0x4000);
    unsigned char *context=mmap(NULL,0xc000,PROT_NONE,
        MAP_ANON|MAP_PRIVATE,-1,0);
    assert(context!=MAP_FAILED);
    assert(!mprotect(context,0x4000,PROT_READ|PROT_WRITE));
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
    assert(!VM27CPUOwnedMappingPublishV1(0,2,thread,(uintptr_t)context,3,1,0,0,false));
    assert(VM27CPUSelfOwnedMappedRangeV1(context,8,true,NULL));
    assert(VM27CPUSelfOwnedMappedRangeV1(context+0x3ffc,8,false,NULL));
    assert(VM27CPUSelfOwnedMappedRangeV1(context,0x4118,false,NULL));
    assert(VM27CPUSelfOwnedMappedRangeV1(context,0x8000,false,NULL));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context,0x4118,true,NULL));
    assert(!VM27CPUSelfOwnedMappedRangeV1(context,0x8001,false,NULL));
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
    assert(counts.contextHits==4); /* foreign thread and receipt never hit */
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
    extended();return 0;
}
