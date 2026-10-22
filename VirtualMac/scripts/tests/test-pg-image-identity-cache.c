#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../vz/host/vm27_pg_image_identity_cache_v1.h"

static VM27PGImageIdentityCacheV1 cache={.generation=1,.active=1};
static void *reader(void *unused) {
    (void)unused;
    for(unsigned i=0;i<10000;++i) {
        uintptr_t base=0;
        assert(VM27PGImageIdentityLookupV1(&cache,getpid(),1,&base));
        assert(base==0x12345000);
    }
    return NULL;
}
int main(void) {
    uintptr_t base=0;
    assert(!VM27PGImageIdentityLookupV1(&cache,getpid(),1,&base));
    VM27PGImageIdentityPublishV1(&cache,getpid(),1,0x12345000);
    pthread_t workers[8];
    for(unsigned i=0;i<8;++i)assert(!pthread_create(&workers[i],NULL,reader,NULL));
    for(unsigned i=0;i<8;++i)assert(!pthread_join(workers[i],NULL));
    pid_t child=fork();assert(child>=0);
    if(!child)_exit(VM27PGImageIdentityLookupV1(&cache,getpid(),1,&base)?1:0);
    int status=0;assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
    VM27PGImageIdentityInvalidateV1(&cache);
    assert(!VM27PGImageIdentityLookupV1(&cache,getpid(),1,&base));
    assert(!VM27PGImageIdentityLookupV1(&cache,getpid(),2,&base));
    VM27PGImageIdentityPublishV1(&cache,getpid(),1,0x11111000);
    assert(!VM27PGImageIdentityLookupV1(&cache,getpid(),2,&base));
    VM27PGImageIdentityPublishV1(&cache,getpid(),2,0x23456000);
    assert(VM27PGImageIdentityLookupV1(&cache,getpid(),2,&base));
    assert(base==0x23456000);
    assert(!VM27PGImageIdentityLookupV1(&cache,1,2,&base));
    for(unsigned i=0;i<32;++i) {
        VM27PGImageIdentityInvalidateV1(&cache);
        uint64_t generation=VM27PGImageIdentityGenerationV1(&cache);
        VM27PGImageIdentityPublishV1(&cache,getpid(),generation,0x34567000);
    }
    assert(cache.next==VM27_PG_IDENTITY_CACHE_CAPACITY_V1);
    assert(!VM27PGImageIdentityLookupV1(&cache,getpid(),cache.generation,&base));
    puts("PASS: concurrent readers, fork rejection, image invalidation, stale publish rejection and finite saturation");
    return 0;
}
