#include "vm27_bc_validation_scope_v1.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sched.h>
static int textureA, textureB;
static atomic_int ready, finished;
static void *validator(void *unused) {
    (void)unused; uint64_t format;
    VM27BCValidationScopeV1 scope;
    VM27BCValidationEnterV1(&scope,&textureA,204);
    atomic_store_explicit(&ready,1,memory_order_release);
    while(!atomic_load_explicit(&finished,memory_order_acquire)) {
        assert(VM27BCValidationLookupV1(&textureA,&format) && format==204);
        assert(!VM27BCValidationLookupV1(&textureB,&format));
        sched_yield();
    }
    VM27BCValidationLeaveV1(&scope);
    assert(!VM27BCValidationLookupV1(&textureA,&format));
    return NULL;
}
int main(void) {
    uint64_t format; VM27BCValidationScopeV1 outer,inner,second;
    assert(!VM27BCValidationLookupV1(&textureA,&format));
    VM27BCValidationEnterV1(&outer,&textureA,204);
    VM27BCValidationEnterV1(&inner,&textureA,186);
    VM27BCValidationEnterV1(&second,&textureB,170);
    assert(VM27BCValidationLookupV1(&textureA,&format) && format==186);
    assert(VM27BCValidationLookupV1(&textureB,&format) && format==170);
    VM27BCValidationLeaveV1(&second); VM27BCValidationLeaveV1(&inner);
    assert(VM27BCValidationLookupV1(&textureA,&format) && format==204);
    VM27BCValidationLeaveV1(&outer);
    pthread_t thread; assert(!pthread_create(&thread,NULL,validator,NULL));
    while(!atomic_load_explicit(&ready,memory_order_acquire))sched_yield();
    for(unsigned i=0;i<200000;++i) {
        assert(!VM27BCValidationLookupV1(&textureA,&format));
        assert(!VM27BCValidationLookupV1(&textureB,&format));
    }
    atomic_store_explicit(&finished,1,memory_order_release);
    assert(!pthread_join(thread,NULL));
    puts("BC_VALIDATION_SCOPE nested restore and400000 concurrent isolation checks PASS");
    return 0;
}
