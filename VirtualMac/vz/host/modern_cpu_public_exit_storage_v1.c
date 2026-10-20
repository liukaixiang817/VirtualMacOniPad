#include "modern_cpu_public_exit_storage_v1.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

typedef struct vm27_exit_entry_v1 {
    struct vm27_exit_entry_v1 *next;
    uint64_t identity, cpu_generation, owner_generation, epoch;
    unsigned char *storage;
    size_t borrows;
    int published, draining;
} vm27_exit_entry_v1;
struct vm27_exit_owner_v1 {
    struct vm27_exit_owner_v1 *next;
    pthread_t owner_thread;
    uint64_t epoch, generation;
    vm27_exit_mock_ops_v1 ops;
    vm27_exit_entry_v1 *entries;
    int operation;
};
struct vm27_exit_borrow_v1 {
    struct vm27_exit_borrow_v1 *next;
    vm27_exit_owner_v1 *owner;
    vm27_exit_entry_v1 *entry;
    uint64_t epoch, owner_generation, cpu_generation;
    pthread_t borrower_thread;
    int released;
};
static pthread_mutex_t vm27_exit_mutex_v1 = PTHREAD_MUTEX_INITIALIZER;
static vm27_exit_owner_v1 *vm27_exit_owners_v1;
static vm27_exit_borrow_v1 *vm27_exit_borrows_v1;
static uint64_t vm27_exit_next_owner_generation_v1;
static uint64_t vm27_exit_next_identity_v1;
static uint64_t vm27_exit_next_cpu_generation_v1;
static _Thread_local vm27_exit_owner_v1 *vm27_exit_tls_owner_v1;
static _Thread_local int vm27_exit_tls_creating_v1;
static void vm27_exit_lock_v1(void) {
    if (pthread_mutex_lock(&vm27_exit_mutex_v1)) abort();
}
static void vm27_exit_unlock_v1(void) {
    if (pthread_mutex_unlock(&vm27_exit_mutex_v1)) abort();
}
// Callers hold mutex; comparison precedes all owner/borrow dereferences.
static vm27_exit_owner_v1 *vm27_exit_find_owner_v1(vm27_exit_owner_v1 *candidate) {
    for (vm27_exit_owner_v1 *p=vm27_exit_owners_v1;p;p=p->next)
        if (p==candidate) return p;
    return NULL;
}
static vm27_exit_entry_v1 *vm27_exit_find_entry_v1(vm27_exit_owner_v1 *owner,
    uint64_t identity) {
    for (vm27_exit_entry_v1 *p=owner->entries;p;p=p->next)
        if (p->identity==identity) return p;
    return NULL;
}
static vm27_exit_status_v1 vm27_exit_admit_v1(vm27_exit_owner_v1 *candidate,
    uint64_t epoch, vm27_exit_owner_v1 **out) {
    vm27_exit_owner_v1 *owner=vm27_exit_find_owner_v1(candidate);
    if (!owner || !epoch || owner->epoch!=epoch) return VM27_EXIT_NOT_LIVE_V1;
    if (!pthread_equal(owner->owner_thread,pthread_self()) || vm27_exit_tls_owner_v1!=owner)
        return VM27_EXIT_WRONG_THREAD_V1;
    if (owner->operation) return VM27_EXIT_BUSY_V1;
    *out=owner;return VM27_EXIT_OK_V1;
}
static int vm27_exit_overlap_v1(const void *a,size_t size,const void *b,size_t bytes) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if (!a || !size || x>UINTPTR_MAX-size) return 1;
    if (!b || !bytes) return 0;
    return x<y+bytes && y<x+size;
}
static int vm27_exit_private_alias_v1(const void *pointer,size_t bytes) {
    if (!pointer || !bytes || (uintptr_t)pointer>UINTPTR_MAX-bytes) return 1;
    for (vm27_exit_owner_v1 *o=vm27_exit_owners_v1;o;o=o->next) {
        if (vm27_exit_overlap_v1(pointer,bytes,o,sizeof(*o))) return 1;
        for (vm27_exit_entry_v1 *e=o->entries;e;e=e->next)
            if (vm27_exit_overlap_v1(pointer,bytes,e,sizeof(*e)) ||
                vm27_exit_overlap_v1(pointer,bytes,e->storage,VM27_EXIT_STORAGE_BYTES_V1)) return 1;
    }
    for (vm27_exit_borrow_v1 *b=vm27_exit_borrows_v1;b;b=b->next)
        if (vm27_exit_overlap_v1(pointer,bytes,b,sizeof(*b))) return 1;
    return 0;
}
vm27_exit_status_v1 vm27_exit_owner_create_v1(uint64_t epoch,
    const vm27_exit_mock_ops_v1 *ops,vm27_exit_owner_v1 **out_owner) {
    if (!epoch || !ops || !out_owner) return VM27_EXIT_BAD_ARGUMENT_V1;
    if (vm27_exit_tls_owner_v1 || vm27_exit_tls_creating_v1) return VM27_EXIT_BUSY_V1;
    vm27_exit_lock_v1();
    if (vm27_exit_private_alias_v1(out_owner,sizeof(*out_owner)) ||
        vm27_exit_private_alias_v1(ops,sizeof(*ops)) || ops->schema_version!=1 ||
        !ops->complete_mock_create || !ops->complete_mock_destroy) {
        vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;
    }
    if (vm27_exit_next_owner_generation_v1==UINT64_MAX) {
        vm27_exit_unlock_v1();return VM27_EXIT_ID_EXHAUSTED_V1;
    }
    vm27_exit_tls_creating_v1=1;
    vm27_exit_owner_v1 *owner=calloc(1,sizeof(*owner));
    if (!owner) {
        vm27_exit_tls_creating_v1=0;vm27_exit_unlock_v1();return VM27_EXIT_OUT_OF_MEMORY_V1;
    }
    owner->epoch=epoch;owner->generation=++vm27_exit_next_owner_generation_v1;
    owner->owner_thread=pthread_self();owner->ops=*ops;
    owner->next=vm27_exit_owners_v1;vm27_exit_owners_v1=owner;
    vm27_exit_tls_owner_v1=owner;vm27_exit_tls_creating_v1=0;*out_owner=owner;
    vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_owner_close_v1(vm27_exit_owner_v1 *candidate,uint64_t epoch) {
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=NULL;
    vm27_exit_status_v1 status=vm27_exit_admit_v1(candidate,epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    for (vm27_exit_entry_v1 *e=owner->entries;e;e=e->next)
        if (e->published || e->borrows || e->storage) {vm27_exit_unlock_v1();return VM27_EXIT_BUSY_V1;}
    vm27_exit_owner_v1 **link=&vm27_exit_owners_v1;
    while (*link!=owner) link=&(*link)->next;
    *link=owner->next;vm27_exit_tls_owner_v1=NULL;
    // Released borrow records remain tombstones until owner close, so a stale
    // released handle cannot alias a later allocation within the owner lifetime.
    vm27_exit_borrow_v1 **borrow_link=&vm27_exit_borrows_v1;
    while (*borrow_link) {
        vm27_exit_borrow_v1 *borrow=*borrow_link;
        if (borrow->owner==owner) {*borrow_link=borrow->next;free(borrow);}
        else borrow_link=&borrow->next;
    }
    vm27_exit_entry_v1 *e=owner->entries;
    while (e) {vm27_exit_entry_v1 *next=e->next;free(e);e=next;}
    free(owner);vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_create_v1(vm27_exit_owner_v1 *candidate,uint64_t epoch,
    uint64_t *out_identity,const unsigned char **out_storage) {
    if (!out_identity || !out_storage) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=NULL;
    vm27_exit_status_v1 status=vm27_exit_admit_v1(candidate,epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    if (vm27_exit_private_alias_v1(out_identity,sizeof(*out_identity)) ||
        vm27_exit_private_alias_v1(out_storage,sizeof(*out_storage)) ||
        vm27_exit_overlap_v1(out_identity,sizeof(*out_identity),out_storage,sizeof(*out_storage))) {
        vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;
    }
    if (vm27_exit_next_identity_v1==UINT64_MAX || vm27_exit_next_cpu_generation_v1==UINT64_MAX) {
        vm27_exit_unlock_v1();return VM27_EXIT_ID_EXHAUSTED_V1;
    }
    vm27_exit_entry_v1 *entry=calloc(1,sizeof(*entry));
    if (!entry) {vm27_exit_unlock_v1();return VM27_EXIT_OUT_OF_MEMORY_V1;}
    entry->storage=calloc(1,VM27_EXIT_STORAGE_BYTES_V1);
    if (!entry->storage) {free(entry);vm27_exit_unlock_v1();return VM27_EXIT_OUT_OF_MEMORY_V1;}
    entry->identity=++vm27_exit_next_identity_v1;
    entry->cpu_generation=++vm27_exit_next_cpu_generation_v1;
    entry->epoch=owner->epoch;entry->owner_generation=owner->generation;
    owner->operation=1;vm27_exit_mock_ops_v1 ops=owner->ops;vm27_exit_unlock_v1();
    int result=ops.complete_mock_create(ops.context);
    vm27_exit_lock_v1();
    if (result) {free(entry->storage);free(entry);owner->operation=0;vm27_exit_unlock_v1();return VM27_EXIT_MOCK_FAILURE_V1;}
    entry->published=1;entry->next=owner->entries;owner->entries=entry;
    *out_identity=entry->identity;*out_storage=entry->storage;
    owner->operation=0;vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_borrow_v1_acquire(vm27_exit_owner_v1 *candidate,
    uint64_t epoch,uint64_t identity,vm27_exit_borrow_v1 **out_borrow) {
    if (!out_borrow || !identity) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=vm27_exit_find_owner_v1(candidate);
    if (!owner || owner->epoch!=epoch || !epoch) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (owner->operation) {vm27_exit_unlock_v1();return VM27_EXIT_BUSY_V1;}
    vm27_exit_entry_v1 *entry=vm27_exit_find_entry_v1(owner,identity);
    if (!entry || !entry->published || entry->draining || !entry->storage ||
        entry->epoch!=epoch || entry->owner_generation!=owner->generation) {
        vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;
    }
    if (vm27_exit_private_alias_v1(out_borrow,sizeof(*out_borrow))) {vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;}
    if (entry->borrows==SIZE_MAX) {vm27_exit_unlock_v1();return VM27_EXIT_BUSY_V1;}
    vm27_exit_borrow_v1 *borrow=calloc(1,sizeof(*borrow));
    if (!borrow) {vm27_exit_unlock_v1();return VM27_EXIT_OUT_OF_MEMORY_V1;}
    borrow->owner=owner;borrow->entry=entry;borrow->epoch=epoch;
    borrow->owner_generation=owner->generation;borrow->cpu_generation=entry->cpu_generation;
    borrow->borrower_thread=pthread_self();borrow->next=vm27_exit_borrows_v1;
    vm27_exit_borrows_v1=borrow;++entry->borrows;*out_borrow=borrow;
    vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
static vm27_exit_borrow_v1 *vm27_exit_find_borrow_v1(vm27_exit_borrow_v1 *candidate) {
    for (vm27_exit_borrow_v1 *b=vm27_exit_borrows_v1;b;b=b->next)
        if (b==candidate) return b;
    return NULL;
}
vm27_exit_status_v1 vm27_exit_borrow_v1_view(vm27_exit_borrow_v1 *candidate,
    const unsigned char **out_storage) {
    if (!out_storage) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_borrow_v1 *borrow=vm27_exit_find_borrow_v1(candidate);
    if (!borrow || borrow->released) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (!pthread_equal(borrow->borrower_thread,pthread_self())) {vm27_exit_unlock_v1();return VM27_EXIT_WRONG_THREAD_V1;}
    vm27_exit_owner_v1 *owner=NULL;vm27_exit_status_v1 status=vm27_exit_admit_v1(borrow->owner,borrow->epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    vm27_exit_entry_v1 *entry=vm27_exit_find_entry_v1(owner,borrow->entry->identity);
    if (entry!=borrow->entry || !entry->published || entry->draining || !entry->storage ||
        owner->generation!=borrow->owner_generation || entry->cpu_generation!=borrow->cpu_generation ||
        !entry->borrows) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (vm27_exit_private_alias_v1(out_storage,sizeof(*out_storage))) {vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;}
    *out_storage=entry->storage;vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_borrow_v1_release(vm27_exit_borrow_v1 *candidate) {
    vm27_exit_lock_v1();vm27_exit_borrow_v1 *borrow=vm27_exit_find_borrow_v1(candidate);
    if (!borrow || borrow->released) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (!pthread_equal(borrow->borrower_thread,pthread_self())) {vm27_exit_unlock_v1();return VM27_EXIT_WRONG_THREAD_V1;}
    if (borrow->owner->operation) {vm27_exit_unlock_v1();return VM27_EXIT_BUSY_V1;}
    --borrow->entry->borrows;borrow->released=1;
    vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_update_mock_success_v1(vm27_exit_owner_v1 *candidate,
    uint64_t epoch,uint64_t identity,int mock_status,const void *raw,size_t bytes) {
    // Refuse failed status/width before any raw pointer access.
    if (mock_status || bytes!=VM27_EXIT_STORAGE_BYTES_V1 || !raw || !identity) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=NULL;
    vm27_exit_status_v1 status=vm27_exit_admit_v1(candidate,epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    vm27_exit_entry_v1 *entry=vm27_exit_find_entry_v1(owner,identity);
    if (!entry || !entry->published || entry->draining || !entry->storage ||
        entry->epoch!=epoch || entry->owner_generation!=owner->generation) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (vm27_exit_private_alias_v1(raw,bytes)) {vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;}
    memcpy(entry->storage,raw,VM27_EXIT_STORAGE_BYTES_V1);
    vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_destroy_v1(vm27_exit_owner_v1 *candidate,
    uint64_t epoch,uint64_t identity) {
    if (!identity) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=NULL;
    vm27_exit_status_v1 status=vm27_exit_admit_v1(candidate,epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    vm27_exit_entry_v1 *entry=vm27_exit_find_entry_v1(owner,identity);
    if (!entry || !entry->published || entry->draining || !entry->storage) {vm27_exit_unlock_v1();return VM27_EXIT_NOT_LIVE_V1;}
    if (entry->borrows) {vm27_exit_unlock_v1();return VM27_EXIT_BUSY_V1;}
    owner->operation=1;vm27_exit_mock_ops_v1 ops=owner->ops;vm27_exit_unlock_v1();
    int result=ops.complete_mock_destroy(ops.context);
    vm27_exit_lock_v1();
    if (result) {owner->operation=0;vm27_exit_unlock_v1();return VM27_EXIT_MOCK_FAILURE_V1;}
    entry->published=0;entry->draining=1;
    // Admission excluded new borrows throughout callback; existing count was0.
    free(entry->storage);entry->storage=NULL;owner->operation=0;
    vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
vm27_exit_status_v1 vm27_exit_owner_stats_v1(vm27_exit_owner_v1 *candidate,uint64_t epoch,
    vm27_exit_stats_v1 *out) {
    if (!out) return VM27_EXIT_BAD_ARGUMENT_V1;
    vm27_exit_lock_v1();vm27_exit_owner_v1 *owner=NULL;
    vm27_exit_status_v1 status=vm27_exit_admit_v1(candidate,epoch,&owner);
    if (status!=VM27_EXIT_OK_V1) {vm27_exit_unlock_v1();return status;}
    if (vm27_exit_private_alias_v1(out,sizeof(*out))) {vm27_exit_unlock_v1();return VM27_EXIT_BAD_ARGUMENT_V1;}
    vm27_exit_stats_v1 stats={0};stats.owner_epoch=owner->epoch;stats.owner_generation=owner->generation;
    for (vm27_exit_entry_v1 *e=owner->entries;e;e=e->next) {
        stats.published+=e->published!=0;stats.retained_borrows+=e->borrows;
        stats.persistent_storage+=e->storage!=NULL;stats.destroyed_tombstones+=e->draining!=0;
    }
    *out=stats;vm27_exit_unlock_v1();return VM27_EXIT_OK_V1;
}
