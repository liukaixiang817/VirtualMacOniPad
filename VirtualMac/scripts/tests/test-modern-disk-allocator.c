// App-private typed allocation ABI test. All allocations are owned by this
// process and released by the genuine Darwin allocator; no VM or disk calls.
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#ifndef VM27_DISK_ALLOCATOR_UUID
#error "The builder must pin the exact provider UUID"
#endif
typedef void *(*MallocFn)(size_t, uint64_t);
typedef void *(*CallocFn)(size_t, size_t, uint64_t);
typedef void *(*ReallocFn)(void *, size_t, uint64_t);
static MallocFn allocate, page_allocate;
static CallocFn clear_allocate;
static ReallocFn resize;
struct Results { unsigned checks, failures, allocations, releases; };
static void Check(struct Results *r, bool ok) { ++r->checks; if (!ok) ++r->failures; }
static void Release(struct Results *r, void *p) { if (p) { free(p); ++r->releases; } }
static bool Read(const void *p, void *out, size_t n) {
    vm_size_t got=0;
    return p && n <= 65536 && vm_read_overwrite(mach_task_self(),
        (vm_address_t)p,n,(vm_address_t)out,&got)==KERN_SUCCESS && got==n;
}
static bool Identity(const void *p,const char *expected) {
    Dl_info d={0}; struct mach_header_64 h;
    p=ptrauth_strip(p,ptrauth_key_function_pointer);
    if (!p || !dladdr(p,&d) || !Read(d.dli_fbase,&h,sizeof(h)) ||
        h.magic!=MH_MAGIC_64 || h.cputype!=CPU_TYPE_ARM64 ||
        h.cpusubtype!=(cpu_subtype_t)0x80000002 || h.sizeofcmds>65536 || h.ncmds>1024) return false;
    const unsigned char *at=(const unsigned char *)d.dli_fbase+sizeof(h);
    const unsigned char *end=at+h.sizeofcmds; unsigned found=0;
    char actual[PATH_MAX],uuid[33];
    if (!realpath(d.dli_fname,actual) || strcmp(actual,expected)) return false;
    for (unsigned i=0;i<h.ncmds;++i) {
        struct load_command c;
        if (end-at<8 || !Read(at,&c,8) || c.cmdsize<8 || c.cmdsize%8 || c.cmdsize>(size_t)(end-at)) return false;
        if (c.cmd==LC_UUID) {
            struct uuid_command u;
            if (c.cmdsize!=sizeof(u) || !Read(at,&u,sizeof(u))) return false;
            for (unsigned j=0;j<16;++j) snprintf(uuid+j*2,3,"%02x",u.uuid[j]);
            if (strcmp(uuid,VM27_DISK_ALLOCATOR_UUID)) return false;
            ++found;
        }
        at+=c.cmdsize;
    }
    return at==end && found==1;
}
static void *Worker(void *arg) {
    struct Results *r=arg;
    const size_t sizes[]={1,7,16,4095,4096,4097,16384};
    const size_t page=(size_t)getpagesize();
    for (unsigned iteration=0;iteration<64;++iteration) {
        const size_t n=sizes[iteration%7];
        const uint64_t type=UINT64_C(0xfedcba9876543210)^iteration;
        unsigned char *p=allocate(n,type); Check(r,p!=NULL);
        if (p) {
            ++r->allocations; memset(p,0x5a,n);
            unsigned char *q=resize(p,n+127,type); Check(r,q!=NULL);
            if (q) { bool same=true; for(size_t j=0;j<n;++j) same&=q[j]==0x5a; Check(r,same); p=q; }
            Release(r,p);
        }
        unsigned char *z=clear_allocate(3,n,type); Check(r,z!=NULL);
        if (z) { ++r->allocations;bool zero=true;for(size_t j=0;j<3*n;++j)zero&=z[j]==0;Check(r,zero);Release(r,z); }
        unsigned char *v=page_allocate(n,type); Check(r,v!=NULL);
        if (v) { ++r->allocations;Check(r,(uintptr_t)v%page==0);memset(v,0xa5,n);Check(r,v[n-1]==0xa5);Release(r,v); }
    }
    return NULL;
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0); if(argc!=2)return 64;
    char expected[PATH_MAX];if(!realpath(argv[1],expected))return 65;
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!lib)return 66;
    const char *names[]={"malloc_type_malloc","malloc_type_calloc","malloc_type_realloc","malloc_type_valloc"};
    void *symbols[4];for(unsigned i=0;i<4;++i){symbols[i]=dlsym(lib,names[i]);if(!Identity(symbols[i],expected))return 67;}
    allocate=(MallocFn)symbols[0];clear_allocate=(CallocFn)symbols[1];resize=(ReallocFn)symbols[2];page_allocate=(MallocFn)symbols[3];
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%d,\"providerUUID\":\"%s\",\"runtimeEntryIdentities\":4,\"pageSize\":%d}\n",getpid(),getuid(),VM27_DISK_ALLOCATOR_UUID,getpagesize());
    pthread_t workers[4];struct Results rows[4]={{0}};
    unsigned created=0,joined=0;for(;created<4;++created)if(pthread_create(&workers[created],NULL,Worker,&rows[created]))break;
    for(unsigned i=0;i<created;++i)if(pthread_join(workers[i],NULL)==0)++joined;
    struct Results total={0};for(unsigned i=0;i<created;++i){total.checks+=rows[i].checks;total.failures+=rows[i].failures;total.allocations+=rows[i].allocations;total.releases+=rows[i].releases;}
    Check(&total,created==4 && joined==4);Check(&total,total.allocations==total.releases);
    void *zero=page_allocate(0,0); Check(&total,!zero || (uintptr_t)zero%(size_t)getpagesize()==0);if(zero){++total.allocations;Release(&total,zero);}
    void *overflow=clear_allocate(SIZE_MAX,2,UINT64_MAX);Check(&total,overflow==NULL);if(overflow){++total.allocations;Release(&total,overflow);}
    void *from_null=resize(NULL,31,UINT64_MAX);Check(&total,from_null!=NULL);if(from_null){++total.allocations;memset(from_null,0x3c,31);Release(&total,from_null);}
    bool passed=created==4 && joined==4 && !total.failures && total.allocations==total.releases;
    printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"allocations\":%u,\"releases\":%u,\"workersJoined\":%u,\"iterations\":256,\"VMCalls\":0,\"diskCalls\":0,\"GPUCalls\":0,\"passed\":%s}\n",total.checks,total.failures,total.allocations,total.releases,joined,passed?"true":"false");
    if(dlclose(lib))return 68;
    return passed?0:1;
}
