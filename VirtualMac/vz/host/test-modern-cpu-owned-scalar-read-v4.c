#include "modern_cpu_owned_mapping_cache_v4_scalar_read.c"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
static void *Foreign(void *p) {unsigned char out[16];assert(!VM27CPUOwnedScalarReadV4(p,8,out));return NULL;}
int main(void) {
 unsigned char *p=mmap(NULL,0xc000,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0);assert(p!=MAP_FAILED);assert(!mprotect(p,0x8000,PROT_READ|PROT_WRITE));
 for(unsigned i=0;i<0x8000;i++)p[i]=(unsigned char)(i*17+3);assert(!mprotect(p+0x4000,0x4000,PROT_READ));
 uint64_t thread=0;assert(!pthread_threadid_np(NULL,&thread));uintptr_t top=(uintptr_t)pthread_get_stackaddr_np(pthread_self());size_t stack=pthread_get_stacksize_np(pthread_self());
 assert(VM27CPUOwnedMappingPublishV1(0,1,thread,(uintptr_t)p,3,1,top-stack,stack,true));
 unsigned char out[32]={0};unsigned offsets[]={0,1,0x3ff1,0x3ffc,0x4000,0x4110,0x7ff0};unsigned widths[]={1,2,4,8,16};
 for(unsigned i=0;i<7;i++)for(unsigned j=0;j<5;j++){assert(VM27CPUOwnedScalarReadV4(p+offsets[i],widths[j],out));assert(!memcmp(out,p+offsets[i],widths[j]));}
 assert(!VM27CPUOwnedScalarReadV4(p,17,out));assert(!VM27CPUOwnedScalarReadV4(p,0,out));assert(!VM27CPUOwnedScalarReadV4(p+0x7ff8,16,out));
 unsigned char *heap=malloc(32);assert(!VM27CPUOwnedScalarReadV4(p,8,heap));free(heap);
 pthread_t t;assert(!pthread_create(&t,NULL,Foreign,p));assert(!pthread_join(t,NULL));
 atomic_store_explicit(&mappings[0].taskPID,getpid()+1,memory_order_relaxed);assert(!VM27CPUOwnedScalarReadV4(p,8,out));atomic_store_explicit(&mappings[0].taskPID,getpid(),memory_order_relaxed);
 VM27CPUOwnedMappingWithdrawV1(0,1,NULL);assert(!mprotect(p,0x8000,PROT_NONE));assert(!VM27CPUOwnedScalarReadV4(p,8,out));
 assert(!mprotect(p,0x8000,PROT_READ|PROT_WRITE));assert(VM27CPUOwnedMappingPublishV1(0,2,thread,(uintptr_t)p,2,0,top-stack,stack,true));
 assert(!VM27CPUOwnedScalarReadV4(p,8,out));assert(!VM27CPUOwnedScalarReadV4(p+0x3ffc,8,out));assert(VM27CPUOwnedScalarReadV4(p+0x4000,8,out));
 VM27CPUOwnedMappingWithdrawV1(0,2,NULL);assert(!munmap(p,0xc000));puts("PASS: real scalar reads, cross-page permissions, foreign thread and PID, heap rejection, withdrawal and readmitted metadata-only page");return 0;
}
