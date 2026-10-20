#include "modern_cpu_native_self_memory_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
extern bool VM27CPUSelfMappedRangeOldV1(const void *,size_t,bool,VM27CPUSelfMappedReceiptV1 *);
#define CHECK(x) do { if(!(x)){fprintf(stderr,"check failed at %d: %s\n",__LINE__,#x);return 1;}++checks;}while(0)
int main(void) {
 unsigned checks=0;size_t page=(size_t)getpagesize(),count=64,total=page*count;
 char temporary[]="/private/tmp/vm27-ram-regions-XXXXXX";
 int fd=mkstemp(temporary);if(fd<0)return 2;unlink(temporary);
 if(ftruncate(fd,(off_t)total)){close(fd);return 2;}
 void *base=mmap(NULL,total,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(base==MAP_FAILED){close(fd);return 2;}
 // Reversed file offsets prevent adjacent pages merging into one VM region.
 for(size_t i=0;i<count;++i)if(mmap((char *)base+i*page,page,PROT_READ|PROT_WRITE,
     MAP_SHARED|MAP_FIXED,fd,(off_t)((count-1-i)*page))==MAP_FAILED)return 2;
 VM27CPUSelfMappedReceiptV1 old={0},now={0};
 CHECK(!VM27CPUSelfMappedRangeOldV1(base,total,true,&old) && old.queries==8);
 CHECK(VM27CPUSelfMappedRangeV1(base,total,true,&now) && now.queries==count);
 CHECK(now.releasedObjectPorts<=now.queries && now.portReleaseStatus==0);
 if(mprotect((char *)base+31*page,page,PROT_NONE))return 2;
 CHECK(!VM27CPUSelfMappedRangeV1(base,total,true,NULL));
 if(mprotect((char *)base+31*page,page,PROT_READ))return 2;
 CHECK(!VM27CPUSelfMappedRangeV1(base,total,true,NULL));
 CHECK(VM27CPUSelfMappedRangeV1(base,total,false,NULL));
 CHECK(!VM27CPUSelfMappedRangeV1(base,0,true,NULL));
 CHECK(!VM27CPUSelfMappedRangeV1((void *)(UINTPTR_MAX-8),16,true,NULL));
 if(munmap(base,total)||close(fd))return 2;
 printf("actualHostVMRegionChecks=%u distinctRegions=%zu oldBudgetRejected=1 newRangeVerified=1 nativeHypervisorCalls=0\n",checks,count);
 return 0;
}
