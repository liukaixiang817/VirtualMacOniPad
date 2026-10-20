#include "vm27_iosurface_guest_transform_unavailable_v1.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#if defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__)
#error This finite memory fixture must not execute on an iPad
#endif
static unsigned checks;
static void check(int value) { ++checks;if(!value)abort(); }
int main(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);check(page>=4096);
    unsigned char *mapping=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
    check(mapping!=MAP_FAILED);check(!mprotect(mapping+page,page,PROT_NONE));
    unsigned char expected[1552],before[1552];unsigned calls=0;
    for(unsigned command=0;command<4;++command)for(unsigned shape=0;shape<4;++shape) {
        size_t size=shape==0?32:shape==1?1552:shape==2?31:1551;
        unsigned char *packet=mapping+page-size;
        memset(packet,0xa5,size);memcpy(packet,&command,4);memcpy(before,packet,size);memcpy(expected,packet,size);
        int valid=(command==1&&size==32)||(command==2&&size==1552);
        if(valid){uint32_t status=(uint32_t)kIOReturnUnsupported;memcpy(expected+4,&status,4);}
        IOReturn result=VM27IOSurfaceGuestTransformUnavailableV1((void *)(uintptr_t)1,packet,size);++calls;
        check(result==(valid?kIOReturnUnsupported:kIOReturnBadArgument));check(!memcmp(packet,expected,size));
        if(!valid)check(!memcmp(packet,before,size));
    }
    /* An unaligned packet uses the actual byte contract, not a cast to an
     * invented generic packet structure. Adjacent bytes remain unchanged. */
    unsigned char unaligned[34];memset(unaligned,0x6a,sizeof(unaligned));uint32_t command=1;
    memcpy(unaligned+1,&command,4);
    check(VM27IOSurfaceGuestTransformUnavailableV1(NULL,unaligned+1,32)==kIOReturnUnsupported);++calls;
    check(unaligned[0]==0x6a&&unaligned[33]==0x6a);
    for(size_t size=0;size<32;++size){
        check(VM27IOSurfaceGuestTransformUnavailableV1((void *)(uintptr_t)1,(void *)(uintptr_t)1,size)==kIOReturnBadArgument);++calls;
    }
    check(VM27IOSurfaceGuestTransformUnavailableV1(NULL,NULL,32)==kIOReturnBadArgument);++calls;
    check(VM27IOSurfaceGuestTransformUnavailableV1(NULL,(void *)(UINTPTR_MAX-3),32)==kIOReturnBadArgument);++calls;
    check(!munmap(mapping,page*2));
    printf("{\"checks\":%u,\"calls\":%u,\"passed\":true,\"nativeAcceleratorCalls\":0,\"deviceOperations\":0}\n",checks,calls);
    return 0;
}
