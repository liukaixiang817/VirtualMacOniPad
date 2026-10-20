#include "vm27_iosurface_guest_transform_unavailable_v1.h"
#include <stdint.h>
#include <string.h>
_Static_assert(sizeof(IOReturn)==4,"The actual caller consumes IOReturn32");
_Static_assert((uint32_t)kIOReturnBadArgument==UINT32_C(0xe00002c2),"SDK status ABI");
_Static_assert((uint32_t)kIOReturnUnsupported==UINT32_C(0xe00002c7),"SDK status ABI");

IOReturn VM27IOSurfaceGuestTransformUnavailableV1(const void *actualAccelerator,
                                                void *packet,size_t packetBytes) {
    (void)actualAccelerator;
    if(!packet || (packetBytes!=32 && packetBytes!=1552) ||
       (uintptr_t)packet>UINTPTR_MAX-packetBytes) return kIOReturnBadArgument;
    uint32_t command;
    memcpy(&command,packet,sizeof(command));
    if((command!=1 || packetBytes!=32) && (command!=2 || packetBytes!=1552))
        return kIOReturnBadArgument;
    /* The genuine Mac caller reads this status field. Preserve every other
     * packet byte, including all unknown payload and embedded addresses. */
    const uint32_t status=(uint32_t)kIOReturnUnsupported;
    memcpy((unsigned char *)packet+4,&status,sizeof(status));
    return kIOReturnUnsupported;
}
