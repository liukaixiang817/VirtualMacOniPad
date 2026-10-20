#include "vm27_owned_app_child_startup_v3.h"
#include "vm27_actual_executable_image_v1.h"
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
/* Child-only dependency, retaining the V3 bootstrap ABI and stable V3 DSO
 * install name. The frontend must never load this constructor-bearing unit. */
static VM27OwnedAppChildV1 *ActualChildStartupOwnerV4;
static bool ActualOriginalChildV4(void) {
    static const uint8_t uuid[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
        0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    VM27ActualExecutableImageV1 image = {0};
    return !VM27ActualExecutableImageFindSelfV1(&image) &&
        !memcmp(image.uuid, uuid, sizeof(uuid));
}
__attribute__((constructor)) static void ActualOwnedChildPreMainV4(void) {
    /* This UUID is a role boundary. The unchanged V3 bootstrap independently
     * authenticates getppid's live audit identity, kernel CD, CS_VALID and
     * native entitlement Booleans before accepting configuration. */
    if (!ActualOriginalChildV4() ||
        VM27OwnedAppChildBootstrapBeforeMainV3(&ActualChildStartupOwnerV4)) _exit(78);
    /* Preserve the true startup/control owner for original Main's lifetime.
     * No native VM/CPU operation or installer runs in this constructor. */
}
