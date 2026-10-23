/* Keep Create/Deliver's existing complete native endpoint gate. The native
 * restore path also requests an optional terminate-all message, even after
 * Create reported unimpErr. Route this third weak import through the same gate
 * so an absent iOS endpoint cannot become an authenticated branch to NULL. */
#include "vm27_owned_vt_host_unavailable_v1.c"

typedef int32_t (*VTCreateTerminateMessageV2)(void **);
__attribute__((visibility("default")))
int32_t VM27OwnedVTCreateTerminateMessageV2(void **outMessage) {
    int incomingErrno=errno;
    void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    if (!VTAdmissionV1(caller,UINT64_C(0xdf6c0)) || !outMessage) {
        errno=ENOTSUP; __builtin_trap();
    }
    VTCreateV1 create=NULL; VTDeliverV1 deliver=NULL;
    if (!VTNativeEndpointV1(&create,&deliver)) {
        *outMessage=NULL;
        VTUnavailableLogV1("terminate-all-message");
        errno=incomingErrno; return -4; /* unimpErr: no message/session made. */
    }
    VTCreateTerminateMessageV2 native=(VTCreateTerminateMessageV2)
        dlsym(RTLD_DEFAULT,"VTParavirtualizationHostSessionCreateTerminateAllSessionsMessage");
    /* NativeEndpoint has just authenticated all five genuine native exports.
     * No unload or process-global interposition occurs in this provider. */
    if (!native) { *outMessage=NULL; errno=incomingErrno; return -4; }
    errno=incomingErrno;
    return native(outMessage);
}
