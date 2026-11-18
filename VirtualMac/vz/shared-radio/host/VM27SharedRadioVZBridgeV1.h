#import "../../host/vm27_genuine_vz_ssh_bridge_v3.h"
FOUNDATION_EXPORT BOOL VM27AttachSharedRadiosToVMV1(id vm, NSString *nativeImage, NSError **error);
FOUNDATION_EXPORT BOOL VM27HasSharedRadioOwnerV1(id vm);
FOUNDATION_EXPORT BOOL VM27SharedRadioRequestForVMV1(id vm, NSDictionary *request,
                                                    void (^completion)(NSDictionary *reply));
FOUNDATION_EXPORT void VM27CloseSharedRadiosForVMV1(id vm, void (^completion)(NSError *));
// Link-time adapter around the existing verified SSH factory. The original
// factory still owns its admission checks and unchanged SSH listener.
FOUNDATION_EXPORT BOOL VM27CreateGenuineVZSSHBridgeV3WithSharedRadiosV1(
    id vm, NSString *image, uint32_t idleMilliseconds, uint16_t tcpPort,
    unsigned scope, unsigned families, VM27GenuineVZSSHBridgeV1 **owner, NSError **error);
