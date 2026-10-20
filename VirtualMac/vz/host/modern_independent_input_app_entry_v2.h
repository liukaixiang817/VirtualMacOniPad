#import "vm27_own_uikit_ingress_endpoint_v1.h"
NS_ASSUME_NONNULL_BEGIN
/* Main UIKit thread. Devices and executor come from the independently loaded
 * genuine27 VM owner. Actual profile, backend, UIKit and executor validation
 * are prerequisites; this declaration does not open any availability gate. */
BOOL VZIndependent27ConnectGenuineInput(id pointing, id keyboard,
    id<VM27ProvenOwnInputExecutorV1> executor, uint64_t epoch,
    uint64_t coordinates, NSError * _Nullable * _Nullable error);
/* The VM owner must obtain OK/Closed here before releasing its actual VM. */
VM27InputResult VZIndependent27CloseInput(void);
NS_ASSUME_NONNULL_END
