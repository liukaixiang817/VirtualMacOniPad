#ifndef VM27_VMM_MANDATORY_PHYSICAL_FRAME_V1_H
#define VM27_VMM_MANDATORY_PHYSICAL_FRAME_V1_H
#include "modern_cpu_native_public_factory_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
// These are the two mandatory private physical fields in the genuine modern
// save/restore frame. This partial bridge does not claim the complete frame.
enum { VM27_VMM_MANDATORY_FRAME_MIN_BYTES_V1=0x600,
 VM27_VMM_CLAIM_FRAME_OFFSET_V1=0x5d8,VM27_VMM_ACTLR_FRAME_OFFSET_V1=0x5f8 };
typedef enum {VM27_VMM_MANDATORY_SAVE_V1=1,VM27_VMM_MANDATORY_RESTORE_V1=2}
 VM27VMMMandatoryFrameActionV1;
typedef struct {
 VM27CPUFactoryMachStatusV2 status,releaseStatus;
 uint64_t vmEpoch,cpuGeneration,publicIdentity;
 VZKernelDebugClaimReceiptV15 claim;
 VZKernelACTLRReceiptV16 actlr;
 bool borrowAcquired,claimComplete,actlrComplete,frameWriteAttempted,frameWriteComplete;
 bool completeModernFrame,fullSaveRestore59;
 // Failed release remains retained in the actual owner thread's bridge.
 // Drain with the explicit function below; it never frees backing or CPU.
 bool borrowRetained;
} VM27VMMMandatoryFrameReceiptV1;
VM27CPUFactoryMachStatusV2 VM27VMMAccessMandatoryPhysicalFrameV1(
 hv_vcpu_t,VM27VMMMandatoryFrameActionV1,void *,size_t,VM27VMMMandatoryFrameReceiptV1 *);
VM27CPUFactoryMachStatusV2 VM27VMMDrainMandatoryPhysicalFrameBorrowV1(void);
#ifdef __cplusplus
}
#endif
#endif
