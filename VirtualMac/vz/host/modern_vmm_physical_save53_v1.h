#ifndef VM27_VMM_PHYSICAL_SAVE53_V1_H
#define VM27_VMM_PHYSICAL_SAVE53_V1_H
#include "modern_cpu_native_public_factory_v14.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
 uint32_t originalSaveCallRVA,logicalSYS,modernField,oldNativeField,frameOffset;
 uint64_t bankMask;
} VM27VMMPhysicalSaveFieldV1;
typedef struct {
 VM27CPUFactoryMachStatusV2 status;
 VM27VMMPhysicalSaveFieldV1 sourceField;
 VM27CPUFactoryDiagnosticV2 factory;
 VZKernelSysReceipt sys;
 bool frameWriteAttempted,frameWriteComplete,completeModernFrame,fullSaveRestore59;
} VM27VMMPhysicalSaveReceiptV1;
// Call only from a selected genuine SAVE site after its original guest feature
// branch. A real retained borrow must span the caller's wider save sequence.
// This is one field dispatch, never an unconditional loop over all 53 fields.
VM27CPUFactoryMachStatusV2 VM27VMMReadOriginalPhysicalSaveFieldV1(
 VM27CPUFactoryBorrowV2 *,uint32_t originalSaveCallRVA,void *,size_t,
 VM27VMMPhysicalSaveReceiptV1 *);
#ifdef __cplusplus
}
#endif
#endif
