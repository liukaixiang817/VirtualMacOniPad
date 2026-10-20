#include "modern_vmm_mandatory_physical_frame_v1.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include <stdint.h>
#include <string.h>

extern bool VM27CPUFactoryOutputRangeDisjointV3(const void *,size_t);
static VM27CPUFactoryMachStatusV2 FrameBadV1(void) {return (int32_t)UINT32_C(0xfae94003);}
static VM27CPUFactoryMachStatusV2 FrameErrorV1(void) {return (int32_t)UINT32_C(0xfae94001);}
static VM27CPUFactoryMachStatusV2 FrameBusyV1(void) {return (int32_t)UINT32_C(0xfae94002);}
static _Thread_local VM27CPUFactoryBorrowV2 *FrameRetainedLeaseV1;
static _Thread_local bool FrameOperationV1;
static bool FrameRangeV1(const void *p,size_t n,bool write) {
 return p && n && n<=UINTPTR_MAX-(uintptr_t)p &&
  VM27CPUFactoryOutputRangeDisjointV3(p,n) && VZKernelCPUOutputRangeDisjointV12(p,n) &&
  VM27CPUConfigOutputRangeDisjointV3(p,n) && VM27CPUSelfMappedRangeV1(p,n,write,NULL);
}
static bool FrameDisjointV1(const void *a,size_t an,const void *b,size_t bn) {
 return an<=UINTPTR_MAX-(uintptr_t)a && bn<=UINTPTR_MAX-(uintptr_t)b &&
  ((uintptr_t)a+an<=(uintptr_t)b || (uintptr_t)b+bn<=(uintptr_t)a);
}
VM27CPUFactoryMachStatusV2 VM27VMMAccessMandatoryPhysicalFrameV1(hv_vcpu_t identity,
 VM27VMMMandatoryFrameActionV1 action,void *frame,size_t bytes,VM27VMMMandatoryFrameReceiptV1 *out) {
 if(FrameOperationV1 || FrameRetainedLeaseV1)return FrameBusyV1();
 if((action!=VM27_VMM_MANDATORY_SAVE_V1 && action!=VM27_VMM_MANDATORY_RESTORE_V1) ||
  bytes<VM27_VMM_MANDATORY_FRAME_MIN_BYTES_V1 ||
  !FrameRangeV1(frame,bytes,action==VM27_VMM_MANDATORY_SAVE_V1) ||
  !FrameRangeV1(out,sizeof(*out),true) || !FrameDisjointV1(frame,bytes,out,sizeof(*out)))return FrameBadV1();
 FrameOperationV1=true;
 VM27VMMMandatoryFrameReceiptV1 r={0};VM27CPUFactoryBorrowV2 *borrow=NULL;
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowAcquireV2(identity,&borrow);
 r.borrowAcquired=status==0;VM27CPUFactoryViewV2 view={0};uint64_t claim=0,actlr=0;
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&view);
 if(!status) {r.vmEpoch=view.vmEpoch;r.cpuGeneration=view.cpuGeneration;r.publicIdentity=view.identity;}
 if(!status && action==VM27_VMM_MANDATORY_RESTORE_V1) {
  uint8_t byte=0;
  if(!VM27CPUSelfReadV1(NULL,(const unsigned char *)frame+VM27_VMM_CLAIM_FRAME_OFFSET_V1,1,&byte) ||
   !VM27CPUSelfReadV1(NULL,(const unsigned char *)frame+VM27_VMM_ACTLR_FRAME_OFFSET_V1,8,&actlr))status=FrameErrorV1();
  claim=byte;
 }
 if(!status) {
  status=VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13(borrow,
   action==VM27_VMM_MANDATORY_SAVE_V1?VZ_KERNEL_DEBUG_CLAIM_READ_V15:VZ_KERNEL_DEBUG_CLAIM_WRITE_V15,
   action==VM27_VMM_MANDATORY_SAVE_V1?0:claim,
   action==VM27_VMM_MANDATORY_SAVE_V1?&claim:NULL,&r.claim,NULL);r.claimComplete=status==0;
 }
 if(!status) {
  status=VM27CPUFactoryBorrowAccessPhysicalACTLRV14(borrow,
   action==VM27_VMM_MANDATORY_SAVE_V1?VZ_KERNEL_ACTLR_READ_V16:VZ_KERNEL_ACTLR_WRITE_V16,
   action==VM27_VMM_MANDATORY_SAVE_V1?0:actlr,
   action==VM27_VMM_MANDATORY_SAVE_V1?&actlr:NULL,&r.actlr,NULL);r.actlrComplete=status==0;
 }
 if(!status && action==VM27_VMM_MANDATORY_SAVE_V1) {
  // Both fields are staged first. No failed CPU read can publish a partial
  // frame; the genuine widths remain one byte and eight bytes respectively.
  if(!FrameRangeV1(frame,bytes,true))status=FrameBadV1();
  else {
   uint8_t byte=(uint8_t)claim;r.frameWriteAttempted=true;
   r.frameWriteComplete=VM27CPUSelfWriteV1(NULL,(unsigned char *)frame+VM27_VMM_CLAIM_FRAME_OFFSET_V1,1,&byte) &&
    VM27CPUSelfWriteV1(NULL,(unsigned char *)frame+VM27_VMM_ACTLR_FRAME_OFFSET_V1,8,&actlr);
   if(!r.frameWriteComplete)status=FrameErrorV1();
  }
 }
 if(borrow) {
  r.releaseStatus=VM27CPUFactoryBorrowReleaseV2(borrow);
  if(r.releaseStatus){FrameRetainedLeaseV1=borrow;r.borrowRetained=true;if(!status)status=r.releaseStatus;}
 }
 r.status=status;
 if(!FrameRangeV1(out,sizeof(*out),true)){FrameOperationV1=false;return FrameBadV1();}
 *out=r;FrameOperationV1=false;return status;
}
VM27CPUFactoryMachStatusV2 VM27VMMDrainMandatoryPhysicalFrameBorrowV1(void) {
 if(FrameOperationV1)return FrameBusyV1();
 if(!FrameRetainedLeaseV1)return 0;
 FrameOperationV1=true;
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowReleaseV2(FrameRetainedLeaseV1);
 if(!status)FrameRetainedLeaseV1=NULL;
 FrameOperationV1=false;return status;
}
