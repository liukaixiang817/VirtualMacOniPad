#include "modern_vmm_mandatory_field_v2.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include <stdint.h>

extern bool VM27CPUFactoryOutputRangeDisjointV3(const void *,size_t);
static VM27CPUFactoryMachStatusV2 FieldBadV2(void) {return (int32_t)UINT32_C(0xfae94003);}
static VM27CPUFactoryMachStatusV2 FieldErrorV2(void) {return (int32_t)UINT32_C(0xfae94001);}
static VM27CPUFactoryMachStatusV2 FieldBusyV2(void) {return (int32_t)UINT32_C(0xfae94002);}
static _Thread_local VM27CPUFactoryBorrowV2 *FieldRetainedLeaseV2;
static _Thread_local bool FieldOperationV2;
static size_t FieldWidthV2(uint32_t field) {
 return field==VM27_VMM_FIELD_DEBUG_CLAIM_V2?1:field==VM27_VMM_FIELD_ACTLR_V2?8:0;
}
static bool FieldRangeV2(void *output,size_t bytes) {
 return output && bytes && bytes<=UINTPTR_MAX-(uintptr_t)output &&
  VM27CPUFactoryOutputRangeDisjointV3(output,bytes) && VZKernelCPUOutputRangeDisjointV12(output,bytes) &&
  VM27CPUConfigOutputRangeDisjointV3(output,bytes) && VM27CPUFactoryGICOutputRangeDisjointV15(output,bytes) &&
  VM27CPUSelfMappedRangeV1(output,bytes,true,NULL);
}
static VM27CPUFactoryMachStatusV2 FieldAccessV2(hv_vcpu_t identity,uint32_t field,
 bool read,uint64_t value,void *output) {
 if(FieldOperationV2 || FieldRetainedLeaseV2)return FieldBusyV2();
 const size_t width=FieldWidthV2(field);
 if(!width || (read && !FieldRangeV2(output,width)) ||
  (!read && field==VM27_VMM_FIELD_DEBUG_CLAIM_V2 && value>UINT8_MAX))return FieldBadV2();
 FieldOperationV2=true;
 VM27CPUFactoryBorrowV2 *borrow=NULL;
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowAcquireV2(identity,&borrow);
 VM27CPUFactoryViewV2 before={0},after={0};uint64_t actual=0;
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&before);
 if(!status && before.identity!=identity)status=FieldBadV2();
 if(!status && field==VM27_VMM_FIELD_DEBUG_CLAIM_V2) {
  VZKernelDebugClaimReceiptV15 receipt={0};
  status=VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13(borrow,
   read?VZ_KERNEL_DEBUG_CLAIM_READ_V15:VZ_KERNEL_DEBUG_CLAIM_WRITE_V15,
   read?0:value,read?&actual:NULL,&receipt,NULL);
 } else if(!status) {
  VZKernelACTLRReceiptV16 receipt={0};
  status=VM27CPUFactoryBorrowAccessPhysicalACTLRV14(borrow,
   read?VZ_KERNEL_ACTLR_READ_V16:VZ_KERNEL_ACTLR_WRITE_V16,
   read?0:value,read?&actual:NULL,&receipt,NULL);
 }
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&after);
 if(!status && (before.identity!=after.identity || before.vmEpoch!=after.vmEpoch ||
  before.cpuGeneration!=after.cpuGeneration))status=FieldBadV2();
 if(borrow) {
  VM27CPUFactoryMachStatusV2 released=VM27CPUFactoryBorrowReleaseV2(borrow);
  if(released){FieldRetainedLeaseV2=borrow;if(!status)status=released;}
 }
 // Publish only after the actual owner operation and its release succeed.
 // This also preserves the genuine byte store between MDCCINT and ACTLR.
 if(!status && read) {
  const uint8_t byte=(uint8_t)actual;
  if(!FieldRangeV2(output,width))status=FieldBadV2();
  else if(!VM27CPUSelfWriteV1(NULL,output,width,width==1?(const void *)&byte:(const void *)&actual))status=FieldErrorV2();
 }
 FieldOperationV2=false;
 return status;
}
VM27CPUFactoryMachStatusV2 VM27VMMGetMandatoryFieldV2(hv_vcpu_t identity,uint32_t field,void *output) {
 return FieldAccessV2(identity,field,true,0,output);
}
VM27CPUFactoryMachStatusV2 VM27VMMSetMandatoryFieldV2(hv_vcpu_t identity,uint32_t field,uint64_t value) {
 return FieldAccessV2(identity,field,false,value,NULL);
}
VM27CPUFactoryMachStatusV2 VM27VMMDrainMandatoryFieldBorrowV2(void) {
 if(FieldOperationV2)return FieldBusyV2();
 if(!FieldRetainedLeaseV2)return 0;
 FieldOperationV2=true;
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowReleaseV2(FieldRetainedLeaseV2);
 if(!status)FieldRetainedLeaseV2=NULL;
 FieldOperationV2=false;return status;
}
