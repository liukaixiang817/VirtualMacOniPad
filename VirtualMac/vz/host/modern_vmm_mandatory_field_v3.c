// The original two physical fields keep their complete retained-owner path.
#define VM27VMMGetMandatoryFieldV2 VM27VMMInheritedGetMandatoryFieldV3
#define VM27VMMSetMandatoryFieldV2 VM27VMMInheritedSetMandatoryFieldV3
#include "modern_vmm_mandatory_field_v2.c"
#undef VM27VMMGetMandatoryFieldV2
#undef VM27VMMSetMandatoryFieldV2
// This selector names original VMM frame reserved_0, not a native offset or SYS.
#define VM27_VMM_RESERVED_ZERO_LOGICAL_FIELD_V3 UINT32_C(0x390)
static _Thread_local VM27CPUFactoryViewV2 ReservedZeroOwnerV3;
static _Thread_local bool ReservedZeroValidV3;
static bool ReservedSameOwnerV3(const VM27CPUFactoryViewV2 *a,const VM27CPUFactoryViewV2 *b) {
 return a->identity==b->identity && a->vmEpoch==b->vmEpoch && a->cpuGeneration==b->cpuGeneration;
}
static VM27CPUFactoryMachStatusV2 ReservedZeroAccessV3(hv_vcpu_t identity,bool read,uint64_t value,void *output) {
 if(FieldOperationV2 || FieldRetainedLeaseV2)return FieldBusyV2();
 if((read && !FieldRangeV2(output,8)) || (read && value))return FieldBadV2();
 FieldOperationV2=true;VM27CPUFactoryBorrowV2 *borrow=NULL;
 VM27CPUFactoryViewV2 before={0},after={0};
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowAcquireV2(identity,&borrow);
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&before);
 if(!status && (!before.identity || before.identity!=identity || !before.vmEpoch || !before.cpuGeneration))status=FieldBadV2();
 bool stagedValid=false;
 if(!status) {
  // TLS is the actual owner pthread. The native factory permits one CPU per
  // owner; a new generation/VM/identity never inherits the former valid bit.
  if(!ReservedSameOwnerV3(&ReservedZeroOwnerV3,&before))ReservedZeroValidV3=false;
  stagedValid=ReservedZeroValidV3;
  if(read && !stagedValid)status=(int32_t)UINT32_C(0xfae9400f);
  else if(!read && value)status=(int32_t)UINT32_C(0xfae9400f);
  else if(!read)stagedValid=true;
 }
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&after);
 if(!status && !ReservedSameOwnerV3(&before,&after))status=FieldBadV2();
 if(borrow) {
  VM27CPUFactoryMachStatusV2 released=VM27CPUFactoryBorrowReleaseV2(borrow);
  if(released){FieldRetainedLeaseV2=borrow;if(!status)status=released;}
 }
 // The value is only the caller's explicitly admitted opaque zero metadata.
 // No native context, architecture register, dirty flag or guest state is read.
 if(!status) {
  ReservedZeroOwnerV3=before;ReservedZeroValidV3=stagedValid;
  if(read) {
   const uint64_t zero=0;
   if(!FieldRangeV2(output,8))status=FieldBadV2();
   else if(!VM27CPUSelfWriteV1(NULL,output,8,&zero))status=FieldErrorV2();
  }
 }
 FieldOperationV2=false;return status;
}
VM27CPUFactoryMachStatusV2 VM27VMMGetMandatoryFieldV2(hv_vcpu_t identity,uint32_t field,void *output) {
 return field==VM27_VMM_RESERVED_ZERO_LOGICAL_FIELD_V3?ReservedZeroAccessV3(identity,true,0,output):VM27VMMInheritedGetMandatoryFieldV3(identity,field,output);
}
VM27CPUFactoryMachStatusV2 VM27VMMSetMandatoryFieldV2(hv_vcpu_t identity,uint32_t field,uint64_t value) {
 return field==VM27_VMM_RESERVED_ZERO_LOGICAL_FIELD_V3?ReservedZeroAccessV3(identity,false,value,NULL):VM27VMMInheritedSetMandatoryFieldV3(identity,field,value);
}
