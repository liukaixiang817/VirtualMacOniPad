#include "modern_vmm_physical_save53_v1.h"
#include "modern_cpu_native_self_memory_v1.h"
#include "modern_cpu_config_os_object_v3_private.h"
#include <stdint.h>
extern bool VM27CPUFactoryOutputRangeDisjointV3(const void *,size_t);
static const VM27VMMPhysicalSaveFieldV1 SaveFieldsV1[]={
#include "modern_vmm_physical_save53_fields_v1.inc"
};
_Static_assert(sizeof(SaveFieldsV1)/sizeof(SaveFieldsV1[0])==53,"genuine matched field count");
static VM27CPUFactoryMachStatusV2 SaveBadV1(void){return (int32_t)UINT32_C(0xfae94003);}
static VM27CPUFactoryMachStatusV2 SaveErrorV1(void){return (int32_t)UINT32_C(0xfae94001);}
static bool SaveRangeV1(const void *p,size_t n) {
 return p && n && n<=UINTPTR_MAX-(uintptr_t)p &&
  VM27CPUFactoryOutputRangeDisjointV3(p,n) && VZKernelCPUOutputRangeDisjointV12(p,n) &&
  VM27CPUConfigOutputRangeDisjointV3(p,n) && VM27CPUSelfMappedRangeV1(p,n,true,NULL);
}
VM27CPUFactoryMachStatusV2 VM27VMMReadOriginalPhysicalSaveFieldV1(
 VM27CPUFactoryBorrowV2 *borrow,uint32_t call,void *frame,size_t bytes,
 VM27VMMPhysicalSaveReceiptV1 *out) {
 const VM27VMMPhysicalSaveFieldV1 *field=NULL;
 for(unsigned i=0;i<53;++i)if(SaveFieldsV1[i].originalSaveCallRVA==call){field=&SaveFieldsV1[i];break;}
 if(!field || bytes<field->frameOffset+8 || !SaveRangeV1(frame,bytes) ||
  !SaveRangeV1(out,sizeof(*out)) ||
  !((uintptr_t)frame+bytes<=(uintptr_t)out || (uintptr_t)out+sizeof(*out)<=(uintptr_t)frame))return SaveBadV1();
 VM27VMMPhysicalSaveReceiptV1 r={0};r.sourceField=*field;uint64_t actual=0;
 VM27CPUFactoryViewV2 before={0},after={0};
 VM27CPUFactoryMachStatusV2 status=VM27CPUFactoryBorrowViewV2(borrow,&before);
 if(!status)status=VM27CPUFactoryBorrowAccessSystemV4(borrow,VZ_KERNEL_SYS_READ,field->logicalSYS,0,&actual,&r.sys,&r.factory);
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&after);
 if(!status && (after.identity!=before.identity || after.vmEpoch!=before.vmEpoch ||
  after.cpuGeneration!=before.cpuGeneration))status=SaveBadV1();
 if(!status) {
  if(!SaveRangeV1(frame,bytes))status=SaveBadV1();
  else {
   r.frameWriteAttempted=true;
   r.frameWriteComplete=VM27CPUSelfWriteV1(NULL,(unsigned char *)frame+field->frameOffset,8,&actual);
   if(!r.frameWriteComplete)status=SaveErrorV1();
  }
 }
 r.status=status;
 if(!SaveRangeV1(out,sizeof(*out)))return SaveBadV1();
 *out=r;return status;
}
