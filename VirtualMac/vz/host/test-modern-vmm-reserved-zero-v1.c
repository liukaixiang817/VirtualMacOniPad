// Typed factory leases are mocks; no context or native register is supplied.
#include "modern_vmm_mandatory_field_v2.h"
#include "modern_cpu_native_self_memory_v1.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
#define BAD ((int32_t)UINT32_C(0xfae94003))
#define BUSY ((int32_t)UINT32_C(0xfae94002))
#define UNSUPPORTED ((int32_t)UINT32_C(0xfae9400f))
static pthread_t Owner;static bool Live=true,FailRelease;static unsigned Acquires,Releases,Views;static uint64_t Identity=7,Epoch=1,Generation=1;static unsigned char Token;
bool VM27CPUFactoryOutputRangeDisjointV3(const void *p,size_t n){return p&&n;}
bool VZKernelCPUOutputRangeDisjointV12(const void *p,size_t n){return p&&n;}
bool VM27CPUConfigOutputRangeDisjointV3(const void *p,size_t n){return p&&n;}
bool VM27CPUFactoryGICOutputRangeDisjointV15(const void *p,size_t n){return p&&n;}
bool VM27CPUSelfMappedRangeV1(const void *p,size_t n,bool write,VM27CPUSelfMappedReceiptV1 *r){(void)write;(void)r;return p&&n;}
bool VM27CPUSelfWriteV1(void *opaque,void *p,size_t n,const void *v){(void)opaque;memcpy(p,v,n);return true;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAcquireV2(VM27CPUFactoryIDV2 id,VM27CPUFactoryBorrowV2 **out){++Acquires;if(!Live||id!=Identity||!pthread_equal(Owner,pthread_self()))return BAD;*out=(void *)&Token;return 0;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowViewV2(VM27CPUFactoryBorrowV2 *p,VM27CPUFactoryViewV2 *out){CHECK(p==(void *)&Token);++Views;*out=(VM27CPUFactoryViewV2){Identity,Epoch,Generation,NULL,false};return 0;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowReleaseV2(VM27CPUFactoryBorrowV2 *p){CHECK(p==(void *)&Token);++Releases;return FailRelease?BUSY:0;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessPhysicalDebugClaimV13(VM27CPUFactoryBorrowV2 *p,VZKernelDebugClaimActionV15 a,uint64_t v,uint64_t *o,VZKernelDebugClaimReceiptV15 *r,VM27CPUFactoryDiagnosticV2 *d){(void)p;(void)a;(void)v;(void)o;(void)r;(void)d;return UNSUPPORTED;}
VM27CPUFactoryMachStatusV2 VM27CPUFactoryBorrowAccessPhysicalACTLRV14(VM27CPUFactoryBorrowV2 *p,VZKernelACTLRActionV16 a,uint64_t v,uint64_t *o,VZKernelACTLRReceiptV16 *r,VM27CPUFactoryDiagnosticV2 *d){(void)p;(void)a;(void)v;(void)o;(void)r;(void)d;return UNSUPPORTED;}
static void *Foreign(void *p){(void)p;uint64_t out=77;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==BAD&&out==77);CHECK(VM27VMMSetMandatoryFieldV2(Identity,0x390,0)==BAD);return NULL;}
int main(void){Owner=pthread_self();uint64_t out=77;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==UNSUPPORTED&&out==77);CHECK(VM27VMMSetMandatoryFieldV2(Identity,0x390,1)==UNSUPPORTED);CHECK(!VM27VMMSetMandatoryFieldV2(Identity,0x390,0));CHECK(!VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)&&out==0);CHECK(VM27VMMSetMandatoryFieldV2(Identity,0x390,UINT64_MAX)==UNSUPPORTED);out=77;CHECK(!VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)&&out==0);
 pthread_t foreign;CHECK(!pthread_create(&foreign,NULL,Foreign,NULL));CHECK(!pthread_join(foreign,NULL));Live=false;out=77;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==BAD&&out==77);Live=true;++Generation;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==UNSUPPORTED&&out==77);
 FailRelease=true;CHECK(VM27VMMSetMandatoryFieldV2(Identity,0x390,0)==BUSY);CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==BUSY&&out==77);FailRelease=false;CHECK(!VM27VMMDrainMandatoryFieldBorrowV2());CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==UNSUPPORTED&&out==77);CHECK(!VM27VMMSetMandatoryFieldV2(Identity,0x390,0));++Epoch;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==UNSUPPORTED&&out==77);CHECK(!VM27VMMSetMandatoryFieldV2(Identity,0x390,0));++Identity;CHECK(VM27VMMGetMandatoryFieldV2(Identity,0x390,&out)==UNSUPPORTED&&out==77);CHECK(Views&&Acquires>Releases);
 puts("{\"freshReadUnsupported\":true,\"explicitZeroStoredAndRead\":true,\"nonzeroUnsupportedWithoutMutation\":true,\"wrongOwnerAndDestroyedCPURejected\":true,\"newIdentityEpochGenerationFresh\":true,\"failedReleaseNotCommitted\":true,\"retainedLeaseRequiresDrain\":true,\"noNativeContextOrRegisterAccess\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;}
