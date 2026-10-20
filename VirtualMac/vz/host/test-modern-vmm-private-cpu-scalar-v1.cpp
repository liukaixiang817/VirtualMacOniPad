#include "modern_vmm_private_cpu_scalar_v1.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <pthread.h>
#include <unistd.h>
extern "C" {
hv_vcpu_t VM27ScalarFixtureBeginV1(void);
void VM27ScalarFixtureSeedV1(uint32_t,uint64_t);
uint64_t VM27ScalarFixtureFieldV1(uint32_t);
void VM27ScalarFixtureFailV1(bool,bool);
void VM27ScalarFixtureEndV1(bool);
unsigned VM27ScalarFixtureChecksV1(void);
}
static unsigned Checks;
#define CHECK(v) do{++Checks;if(!(v)){std::fprintf(stderr,"FAIL %d %s\n",__LINE__,#v);std::abort();}}while(0)
struct OriginalFailureV1 {int32_t status;};
static void Failure(int32_t status){throw OriginalFailureV1{status};}
static const struct {uint32_t call,selector,field,oldField,frame;uint64_t bank;} Fields[]={
#include "modern_vmm_physical_save53_fields_v1.inc"
};
template<class F>static void ExpectFailure(F fn,uint32_t expected) {
 bool caught=false;try{fn();}catch(const OriginalFailureV1 &error){caught=true;CHECK((uint32_t)error.status==expected);}
 CHECK(caught);
}
static void *Foreign(void *opaque) {
 hv_vcpu_t cpu=*(hv_vcpu_t *)opaque;
 ExpectFailure([&]{(void)VM27VMMReadCPUScalarV1(cpu,0x8010,Failure);},0xfae94003);
 ExpectFailure([&]{VM27VMMWriteCPUScalarV1(cpu,0x6a0,3,Failure);},0xfae94003);
 return nullptr;
}
int main() {
 alarm(20);hv_vcpu_t cpu=VM27ScalarFixtureBeginV1();CHECK(cpu);
 for(const auto &row:Fields) {
  uint64_t before=UINT64_C(0xa1b2c3d400000000)|row.selector;
  VM27ScalarFixtureSeedV1(row.oldField,before);
  CHECK(VM27VMMReadCPUScalarV1(cpu,row.selector,Failure)==before);
  uint64_t value=~before;VM27VMMWriteCPUScalarV1(cpu,row.selector,value,Failure);
  CHECK(VM27ScalarFixtureFieldV1(row.oldField)==value);
  CHECK(VM27VMMReadCPUScalarV1(cpu,row.selector,Failure)==value);
 }
 CHECK(VM27VMMReadCPUScalarV1(cpu,0x6a0,Failure)==0x83);
 VM27VMMWriteCPUScalarV1(cpu,0x6a0,0x44,Failure);
 CHECK(VM27VMMReadCPUScalarV1(cpu,0x6a0,Failure)==0x44);
 uint64_t original=UINT64_C(0xfedcba9876543210);
 CHECK(VM27VMMReadCPUScalarV1(cpu,0x410,Failure)==original);
 for(uint32_t flag:{0u,1u,2u,3u,0xffu}) {
  VM27VMMUpdateACTLRBit1V1(cpu,flag,Failure);
  CHECK(VM27ScalarFixtureFieldV1(0x3f8)==((original&~UINT64_C(2))|((uint64_t)(flag&1)<<1)));
 }
 ExpectFailure([&]{(void)VM27VMMReadCPUScalarV1(cpu,0x390,Failure);},0xfae94003);
 ExpectFailure([&]{VM27VMMWriteCPUScalarV1(cpu,0x6a0,0x100,Failure);},0xfae94003);
 pthread_t thread;CHECK(!pthread_create(&thread,nullptr,Foreign,&cpu));CHECK(!pthread_join(thread,nullptr));
 VM27ScalarFixtureFailV1(true,false);
 ExpectFailure([&]{(void)VM27VMMReadCPUScalarV1(cpu,0x8010,Failure);},0xfae94001);
 ExpectFailure([&]{VM27VMMUpdateACTLRBit1V1(cpu,0,Failure);},0xfae94001);
 VM27ScalarFixtureEndV1(false);
 cpu=VM27ScalarFixtureBeginV1();VM27ScalarFixtureFailV1(false,true);
 ExpectFailure([&]{VM27VMMWriteCPUScalarV1(cpu,0x410,0x1234,Failure);},0xfae94001);
 CHECK(VM27ScalarFixtureFieldV1(0x3f8)==0x1234);VM27ScalarFixtureEndV1(true);
 std::printf("{\"checks\":%u,\"actualRoot11OwnerFixtureChecks\":%u,\"actual53NativeFieldPairs\":true,\"truePrivateClaimAndACTLR\":true,\"originalACTLRBit1FlagSemantics\":true,\"errorStatusPropagatedViaCallerCallback\":true,\"partialWriteRetainsActualOwnerCleanup\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0,\"full27Backend\":false}\n",Checks,VM27ScalarFixtureChecksV1());
}
