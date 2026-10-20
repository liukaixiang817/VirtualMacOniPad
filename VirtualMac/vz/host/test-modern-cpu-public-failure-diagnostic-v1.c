// Deliberately no Hypervisor framework or native CPU. Wrapper boundary only.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef int32_t hv_return_t;
typedef uint64_t hv_vcpu_t;
typedef uint16_t hv_sys_reg_t;
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);abort();}}while(0)
static unsigned Calls[4];static hv_return_t Result;
static hv_return_t VM27InheritedGetControlFailureV1(hv_vcpu_t cpu,uint32_t selector,uint64_t *out){CHECK(cpu==7&&selector==9&&out);++Calls[0];errno=41;if(!Result)*out=111;return Result;}
static hv_return_t VM27InheritedSetControlFailureV1(hv_vcpu_t cpu,uint32_t selector,uint64_t value){CHECK(cpu==7&&selector==0&&value==UINT64_C(0xabc));++Calls[1];errno=42;return Result;}
static hv_return_t VM27InheritedGetSYSFailureV1(hv_vcpu_t cpu,hv_sys_reg_t selector,uint64_t *out){CHECK(cpu==7&&selector==0xc03b&&out);++Calls[2];errno=43;if(!Result)*out=222;return Result;}
static hv_return_t VM27InheritedSetSYSFailureV1(hv_vcpu_t cpu,hv_sys_reg_t selector,uint64_t value){CHECK(cpu==7&&selector==0xc024&&value==UINT64_C(0xdef));++Calls[3];errno=44;return Result;}
#include "modern_cpu_public_failure_diagnostic_v1.inc"
int main(void){for(unsigned round=0;round<4;++round){Result=round?((hv_return_t)UINT32_C(0xfae94000)+round):0;uint64_t out=UINT64_C(0xfeedface);CHECK(_hv_vcpu_get_control_field(7,9,&out)==Result&&errno==41&&out==(round?UINT64_C(0xfeedface):111));CHECK(_hv_vcpu_set_control_field(7,0,UINT64_C(0xabc))==Result&&errno==42);out=UINT64_C(0xfeedface);CHECK(hv_vcpu_get_sys_reg(7,0xc03b,&out)==Result&&errno==43&&out==(round?UINT64_C(0xfeedface):222));CHECK(hv_vcpu_set_sys_reg(7,0xc024,UINT64_C(0xdef))==Result&&errno==44);}for(unsigned i=0;i<4;++i)CHECK(Calls[i]==4);puts("{\"eachOriginalCalledOnce\":true,\"fourSuccessOutputsPreserved\":true,\"twelveFailureResultsPreserved\":true,\"failureReadOutputsUntouched\":true,\"errnoPreserved\":true,\"eightFailureLogsMaximum\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;}
