#include <stdint.h>
#include <stdio.h>
static int32_t VM27NativeTrapWithFailureDiagnosticV3(uint64_t,void *);
#define VM27ProductionNativeTrapV1 VM27NativeTrapWithFailureDiagnosticV3
#include "modern_cpu_production_native_ops_v2.c"
#undef VM27ProductionNativeTrapV1
extern int32_t VM27ProductionNativeTrapV1(uint64_t,void *);
static int32_t VM27NativeTrapWithFailureDiagnosticV3(uint64_t operation,void *arguments) {
 int32_t result=VM27ProductionNativeTrapV1(operation,arguments);
 if(result)dprintf(2,"[Independent27HV] failed stage=native-trap operation=%llu nativeReturn=%d raw=0x%08x\n",(unsigned long long)operation,result,(unsigned)result);
 return result;
}
