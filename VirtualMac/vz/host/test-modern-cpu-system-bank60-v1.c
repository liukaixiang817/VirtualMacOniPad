#include "modern_cpu_kernel_system_v3_private.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {unsigned char bytes[0x8000];unsigned writes;} State;
static bool Read(void *p,uint32_t offset,size_t n,void *out) {
 State *s=p;assert(n==8 && offset+n<=sizeof(s->bytes));memcpy(out,s->bytes+offset,n);return true;
}
static bool Write(void *p,uint32_t offset,size_t n,const void *value) {
 State *s=p;assert(n==8 && (offset==0x810 || offset==0x808 || offset==0x748));
 ++s->writes;memcpy(s->bytes+offset,value,n);return true;
}
int main(void) {
 VZKernelSysDescriptor d={0};
 assert(!VZKernelSysLookup(0xe788,&d) && d.nativeOffset==0x810 && d.nativeReadyDirtyMask==(UINT64_C(1)<<60));
 assert(!VZKernelSysLookup(0xe789,&d) && d.nativeOffset==0x808 && d.nativeReadyDirtyMask==(UINT64_C(1)<<60));
 assert(!VZKernelSysLookup(0xe78c,&d) && d.nativeOffset==0x760 && d.nativeReadyDirtyMask==(UINT64_C(1)<<57));
 State state={0};uint64_t ready=UINT64_MAX,oldDirty=UINT64_C(1)<<57;
 memcpy(state.bytes+0x4100,&ready,8);memcpy(state.bytes+0x748,&oldDirty,8);
 VZKernelInitAccess access={&state,Read,Write};VZKernelSysFeatureCache cache={0};
 VZKernelSysRequest request={.schemaVersion=1,.validatedKernelProfile=VZ_KERNEL_PROFILE_IPADOS_16_1_1,.nativeHVISA=2,.action=VZ_KERNEL_SYS_WRITE,.identifier=0xe788,.value=UINT64_C(0x123456789abcdef0)};
 VZKernelSysReceipt receipt={0};
 assert(!VZKernelSysApplyVerifiedRouteV3(&request,&access,&cache,NULL,&receipt,NULL));
 request.identifier=0xe789;request.value=UINT64_C(0x88aabbccddeeff11);
 assert(!VZKernelSysApplyVerifiedRouteV3(&request,&access,&cache,NULL,&receipt,NULL));
 uint64_t value=0,dirty=0;memcpy(&value,state.bytes+0x810,8);assert(value==UINT64_C(0x123456789abcdef0));
 memcpy(&value,state.bytes+0x808,8);assert(value==request.value);memcpy(&dirty,state.bytes+0x748,8);
 assert(dirty==(oldDirty|(UINT64_C(1)<<60)) && state.writes==4);
 puts("{\"actualSYSRouteExecuted\":true,\"e788e789UseTrueKernelBank60\":true,\"physicalOffsetsAndValuesPreserved\":true,\"existingDirty57Preserved\":true,\"noDirty56Introduced\":true,\"group57Unchanged\":true,\"nativeCallsExecuted\":0,\"deviceOperations\":0}");return 0;
}
