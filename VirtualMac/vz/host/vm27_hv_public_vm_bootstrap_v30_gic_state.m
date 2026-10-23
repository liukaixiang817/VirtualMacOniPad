#include "vm27_hv_public_vm_bootstrap_v12.h"
#include "modern_gic_state_v1.h"
__attribute__((visibility("hidden"))) __typeof__(hv_gic_state_create) VM27GICUnsupportedStateCreateV30;
__attribute__((visibility("hidden"))) __typeof__(hv_gic_state_get_size) VM27GICUnsupportedStateSizeV30;
__attribute__((visibility("hidden"))) __typeof__(hv_gic_state_get_data) VM27GICUnsupportedStateDataV30;
__attribute__((visibility("hidden"))) __typeof__(hv_gic_set_state) VM27GICUnsupportedStateSetV30;
#define hv_gic_state_create VM27GICUnsupportedStateCreateV30
#define hv_gic_state_get_size VM27GICUnsupportedStateSizeV30
#define hv_gic_state_get_data VM27GICUnsupportedStateDataV30
#define hv_gic_set_state VM27GICUnsupportedStateSetV30
#include "vm27_hv_public_vm_bootstrap_v29_caller_frame.m"
#undef hv_gic_state_create
#undef hv_gic_state_get_size
#undef hv_gic_state_get_data
#undef hv_gic_set_state
__attribute__((visibility("hidden"))) hv_return_t VM27CPUFactoryGICStateV1(
 VM27CPUFactoryVMV2 *,void *,size_t,bool);
@interface OS_VM27GICStateV1 : OS_object
@end
typedef struct GICStateEntryV30 {
 struct GICStateEntryV30 *next;
 const void *object;
 void *data;
 size_t bytes;
} GICStateEntryV30;
static pthread_mutex_t GICStateMutexV30=PTHREAD_MUTEX_INITIALIZER;
static GICStateEntryV30 *GICStatesV30;
static void StateLockV30(void){if(pthread_mutex_lock(&GICStateMutexV30))abort();}
static void StateUnlockV30(void){if(pthread_mutex_unlock(&GICStateMutexV30))abort();}
static bool GICStateOutputDisjointV30(const void *p,size_t bytes) {
 StateLockV30();bool valid=Disjoint(p,bytes,&GICStateMutexV30,sizeof(GICStateMutexV30)) &&
  Disjoint(p,bytes,&GICStatesV30,sizeof(GICStatesV30));
 for(GICStateEntryV30 *e=GICStatesV30;e && valid;e=e->next)
  valid=Disjoint(p,bytes,e,sizeof(*e)) && Disjoint(p,bytes,e->object,64) && Disjoint(p,bytes,e->data,e->bytes);
 StateUnlockV30();return valid;
}
@implementation OS_VM27GICStateV1
- (void)dealloc {
 StateLockV30();GICStateEntryV30 **link=&GICStatesV30;
 while(*link && (*link)->object!=self)link=&(*link)->next;
 GICStateEntryV30 *e=*link;if(e)*link=e->next;StateUnlockV30();
 if(e){memset(e->data,0,e->bytes);free(e->data);free(e);}[super dealloc];
}
@end
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
hv_gic_state_t hv_gic_state_create(void) {
 if(!Begin())return NULL;
 GICLockV9();VM27CPUFactoryVMV2 *vm=GICBackendV9.installed && !GICBackendV9.controllerDetached?GICBackendV9.vm:NULL;GICUnlockV9();
 size_t bytes=VM27GICStateBytesV1();void *data=vm?calloc(1,bytes):NULL;
 hv_return_t status=!data?Error(5):VM27CPUFactoryGICStateV1(vm,data,bytes,false);
 if(status){free(data);End();dprintf(2,"[VM27GICStateV1] capture-failed status=0x%08x\n",status);return NULL;}
 GICStateEntryV30 *e=calloc(1,sizeof(*e));Class cls=[OS_VM27GICStateV1 class];
 id object=e && class_getInstanceSize(cls)==8?_os_object_alloc(cls,64):nil;
 if(!object){free(e);free(data);End();return NULL;}
 e->object=object;e->data=data;e->bytes=bytes;StateLockV30();e->next=GICStatesV30;GICStatesV30=e;StateUnlockV30();End();
 dprintf(2,"[VM27GICStateV1] captured bytes=%zu\n",bytes);return (hv_gic_state_t)(void *)object;
}
#pragma clang diagnostic pop
static GICStateEntryV30 *RetainStateV30(hv_gic_state_t state) {
 StateLockV30();GICStateEntryV30 *e=GICStatesV30;
 while(e && e->object!=state)e=e->next;
 if(e)CFRetain((CFTypeRef)e->object);StateUnlockV30();return e;
}
hv_return_t hv_gic_state_get_size(hv_gic_state_t state,size_t *out) {
 if(!GICCallerOutputV9(out,sizeof(*out)) || !GICStateOutputDisjointV30(out,sizeof(*out)))return Error(3);
 GICStateEntryV30 *e=RetainStateV30(state);if(!e)return Error(3);
 *out=e->bytes;CFRelease((CFTypeRef)e->object);return 0;
}
hv_return_t hv_gic_state_get_data(hv_gic_state_t state,void *out) {
 GICStateEntryV30 *e=RetainStateV30(state);if(!e)return Error(3);
 hv_return_t status=GICCallerOutputV9(out,e->bytes) && GICStateOutputDisjointV30(out,e->bytes)?0:Error(3);
 if(!status)memcpy(out,e->data,e->bytes);CFRelease((CFTypeRef)e->object);return status;
}
hv_return_t hv_gic_set_state(const void *input,size_t bytes) {
 if(bytes!=VM27GICStateBytesV1() || !OutputBeforeLock(input,bytes) ||
  !VM27CPUSelfMappedRangeV1(input,bytes,false,NULL))return Error(3);
 void *copy=calloc(1,bytes);if(!copy)return Error(5);memcpy(copy,input,bytes);
 if(!Begin()){free(copy);return Error(2);}
 GICLockV9();VM27CPUFactoryVMV2 *vm=GICBackendV9.installed && !GICBackendV9.controllerDetached?GICBackendV9.vm:NULL;GICUnlockV9();
 hv_return_t status=!vm?Error(3):VM27CPUFactoryGICStateV1(vm,copy,bytes,true);
 End();memset(copy,0,bytes);free(copy);
 dprintf(2,"[VM27GICStateV1] restored bytes=%zu status=0x%08x\n",bytes,status);return status;
}
