#include "vm27_hv_public_vm_bootstrap_v9.h"
#include "modern_cpu_native_self_memory_v1.h"
// Preserve every frozen VM/RAM operation. Only teardown and the strong output
// guard gain controller lifetime checks; inherited definitions stay hidden.
__attribute__((visibility("hidden"))) __typeof__(hv_vm_destroy) VM27GICInheritedDestroyV9;
__attribute__((visibility("hidden"))) __typeof__(VM27HVVMUninstallNativeOpsV1) VM27GICInheritedUninstallV9;
__attribute__((visibility("hidden"))) __typeof__(VM27HVVMOutputRangeDisjointV1) VM27GICInheritedVMOutputV9;
#define hv_vm_destroy VM27GICInheritedDestroyV9
#define VM27HVVMUninstallNativeOpsV1 VM27GICInheritedUninstallV9
#define VM27HVVMOutputRangeDisjointV1 VM27GICInheritedVMOutputV9
#include "vm27_hv_public_vm_bootstrap_v8.m"
#undef VM27HVVMOutputRangeDisjointV1
#undef VM27HVVMUninstallNativeOpsV1
#undef hv_vm_destroy

@interface OS_VM27GICConfigV1 : OS_object
@end
typedef struct GICConfigEntryV9 {
 struct GICConfigEntryV9 *next;
 const void *object;
 VM27CPUFactoryVMV2 *vm;
 VM27GICConfigV1 config;
 uint64_t generation;
 uint32_t fields;
 bool inUse;
} GICConfigEntryV9;
typedef struct {
 uintptr_t isaLayoutOnly;
 uint32_t internalRefsLayoutOnly,externalRefsLayoutOnly;
 uint64_t generation,distributorBase,redistributorBase,msiBase;
 uint32_t msiFirst,msiCount,fields,reserved;
} GICConfigStorageV9;
_Static_assert(sizeof(GICConfigStorageV9)==64 && offsetof(GICConfigStorageV9,generation)==16,
 "Actual OS_object64B layout preserves reference counts");
static pthread_mutex_t GICMutexV9=PTHREAD_MUTEX_INITIALIZER;
static GICConfigEntryV9 *GICConfigsV9;
static uint64_t GICNextGenerationV9=1;
static struct {
 VM27CPUFactoryVMV2 *vm;
 VM27GICConfigV1 config;
 VM27GICDeadlineSchedulerV1 *scheduler;
 bool installed,controllerDetached;
} GICBackendV9;
// A failed real borrow release retains a cleanup token on its genuine owner
// thread. It must never be discarded or replaced by a numeric CPU identity.
static _Thread_local VM27CPUFactoryBorrowV2 *GICDeferredBorrowV9;
static _Thread_local bool GICCPUAdmissionV9;
static void GICLockV9(void){if(pthread_mutex_lock(&GICMutexV9))abort();}
static void GICUnlockV9(void){if(pthread_mutex_unlock(&GICMutexV9))abort();}
static bool GICOutputLockedV9(const void *p,size_t n) {
 if(!p || !n || n>UINTPTR_MAX-(uintptr_t)p ||
  !Disjoint(p,n,&GICMutexV9,sizeof(GICMutexV9)) ||
  !Disjoint(p,n,&GICConfigsV9,sizeof(GICConfigsV9)) ||
  !Disjoint(p,n,&GICNextGenerationV9,sizeof(GICNextGenerationV9)) ||
  !Disjoint(p,n,&GICBackendV9,sizeof(GICBackendV9)) ||
  !Disjoint(p,n,&GICDeferredBorrowV9,sizeof(GICDeferredBorrowV9)) ||
  !Disjoint(p,n,&GICCPUAdmissionV9,sizeof(GICCPUAdmissionV9)))return false;
 for(GICConfigEntryV9 *e=GICConfigsV9;e;e=e->next)
  if(!Disjoint(p,n,e,sizeof(*e)) || !Disjoint(p,n,e->object,64))return false;
 return !GICBackendV9.scheduler || VM27GICDeadlineOutputDisjointV1(GICBackendV9.scheduler,p,n);
}
bool VM27HVVMOutputRangeDisjointV1(const void *p,size_t n) {
 if(!VM27GICInheritedVMOutputV9(p,n))return false;
 // Factory calls this while holding its registry. Do not enter Factory again.
 GICLockV9();bool valid=GICOutputLockedV9(p,n);GICUnlockV9();return valid;
}
static bool GICCallerOutputV9(const void *p,size_t n) {
 return OutputBeforeLock(p,n) && VM27CPUSelfMappedRangeV1(p,n,true,NULL);
}
static GICConfigEntryV9 *GICFindConfigV9(const void *p) {
 for(GICConfigEntryV9 *e=GICConfigsV9;e;e=e->next)if(e->object==p)return e;
 return NULL;
}
static void GICCopyStorageV9(GICConfigEntryV9 *e) {
 GICConfigStorageV9 *s=(void *)e->object;
 s->generation=e->generation;s->distributorBase=e->config.distributorBase;
 s->redistributorBase=e->config.redistributorBase;s->msiBase=e->config.msiBase;
 s->msiFirst=e->config.msiFirst;s->msiCount=e->config.msiCount;s->fields=e->fields;
}
@implementation OS_VM27GICConfigV1
- (void)dealloc {
 GICLockV9();GICConfigEntryV9 **link=&GICConfigsV9;
 while(*link && (*link)->object!=self)link=&(*link)->next;
 GICConfigEntryV9 *e=*link;
 if(e){if(e->inUse)abort();*link=e->next;}
 memset((unsigned char *)(void *)self+16,0,48);GICUnlockV9();free(e);
 [super dealloc];
}
@end
hv_gic_config_t hv_gic_config_create(void) {
 // The SDK requires a retained nonnull object created after the real VM. It
 // provides no error result for invalid creation order or allocation failure.
 if(!VM27CPUFactoryVMOutputGuardLinkedV7() || !Begin())abort();
 Lock();VM27CPUFactoryVMV2 *vm=Backend.vm;
 bool owner=Backend.installed && vm && !Backend.vmDestroyed && pthread_equal(Backend.owner,pthread_self());
 Unlock();VM27CPUFactoryVMGICDescriptionV15 d={0};
 if(!owner || VM27CPUFactoryVMGICDescribeV15(vm,&d) || !d.live){End();abort();}
 Class cls=[OS_VM27GICConfigV1 class];if(class_getInstanceSize(cls)!=8){End();abort();}
 GICConfigEntryV9 *e=calloc(1,sizeof(*e));if(!e){End();abort();}
 id object=_os_object_alloc(cls,64);if(!object){free(e);End();abort();}
 memset((unsigned char *)(void *)object+16,0,48);
 GICLockV9();
 if(GICNextGenerationV9==UINT64_MAX){GICUnlockV9();CFRelease((CFTypeRef)object);free(e);End();abort();}
 e->object=object;e->vm=vm;e->generation=GICNextGenerationV9++;
 e->config=(VM27GICConfigV1){.schemaVersion=1,.maxCPUs=VM27_GIC_CPUS_V1,.ipaBits=36,.vmEpoch=d.vmEpoch};
 GICCopyStorageV9(e);e->next=GICConfigsV9;GICConfigsV9=e;
 GICUnlockV9();End();return (hv_gic_config_t)(void *)object;
}
static hv_return_t GICSetBaseV9(hv_gic_config_t object,uint32_t field,uint64_t value) {
 uint64_t bytes=field==1?VM27_GIC_DIST_BYTES_V1:field==2?
  VM27_GIC_REDIST_BYTES_V1*VM27_GIC_CPUS_V1:VM27_GIC_MSI_BYTES_V1;
 uint64_t align=field==2?VM27_GIC_REDIST_BYTES_V1:VM27_GIC_DIST_BYTES_V1;
 if((field!=1 && field!=2 && field!=4) || value&(align-1) || value> (UINT64_C(1)<<36)-bytes)return Error(3);
 GICLockV9();GICConfigEntryV9 *e=GICFindConfigV9(object);
 hv_return_t status=!e?Error(3):e->inUse?Error(2):0;
 if(!status) {
  if(field==1)e->config.distributorBase=value;
  else if(field==2)e->config.redistributorBase=value;
  else e->config.msiBase=value;
  e->fields|=field;e->config.msiConfigured=(e->fields&12)==12;GICCopyStorageV9(e);
 }
 GICUnlockV9();return status;
}
hv_return_t hv_gic_config_set_distributor_base(hv_gic_config_t c,hv_ipa_t a){return GICSetBaseV9(c,1,a);}
hv_return_t hv_gic_config_set_redistributor_base(hv_gic_config_t c,hv_ipa_t a){return GICSetBaseV9(c,2,a);}
hv_return_t hv_gic_config_set_msi_region_base(hv_gic_config_t c,hv_ipa_t a){return GICSetBaseV9(c,4,a);}
hv_return_t hv_gic_config_set_msi_interrupt_range(hv_gic_config_t object,uint32_t first,uint32_t count) {
 if(first<32 || first>=VM27_GIC_INTIDS_V1 || !count || count>VM27_GIC_INTIDS_V1-first)return Error(3);
 GICLockV9();GICConfigEntryV9 *e=GICFindConfigV9(object);
 hv_return_t status=!e?Error(3):e->inUse?Error(2):0;
 if(!status){e->config.msiFirst=first;e->config.msiCount=count;e->fields|=8;
  e->config.msiConfigured=(e->fields&12)==12;GICCopyStorageV9(e);}
 GICUnlockV9();return status;
}
static hv_return_t GICStatusV9(VZKernelStatus s) {
 switch(s){case VZ_KERNEL_OK:return 0;case VZ_KERNEL_BUSY:return Error(2);
 case VZ_KERNEL_BAD_ARGUMENT:case VZ_KERNEL_WRONG_THREAD:case VZ_KERNEL_NOT_LIVE:return Error(3);
 case VZ_KERNEL_OUT_OF_MEMORY:return Error(5);case VZ_KERNEL_UNSUPPORTED:return Error(15);
 default:return Error(1);}
}
static VZKernelStatus GICWakeV9(void *vm,const VZKernelRunPendingRequestV14 *q) {
 return VM27CPUFactoryGICSignalWakeV15(vm,q);
}
hv_return_t hv_gic_create(hv_gic_config_t object) {
 if(!Begin())return Error(2);
 Lock();VM27CPUFactoryVMV2 *vm=Backend.vm;void *nativeContext=Backend.ops.context;
 bool valid=Backend.installed && vm && !Backend.vmDestroyed && pthread_equal(Backend.owner,pthread_self());Unlock();
 if(!valid){End();return Error(3);}
 VM27CPUFactoryVMGICDescriptionV15 d={0};hv_return_t status=VM27CPUFactoryVMGICDescribeV15(vm,&d);
 GICLockV9();GICConfigEntryV9 *e=GICFindConfigV9(object);VM27GICConfigV1 config={0};
 if(!status)status=!e || e->vm!=vm || e->config.vmEpoch!=d.vmEpoch || !d.live || (e->fields&3)!=3?Error(3):
  e->inUse || GICBackendV9.scheduler || GICBackendV9.installed || d.gicInstalled || d.liveCPUCount?Error(2):0;
 if(!status){e->inUse=true;config=e->config;CFRetain((CFTypeRef)object);}GICUnlockV9();
 if(status){End();return status;}
 VM27GICDeadlineBindingsV1 clock={nativeContext,vm,VZKernelReadPhysicalCounterV16,
  VZKernelReadPhysicalCounterFrequencyV17,GICWakeV9};
 VM27GICDeadlineSchedulerV1 *scheduler=NULL;
 status=GICStatusV9(VM27GICDeadlineCreateV1(d.vmEpoch,&clock,&scheduler));
 if(!status) {
  VM27CPUFactoryGICSchedulerV15 binding={scheduler,VM27GICDeadlineScheduleV1,VM27GICDeadlineDrainV1};
  status=VM27CPUFactoryVMGICInstallV15(vm,&config,&binding);
 }
 if(!status){GICLockV9();GICBackendV9.vm=vm;GICBackendV9.config=config;
  GICBackendV9.scheduler=scheduler;GICBackendV9.installed=true;GICBackendV9.controllerDetached=false;GICUnlockV9();}
 else if(scheduler) {
  VZKernelStatus cleanup=VM27GICDeadlineDestroyV1(scheduler);
  if(cleanup!=VZ_KERNEL_OK){GICLockV9();GICBackendV9.vm=vm;GICBackendV9.scheduler=scheduler;
   GICBackendV9.controllerDetached=true;GICUnlockV9();status=GICStatusV9(cleanup);}
 }
 GICLockV9();e->inUse=false;GICUnlockV9();CFRelease((CFTypeRef)object);End();return status;
}
// Controller methods carry the actual factory VM opaque handle. Factory takes
// its registry/VM operation lease before dereferencing; teardown cannot race it.
static hv_return_t GICVMAccessV9(VM27CPUFactoryVMGICActionV15 action,uint64_t selector,uint64_t value,uint64_t *out) {
 if(out && !GICCallerOutputV9(out,sizeof(*out)))return Error(3);
 GICLockV9();VM27CPUFactoryVMV2 *vm=GICBackendV9.installed && !GICBackendV9.controllerDetached?GICBackendV9.vm:NULL;
 GICUnlockV9();if(!vm)return Error(3);
 uint64_t staged=0;hv_return_t status=VM27CPUFactoryVMGICAccessV15(vm,action,selector,value,out?&staged:NULL);
 if(!status && out){if(!GICCallerOutputV9(out,sizeof(*out)))return Error(3);*out=staged;}return status;
}
hv_return_t hv_gic_set_spi(uint32_t id,bool level){return GICVMAccessV9(VM27_FACTORY_GIC_SPI_LEVEL_V15,id,level,NULL);}
hv_return_t hv_gic_send_msi(hv_ipa_t address,uint32_t id){return GICVMAccessV9(VM27_FACTORY_GIC_MSI_V15,address,id,NULL);}
hv_return_t hv_gic_get_distributor_reg(hv_gic_distributor_reg_t r,uint64_t *out){
 return !out?Error(3):GICVMAccessV9(VM27_FACTORY_GIC_DISTRIBUTOR_READ_V15,r,0,out);}
hv_return_t hv_gic_set_distributor_reg(hv_gic_distributor_reg_t r,uint64_t v){
 return GICVMAccessV9(VM27_FACTORY_GIC_DISTRIBUTOR_WRITE_V15,r,v,NULL);}
hv_return_t hv_gic_reset(void){return GICVMAccessV9(VM27_FACTORY_GIC_RESET_V15,0,0,NULL);}
__attribute__((visibility("hidden"))) hv_return_t VM27HVDrainGICBorrowV9(void) {
 if(GICCPUAdmissionV9)return Error(2);
 if(!GICDeferredBorrowV9)return 0;
 GICCPUAdmissionV9=true;hv_return_t status=VM27CPUFactoryBorrowReleaseV2(GICDeferredBorrowV9);
 if(!status)GICDeferredBorrowV9=NULL;GICCPUAdmissionV9=false;return status;
}
static hv_return_t GICCPUAccessV9(hv_vcpu_t id,VM27CPUFactoryCPUGICActionV15 action,
 uint32_t selector,bool write,uint64_t value,uint64_t *out) {
 if(GICCPUAdmissionV9)return Error(2);
 if(GICDeferredBorrowV9){hv_return_t s=VM27HVDrainGICBorrowV9();if(s)return s;}
 if(!write && (!out || !GICCallerOutputV9(out,sizeof(*out))))return Error(3);
 GICCPUAdmissionV9=true;VM27CPUFactoryBorrowV2 *borrow=NULL;
 hv_return_t status=VM27CPUFactoryBorrowAcquireV2(id,&borrow);uint64_t staged=0;
 VM27CPUFactoryViewV2 actual={0};
 if(!status)status=VM27CPUFactoryBorrowViewV2(borrow,&actual);
 if(!status)status=action?VM27CPUFactoryBorrowGICAccessV15(borrow,action,selector,value,write?NULL:&staged):Error(15);
 bool committed=!status && (write || (action==VM27_FACTORY_GIC_ICC_READ_V15 &&
  (selector==0xc640 || selector==0xc660)));
 if(borrow){hv_return_t release=VM27CPUFactoryBorrowReleaseV2(borrow);
  if(release){GICDeferredBorrowV9=borrow;status=release;}}
 if(!status && !write){if(!GICCallerOutputV9(out,sizeof(*out)))status=Error(3);else *out=staged;}
 if(status && committed) {
  // The controller may already have consumed an acknowledged interrupt. Its
  // genuine attachment still retains the CPU after this borrow's release.
  // Withdraw through that actual registry/owner, never replay the read.
  hv_return_t poisoned=VM27CPUFactoryPoisonGICCPUV15(id,actual.vmEpoch,actual.cpuGeneration);
  if(poisoned)status=poisoned;
 }
 GICCPUAdmissionV9=false;return status;
}
hv_return_t hv_gic_get_redistributor_base(hv_vcpu_t c,hv_ipa_t *out){
 return GICCPUAccessV9(c,VM27_FACTORY_GIC_REDISTRIBUTOR_BASE_V15,0,false,0,out);}
hv_return_t hv_gic_get_redistributor_reg(hv_vcpu_t c,hv_gic_redistributor_reg_t r,uint64_t *out){
 return GICCPUAccessV9(c,VM27_FACTORY_GIC_REDISTRIBUTOR_READ_V15,r,false,0,out);}
hv_return_t hv_gic_set_redistributor_reg(hv_vcpu_t c,hv_gic_redistributor_reg_t r,uint64_t v){
 return GICCPUAccessV9(c,VM27_FACTORY_GIC_REDISTRIBUTOR_WRITE_V15,r,true,v,NULL);}
hv_return_t hv_gic_get_icc_reg(hv_vcpu_t c,hv_gic_icc_reg_t r,uint64_t *out){
 return GICCPUAccessV9(c,VM27_FACTORY_GIC_ICC_READ_V15,r,false,0,out);}
hv_return_t hv_gic_set_icc_reg(hv_vcpu_t c,hv_gic_icc_reg_t r,uint64_t v){
 return GICCPUAccessV9(c,VM27_FACTORY_GIC_ICC_WRITE_V15,r,true,v,NULL);}
// EL2 is refused by the actual VM profile; these genuine SDK methods preserve
// outputs and validate an actual retained CPU instead of inventing ICH/ICV data.
hv_return_t hv_gic_get_ich_reg(hv_vcpu_t c,hv_gic_ich_reg_t r,uint64_t *out){return GICCPUAccessV9(c,0,r,false,0,out);}
hv_return_t hv_gic_set_ich_reg(hv_vcpu_t c,hv_gic_ich_reg_t r,uint64_t v){return GICCPUAccessV9(c,0,r,true,v,NULL);}
hv_return_t hv_gic_get_icv_reg(hv_vcpu_t c,hv_gic_icv_reg_t r,uint64_t *out){return GICCPUAccessV9(c,0,r,false,0,out);}
hv_return_t hv_gic_set_icv_reg(hv_vcpu_t c,hv_gic_icv_reg_t r,uint64_t v){return GICCPUAccessV9(c,0,r,true,v,NULL);}
hv_return_t hv_gic_get_msi_reg(hv_gic_msi_reg_t r,uint64_t *out) {
 if(!GICCallerOutputV9(out,sizeof(*out)))return Error(3);
 GICLockV9();bool live=GICBackendV9.installed && !GICBackendV9.controllerDetached && GICBackendV9.config.msiConfigured;
 uint64_t value=((uint64_t)GICBackendV9.config.msiFirst<<16)|GICBackendV9.config.msiCount;
 GICUnlockV9();if(!live || r!=8)return Error(3);*out=value;return 0;
}
hv_return_t hv_gic_set_msi_reg(hv_gic_msi_reg_t r,uint64_t v) {
 if(r!=0x40 || v>UINT32_MAX)return Error(3);
 GICLockV9();bool live=GICBackendV9.installed && !GICBackendV9.controllerDetached && GICBackendV9.config.msiConfigured;
 uint64_t address=GICBackendV9.config.msiBase+0x40;GICUnlockV9();
 return !live?Error(3):hv_gic_send_msi(address,(uint32_t)v);
}
static hv_return_t GICSizeV9(size_t *out,size_t value) {
 if(!GICCallerOutputV9(out,sizeof(*out)))return Error(3);*out=value;return 0;
}
hv_return_t hv_gic_get_distributor_size(size_t *out){return GICSizeV9(out,VM27_GIC_DIST_BYTES_V1);}
hv_return_t hv_gic_get_distributor_base_alignment(size_t *out){return GICSizeV9(out,VM27_GIC_DIST_BYTES_V1);}
hv_return_t hv_gic_get_redistributor_region_size(size_t *out){return GICSizeV9(out,VM27_GIC_REDIST_BYTES_V1*VM27_GIC_CPUS_V1);}
hv_return_t hv_gic_get_redistributor_size(size_t *out){return GICSizeV9(out,VM27_GIC_REDIST_BYTES_V1);}
hv_return_t hv_gic_get_redistributor_base_alignment(size_t *out){return GICSizeV9(out,VM27_GIC_REDIST_BYTES_V1);}
hv_return_t hv_gic_get_msi_region_size(size_t *out){return GICSizeV9(out,VM27_GIC_MSI_BYTES_V1);}
hv_return_t hv_gic_get_msi_region_base_alignment(size_t *out){return GICSizeV9(out,VM27_GIC_MSI_BYTES_V1);}
hv_return_t hv_gic_get_spi_interrupt_range(uint32_t *first,uint32_t *count) {
 if(!GICCallerOutputV9(first,sizeof(*first)) || !GICCallerOutputV9(count,sizeof(*count)) ||
  !Disjoint(first,sizeof(*first),count,sizeof(*count)))return Error(3);
 *first=32;*count=VM27_GIC_INTIDS_V1-32;return 0;
}
hv_return_t hv_gic_get_intid(hv_gic_intid_t which,uint32_t *out) {
 if(!GICCallerOutputV9(out,sizeof(*out)))return Error(3);
 if(which!=23 && which!=27 && which!=30)return (which==25 || which==26)?Error(15):Error(3);
 *out=which;return 0;
}
// The header's nonnull annotation conflicts with its documented "returns no
// object" behavior. Follow that behavior for a profile without serialization.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
hv_gic_state_t hv_gic_state_create(void){return NULL;}
#pragma clang diagnostic pop
hv_return_t hv_gic_state_get_size(hv_gic_state_t state,size_t *out){(void)state;(void)out;return Error(15);}
hv_return_t hv_gic_state_get_data(hv_gic_state_t state,void *out){(void)state;(void)out;return Error(15);}
hv_return_t hv_gic_set_state(const void *data,size_t bytes){(void)data;(void)bytes;return Error(15);}
hv_return_t hv_vm_destroy(void) {
 if(!Begin())return Error(2);
 Lock();VM27CPUFactoryVMV2 *vm=Backend.vm;bool owner=vm && pthread_equal(Backend.owner,pthread_self());Unlock();
 if(!owner){End();return Error(3);}
 GICLockV9();bool attached=GICBackendV9.installed && !GICBackendV9.controllerDetached;
 VM27GICDeadlineSchedulerV1 *scheduler=GICBackendV9.scheduler;GICUnlockV9();hv_return_t status=0;
 if(attached) {
  status=VM27CPUFactoryVMGICTeardownV15(vm);
  if(!status){GICLockV9();GICBackendV9.controllerDetached=true;GICBackendV9.installed=false;GICUnlockV9();}
 }
 if(!status && scheduler) {
  GICLockV9();
  status=GICStatusV9(VM27GICDeadlineDestroyV1(scheduler));
  if(!status)memset(&GICBackendV9,0,sizeof(GICBackendV9));
  GICUnlockV9();
 }
 // The frozen teardown acquires this same admission itself. All controller
 // resources have really drained before releasing admission to that operation.
 End();return status?status:VM27GICInheritedDestroyV9();
}
hv_return_t VM27HVVMUninstallNativeOpsV1(void) {
 GICLockV9();bool busy=GICConfigsV9 || GICBackendV9.scheduler || GICBackendV9.installed;GICUnlockV9();
 return busy?Error(2):VM27GICInheritedUninstallV9();
}
