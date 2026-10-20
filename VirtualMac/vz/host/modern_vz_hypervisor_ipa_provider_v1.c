#include "modern_vz_hypervisor_ipa_acquisition_v1.h"
#include "modern_vz_hypervisor_framework_limits.h"
#include <pthread.h>
#include <string.h>

// Implemented by this provider's exact own-frame iOS boundary, or explicitly
// by a local fixture. No old-Hypervisor function pointer is accepted here.
extern int32_t VZIPA27AcquireNative(uint32_t *,VZFrameworkIPANativeReceiptV1 *);
static pthread_once_t Once=PTHREAD_ONCE_INIT;
static pthread_mutex_t ReceiptMutex=PTHREAD_MUTEX_INITIALIZER;
static VZFrameworkIPANativeReceiptV1 Receipt;
static int32_t CachedStatus=(int32_t)UINT32_C(0xfae94001);
static uint32_t CachedIPA;
static void Initialize(void) {
    VZFrameworkIPANativeReceiptV1 actual;memset(&actual,0,sizeof(actual));
    uint32_t value=0;int32_t status=VZIPA27AcquireNative(&value,&actual);
    // Native acquisition establishes its own mapping/cleanup, profile and
    // actual return. Never accept a supplied successful status alone.
    bool complete=!status && actual.schemaVersion==1 && actual.queryCalls==1 && actual.queryOwnerThread &&
        actual.actualNativeReturn==0 && actual.profileAndFrameValidated==1 && actual.originalZeroInput==1 &&
        actual.alignment32==1 && actual.exteriorIntact==1 && actual.mappingReleased==1 &&
        actual.packedFieldsKnown==1 && actual.resultKnown==1 && actual.status==0 && actual.minIPA==value &&
        !(actual.leftPackedU64>>32) && !(actual.rightPackedU64>>32) &&
        value==(uint32_t)(actual.leftPackedU64<actual.rightPackedU64?actual.leftPackedU64:actual.rightPackedU64);
    if(!status && !complete) status=(int32_t)UINT32_C(0xfae94001);
    actual.status=status;if(status) actual.resultKnown=0;
    if(pthread_mutex_lock(&ReceiptMutex)) {CachedStatus=(int32_t)UINT32_C(0xfae94001);return;}
    Receipt=actual;
    if(pthread_mutex_unlock(&ReceiptMutex)) {CachedStatus=(int32_t)UINT32_C(0xfae94001);return;}
    CachedStatus=status;if(complete) CachedIPA=value;
}
int32_t hv_vm_config_get_max_ipa_size(uint32_t *out) {
    if(!out) return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    if(pthread_once(&Once,Initialize)) return (int32_t)UINT32_C(0xfae94001);
    if(CachedStatus) return CachedStatus;
    *out=CachedIPA;return 0;
}
int32_t VZFrameworkCopyMaxIPANativeReceiptV1(VZFrameworkIPANativeReceiptV1 *out) {
    if(!out) return VZ_FRAMEWORK_HV_BAD_ARGUMENT;
    if(pthread_mutex_lock(&ReceiptMutex)) return (int32_t)UINT32_C(0xfae94001);
    VZFrameworkIPANativeReceiptV1 actual=Receipt;
    if(pthread_mutex_unlock(&ReceiptMutex)) return (int32_t)UINT32_C(0xfae94001);
    *out=actual;return 0;
}
