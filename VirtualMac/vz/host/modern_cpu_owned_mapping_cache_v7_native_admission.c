#include "modern_cpu_owned_mapping_cache_v6_owner_tls.c"
#include "modern_cpu_owned_native_admission_v7.h"
bool VM27CPUOwnedNativeAdmissionV7(VM27OwnedNativeAdmissionV7 *out) {
 if(!out || !CurrentMappingV6() || !(OwnerMappingV6.reads&2u) ||
    !InsideOwnedMappingV1((uintptr_t)out,sizeof(*out),OwnerMappingV6.stack,OwnerMappingV6.stackBytes) ||
    !SameMappingV6())return false;
 VM27OwnedNativeAdmissionV7 r={OwnerMappingV6.token,OwnerMappingV6.context,0};
 r.version=*(const volatile uint64_t *)(r.context+0x4000);
 if(!SameMappingV6())return false;
 *out=r;return true;
}
