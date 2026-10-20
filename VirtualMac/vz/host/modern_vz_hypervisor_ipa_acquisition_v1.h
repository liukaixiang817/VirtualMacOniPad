#ifndef MODERN_VZ_HYPERVISOR_IPA_ACQUISITION_V1_H
#define MODERN_VZ_HYPERVISOR_IPA_ACQUISITION_V1_H
#include "modern_vz_hypervisor_ipa_transform_v1.h"
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t schemaVersion;
    void *context;
    // The production provider independently verifies exact OS/image/trap
    // provenance. Fixtures replace only this private acquisition boundary.
    bool (*validateOwnProfileAndFrame)(void *, uint64_t *actualThread);
    int32_t (*invokeOwnedBufferOp0)(void *, void *owned352ZeroBuffer);
} VZFrameworkIPAAcquisitionOpsV1;

typedef struct {
    uint32_t schemaVersion;
    uint32_t queryCalls;
    uint64_t queryOwnerThread;
    int32_t actualNativeReturn;
    int32_t status;
    uint32_t minIPA;
    uint32_t profileAndFrameValidated;
    uint32_t originalZeroInput;
    uint32_t alignment32;
    uint32_t exteriorIntact;
    uint32_t mappingReleased;
    uint32_t packedFieldsKnown;
    uint32_t resultKnown;
    uint64_t leftPackedU64;
    uint64_t rightPackedU64;
} VZFrameworkIPANativeReceiptV1;

// Private application acquisition, one original native0 at most. Own mapping
// lifetime and every failure precede the sole four-byte success store.
int32_t VZFrameworkQueryMaxIPANativeV1(const VZFrameworkIPAAcquisitionOpsV1 *,
    uint32_t *out, VZFrameworkIPANativeReceiptV1 *receipt);

// Genuine original27 export ABI. Cache is initialized by a real query once
// per process; it contains its actual status, never a constant36 fallback.
int32_t hv_vm_config_get_max_ipa_size(uint32_t *out);

// Read-only app diagnostic. It never initiates a query, maps or native call.
int32_t VZFrameworkCopyMaxIPANativeReceiptV1(VZFrameworkIPANativeReceiptV1 *out);

#ifdef __cplusplus
}
#endif
#endif
