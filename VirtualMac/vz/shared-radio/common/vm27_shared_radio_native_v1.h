#pragma once
#include <stdint.h>
#include <stddef.h>

#define VM27_NATIVE_RADIO_PROTOCOL 2u
#define VM27_NATIVE_RADIO_CLIENT_TYPE 0x564d5201u
#define VM27_NATIVE_RADIO_MAX_BSS 64u
#define VM27_NATIVE_RADIO_MAX_IE 512u
// Private core/front-end return value, not a wire or IOKit status. An
// unavailable BSS is an association outcome, not an unavailable controller.
enum { VM27_NATIVE_CORE_JOIN_NO_CANDIDATE = -3 };
enum { VM27_NATIVE_REQUEST_NONE = 0, VM27_NATIVE_REQUEST_STATE = 1, VM27_NATIVE_REQUEST_SCAN = 2,
       VM27_NATIVE_REQUEST_JOIN = 3, VM27_NATIVE_REQUEST_DETACH = 4 };
enum { VM27_NATIVE_METHOD_POLL = 0, VM27_NATIVE_METHOD_PUBLISH = 1,
       VM27_NATIVE_METHOD_TX_PULL = 2, VM27_NATIVE_METHOD_RX_PUSH = 3,
       VM27_NATIVE_METHOD_JOIN_DETAILS = 4 };
enum { VM27_NATIVE_BSS_CURRENT_HOST = 1u };
// Optional protocol-2 extension in snapshot.reserved[0]. Send only when the
// driver advertises NativeExplicitAssociationAvailable; other words stay zero.
enum { VM27_NATIVE_STATE_EXPLICIT_ASSOCIATION = 1u,
       VM27_NATIVE_STATE_MANAGED_ASSOCIATION = 2u };
enum { VM27_NATIVE_JOIN_DETAILS_VERSION = 1u,
       VM27_NATIVE_JOIN_OPEN = 0u, VM27_NATIVE_JOIN_PMK = 1u };

// Optional method 4; protocol-2 request/snapshot layouts remain unchanged.
// Only the current administrator companion can read the active join sequence.
// Never publish this object in IORegistry, tracing, files, or crash diagnostics.
typedef struct {
    uint32_t version, byteSize, sequence, keyType, channel, ssidLength;
    uint8_t ssid[32], bssid[6], mac[6], pmk[32];
} VM27NativeRadioJoinDetailsV1;

typedef struct {
    uint32_t version, byteSize, sequence, kind;
    uint64_t reserved;
    uint32_t ssidLength;
    uint8_t ssid[32], bssid[6], mac[6];
} VM27NativeRadioRequestV1;

// Validate the private response against the public poll captured in the same
// request, including its sequence, to reject stale/cross-network credentials.
static inline int vm27_native_join_details_match_v1(const VM27NativeRadioJoinDetailsV1 *d,
                                                   const VM27NativeRadioRequestV1 *r) {
    if(!d||!r||r->version!=VM27_NATIVE_RADIO_PROTOCOL||r->byteSize!=sizeof(*r)||
       r->kind!=VM27_NATIVE_REQUEST_JOIN||r->reserved||!r->sequence||
       d->version!=VM27_NATIVE_JOIN_DETAILS_VERSION||d->byteSize!=sizeof(*d)||
       d->sequence!=r->sequence||!d->ssidLength||d->ssidLength>32||
       d->ssidLength!=r->ssidLength||!d->channel||d->channel>196||d->keyType>VM27_NATIVE_JOIN_PMK)return 0;
    unsigned bssid=0,mac=0;
    for(unsigned i=0;i<d->ssidLength;i++)if(d->ssid[i]!=r->ssid[i])return 0;
    for(unsigned i=0;i<6;i++){
        if(d->bssid[i]!=r->bssid[i]||d->mac[i]!=r->mac[i])return 0;
        bssid|=d->bssid[i];mac|=d->mac[i];
    }
    if(!bssid||!mac||(d->bssid[0]&1)||(d->mac[0]&1))return 0;
    if(d->keyType==VM27_NATIVE_JOIN_OPEN)for(unsigned i=0;i<32;i++)if(d->pmk[i])return 0;
    return 1;
}

// Deliberately below 4 KiB: packet I/O never uses pageable descriptors.
typedef struct {
    uint32_t version, byteSize, length, reserved;
    uint8_t bytes[1518];
} VM27NativeRadioPacketV1;

typedef struct {
    uint8_t bssid[6], ssidLength;
    int8_t rssi;
    uint16_t channel, capability, beaconInterval, ieLength;
    uint32_t ageMS, flags;
    uint8_t ssid[32], ies[VM27_NATIVE_RADIO_MAX_IE];
} VM27NativeRadioBSSV1;

typedef struct {
    uint32_t version, byteSize, sequence, kind;
    int32_t status;
    uint32_t hostPowered, hostAssociated, recordCount, dataPathConfigured, reserved[3];
    VM27NativeRadioBSSV1 records[VM27_NATIVE_RADIO_MAX_BSS];
} VM27NativeRadioSnapshotV1;

#if defined(__cplusplus)
static_assert(sizeof(VM27NativeRadioRequestV1) == 72, "native request layout");
static_assert(sizeof(VM27NativeRadioJoinDetailsV1) == 100, "private join details layout");
static_assert(sizeof(VM27NativeRadioPacketV1) == 1536, "native packet layout");
static_assert(sizeof(VM27NativeRadioBSSV1) == 568, "native scan record layout");
static_assert(offsetof(VM27NativeRadioSnapshotV1, records) == 48, "native snapshot layout");
#endif
