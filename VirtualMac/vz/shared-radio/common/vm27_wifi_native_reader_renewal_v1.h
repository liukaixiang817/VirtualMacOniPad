#ifndef VM27_WIFI_NATIVE_READER_RENEWAL_V1_H
#define VM27_WIFI_NATIVE_READER_RENEWAL_V1_H
#include <stdint.h>
#include <string.h>
typedef struct {
    int identityStatus,infraStatus,ssidStatus,peerStatus,authStatus,wsecStatus,modeStatus;
    uint32_t infra,auth,wsec,mode;
    uint8_t identity[6],peer[6];
} VM27WiFiNativeReaderStateV1;
enum { VM27NativeReaderRefuseV1=-1,VM27NativeReaderAbsentV1=0,VM27NativeReaderOwnedIdleV1=1 };
static inline int vm27_wifi_reader_endpoint_absent_v1(int status){
    return status==-19||status==(int32_t)UINT32_C(0xe3ff8101);
}
// Only a completely absent endpoint or this exact, unassociated and
// authentication-free STA is eligible. Partial absence and unknown errors
// cannot authorize closing a live native control session.
static inline int vm27_wifi_native_reader_renewal_v1(const VM27WiFiNativeReaderStateV1 *s,
                                                    const uint8_t expected[6]){
    if(!s||!expected||s->modeStatus||s->mode)return VM27NativeReaderRefuseV1;
    unsigned expectedBits=0;for(unsigned i=0;i<6;i++)expectedBits|=expected[i];
    if(!expectedBits||(expected[0]&1))return VM27NativeReaderRefuseV1;
    if(vm27_wifi_reader_endpoint_absent_v1(s->identityStatus)&&
       vm27_wifi_reader_endpoint_absent_v1(s->infraStatus)&&
       vm27_wifi_reader_endpoint_absent_v1(s->ssidStatus))return VM27NativeReaderAbsentV1;
    if(s->identityStatus||s->infraStatus||s->ssidStatus||s->infra!=1||
       memcmp(s->identity,expected,6)||s->authStatus||s->wsecStatus||s->auth||s->wsec)
        return VM27NativeReaderRefuseV1;
    unsigned peer=0;for(unsigned i=0;i<6;i++)peer|=s->peer[i];
    if(s->peerStatus!=(int32_t)UINT32_C(0xe3ff8111)&&(s->peerStatus||peer))
        return VM27NativeReaderRefuseV1;
    return VM27NativeReaderOwnedIdleV1;
}
#endif
