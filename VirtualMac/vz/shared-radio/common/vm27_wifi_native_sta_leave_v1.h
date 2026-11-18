#ifndef VM27_WIFI_NATIVE_STA_LEAVE_V1_H
#define VM27_WIFI_NATIVE_STA_LEAVE_V1_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum { VM27STAInvalidV1=-1, VM27STAIdleV1=0, VM27STALeaveV1=1, VM27STAAbortV1=2 };
// The original NetManager's LeaveMethod table at RVA0x29b630 is {201,52}.
// setDEAUTH selects method0; setDISASSOCIATE selects method1. Only an
// associated, validated peer is eligible for 201; a pending join uses 52.
static inline int vm27_wifi_native_sta_command_v1(int action,bool deauthenticatePeer) {
    switch(action){
        case VM27STAIdleV1:return 0;
        case VM27STALeaveV1:return deauthenticatePeer?201:52;
        case VM27STAAbortV1:return 52;
        default:return -1;
    }
}
// 20B101 NetManager::leaveNetworkSync uses one 12-byte reason/peer request.
// JoinManager::abortJoinSync reaches its zero-peer firmware abort only while
// the join-in-progress bit is set (RVA 0x22cbb0..0x22cc14), before leaving.
// A completed link must not receive another unconditional abort after leave.
static inline int vm27_wifi_native_sta_leave_v1(int peerRead,const uint8_t peer[6],
    bool stateKnown,bool joinPending,uint8_t payload[12]) {
    if(!peer||!payload)return VM27STAInvalidV1;
    memset(payload,0,12);
    const int notAssociated=(int32_t)UINT32_C(0xe3ff8111);
    if(peerRead && peerRead!=notAssociated)return VM27STAInvalidV1;
    unsigned present=0;for(unsigned i=0;i<6;i++)present|=peer[i];
    uint32_t reason;
    if(!peerRead && present){
        if(peer[0]&1)return VM27STAInvalidV1;
        reason=8;memcpy(payload,&reason,4);memcpy(payload+4,peer,6);
        return VM27STALeaveV1;
    }
    if(stateKnown&&!joinPending)return VM27STAIdleV1;
    reason=3;memcpy(payload,&reason,4);return VM27STAAbortV1;
}
#endif
