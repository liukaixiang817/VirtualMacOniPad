#include "VM27SharedRadioBackendV1.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/libkern.h>
#include <sys/errno.h>
#include <sys/kpi_mbuf.h>

static constexpr uint32_t PacketRingCount = 128;

OSDefineMetaClassAndStructors(VM27SharedRadioBackendV1, IOService)
OSDefineMetaClassAndStructors(VM27SharedRadioUserClientV1, IOUserClient)

const mtk_core_ops_v6 VM27SharedRadioBackendV1::operations = {
    {{{{{MTK_CORE_API_V6, sizeof(mtk_core_ops_v6), setCallbacks, tx, setEnabled, getMac, getLink},
        scan, results, join, disconnect, status}, mode, bss, channels, txBytes}, setMac}, rate, country},
    chip, channels2, linkChannel
};

bool VM27SharedRadioBackendV1::start(IOService *provider) {
    if (!IOService::start(provider)) return false;
    lock = IOLockAlloc();
    cache = (VM27NativeRadioSnapshotV1 *)IOMallocZero(sizeof(*cache));
    txRing = (VM27NativeRadioPacketV1 *)IOMallocZero(sizeof(*txRing) * PacketRingCount);
    loop = IOWorkLoop::workLoop();
    gate = IOCommandGate::commandGate(this);
    if (!lock || !cache || !txRing || !loop || !gate || loop->addEventSource(gate) != kIOReturnSuccess) return false;
    setProperty("SharedRadioProtocol", VM27_NATIVE_RADIO_PROTOCOL, 32);
    setProperty("PhysicalRadioOwnedByIPad", true);
    setProperty("SharesHostAssociation", true);
    setProperty("NativeExplicitAssociationAvailable", true);
    setProperty("NativeIndependentAssociationAvailable", true);
    setProperty("NativeAssociationDataPathReady", false);
    setProperty("HostRadioClientOnline", false);
    registerService();
    return true;
}
IOWorkLoop *VM27SharedRadioBackendV1::getWorkLoop() const { return loop; }
void VM27SharedRadioBackendV1::stop(IOService *provider) {
    if (lock) { IOLockLock(lock); stopping = true; online = false;bzero(&pendingJoin,sizeof(pendingJoin)); IOLockUnlock(lock); }
    if (loop && gate) { loop->removeEventSource(gate); gate->release(); gate = nullptr; }
    IOService::stop(provider);
}
void VM27SharedRadioBackendV1::free() {
    bzero(&pendingJoin,sizeof(pendingJoin));
    if (gate) { if (loop) loop->removeEventSource(gate); gate->release(); }
    if (loop) loop->release();
    if (cache) IOFree(cache, sizeof(*cache));
    if (txRing) IOFree(txRing, sizeof(*txRing) * PacketRingCount);
    if (lock) IOLockFree(lock);
    IOService::free();
}
IOReturn VM27SharedRadioBackendV1::callPlatformFunction(const OSSymbol *name, bool wait, void *a, void *b, void *c, void *d) {
    if(name&&name->isEqualTo("VM27SharedRadioGuestPowerV1"))
        return gate?gate->runAction(gatedGuestPower,a):kIOReturnNotReady;
    if (name && name->isEqualTo(MTK_CORE_OPS_V6) && a && b) {
        *(const mtk_core_ops_v6 **)a = &operations; *(void **)b = this; return kIOReturnSuccess;
    }
    if (name && (name->isEqualTo(MTK_CORE_FE_CLAIM) || name->isEqualTo(MTK_CORE_FE_DECLINED))) return kIOReturnSuccess;
    return IOService::callPlatformFunction(name, wait, a, b, c, d);
}
IOReturn VM27SharedRadioBackendV1::newUserClient(task_t task, void *securityID, UInt32 type, OSDictionary *properties, IOUserClient **out) {
    if (!out || type != VM27_NATIVE_RADIO_CLIENT_TYPE ||
        IOUserClient::clientHasPrivilege((void *)task, kIOClientPrivilegeAdministrator) != kIOReturnSuccess) return kIOReturnNotPrivileged;
    *out = nullptr;
    auto *created = OSTypeAlloc(VM27SharedRadioUserClientV1);
    if (!created) return kIOReturnNoMemory;
    if (!created->initWithTask(task, securityID, type, properties) || !created->attach(this) || !created->start(this)) {
        if (created->getProvider() == this) created->detach(this);
        created->release(); return kIOReturnNotOpen;
    }
    *out = created; return kIOReturnSuccess;
}
IOReturn VM27SharedRadioBackendV1::claim(VM27SharedRadioUserClientV1 *who) {
    IOLockLock(lock);
    bool accepted = !stopping && (!client || client == who);
    if (accepted) { client = who; online = true; }
    IOLockUnlock(lock);
    if (accepted) setProperty("HostRadioClientOnline", true);
    return accepted ? kIOReturnSuccess : kIOReturnExclusiveAccess;
}
void VM27SharedRadioBackendV1::disconnectClient(VM27SharedRadioUserClientV1 *who) {
    if (gate) gate->runAction(gatedDisconnect, who);
}
IOReturn VM27SharedRadioBackendV1::gatedDisconnect(OSObject *owner, void *who, void *, void *, void *) {
    auto *self = (VM27SharedRadioBackendV1 *)owner;
    mtk_fe_callbacks_v2 cb = {}; bool cancelled = false, linkDown = false;
    IOLockLock(self->lock);
    if (self->client == who) {
        self->client = nullptr; self->online = false; cancelled = self->scanning; self->scanning = false; cb = self->callbacks;
        linkDown = self->joined; self->joined = self->joining = self->detaching = self->pathConfigured = false;
        self->detachSequence = 0;
        bzero(&self->pendingJoin,sizeof(self->pendingJoin));
        self->txHead = self->txTail = 0;
    }
    IOLockUnlock(self->lock);
    if (cancelled && cb.scan_done) cb.scan_done(cb.v1.ctx, -1, 0);
    if (linkDown && cb.v1.link) cb.v1.link(cb.v1.ctx, 0, 0);
    self->setProperty("HostRadioClientOnline", false);
    self->setProperty("NativeAssociationDataPathReady",false);
    return kIOReturnSuccess;
}
IOReturn VM27SharedRadioBackendV1::poll(VM27SharedRadioUserClientV1 *who, VM27NativeRadioRequestV1 *out) {
    IOLockLock(lock);
    bool accepted = !stopping && client == who;
    if (accepted) {
        bzero(out, sizeof(*out));out->version=VM27_NATIVE_RADIO_PROTOCOL;out->byteSize=sizeof(*out);
        if (detaching) {out->kind=VM27_NATIVE_REQUEST_DETACH;out->sequence=detachSequence;}
        else if (joining) *out=joinRequest;
        else {
            if (scanning) {out->kind=VM27_NATIVE_REQUEST_SCAN;out->sequence=sequence;}
            if (joined) {out->ssidLength=hostNetwork.ssidLength;memcpy(out->ssid,hostNetwork.ssid,hostNetwork.ssidLength);}
        }
    }
    IOLockUnlock(lock);
    return accepted ? kIOReturnSuccess : kIOReturnNotOpen;
}
IOReturn VM27SharedRadioBackendV1::joinDetails(VM27SharedRadioUserClientV1 *who,uint32_t requested,VM27NativeRadioJoinDetailsV1 *out) {
    if(!out)return kIOReturnBadArgument;bzero(out,sizeof(*out));
    IOLockLock(lock);
    bool accepted=!stopping&&client==who&&managedAssociation&&joining&&!detaching&&requested&&
        requested==joinRequest.sequence&&pendingJoin.sequence==requested;
    if(accepted)*out=pendingJoin;
    IOLockUnlock(lock);return accepted?kIOReturnSuccess:kIOReturnNotReady;
}
IOReturn VM27SharedRadioBackendV1::publish(VM27SharedRadioUserClientV1 *who, const VM27NativeRadioSnapshotV1 *value, size_t size) {
    if (!value || size < offsetof(VM27NativeRadioSnapshotV1, records) || value->version != VM27_NATIVE_RADIO_PROTOCOL ||
        value->recordCount > VM27_NATIVE_RADIO_MAX_BSS || value->byteSize != size ||
        size != offsetof(VM27NativeRadioSnapshotV1, records) + value->recordCount * sizeof(VM27NativeRadioBSSV1) ||
        value->hostPowered > 1 || value->hostAssociated > 1 || value->dataPathConfigured > 1 ||
        (value->kind < VM27_NATIVE_REQUEST_STATE || value->kind > VM27_NATIVE_REQUEST_DETACH)) return kIOReturnBadArgument;
    if (value->reserved[0] & ~(VM27_NATIVE_STATE_EXPLICIT_ASSOCIATION|VM27_NATIVE_STATE_MANAGED_ASSOCIATION)) return kIOReturnBadArgument;
    for (unsigned i = 1; i < 3; ++i) if (value->reserved[i]) return kIOReturnBadArgument;
    if (value->kind != VM27_NATIVE_REQUEST_SCAN &&
        (value->recordCount > 1 || (value->recordCount && !(value->records[0].flags & VM27_NATIVE_BSS_CURRENT_HOST)))) return kIOReturnBadArgument;
    for (uint32_t i = 0; i < value->recordCount; ++i) {
        const auto &row = value->records[i];
        if (row.ssidLength > 32 || row.ieLength > VM27_NATIVE_RADIO_MAX_IE || !row.channel || row.channel > 196 ||
            (row.bssid[0] & 1) || row.flags & ~VM27_NATIVE_BSS_CURRENT_HOST) return kIOReturnBadArgument;
        unsigned nonzero = 0; for (unsigned j = 0; j < 6; ++j) nonzero |= row.bssid[j];
        if (!nonzero) return kIOReturnBadArgument;
        for (unsigned j = 0; j < row.ieLength;) {
            if (row.ieLength - j < 2 || row.ies[j + 1] > row.ieLength - j - 2) return kIOReturnBadArgument;
            j += 2 + row.ies[j + 1];
        }
    }
    return gate ? gate->runAction(gatedPublish, who, (void *)value, (void *)(uintptr_t)size) : kIOReturnNotReady;
}
IOReturn VM27SharedRadioBackendV1::gatedPublish(OSObject *owner, void *who, void *input, void *bytes, void *) {
    auto *self = (VM27SharedRadioBackendV1 *)owner;
    const auto *value = (const VM27NativeRadioSnapshotV1 *)input;
    size_t size = (uintptr_t)bytes;
    mtk_fe_callbacks_v2 cb = {}; bool complete = false, joinComplete = false, linkDown = false, linkUp = false;
    uint8_t joinedBSSID[6]={0};
    IOLockLock(self->lock);
    if (self->client != who || self->stopping ||
        (value->kind == VM27_NATIVE_REQUEST_SCAN && (!self->scanning || value->sequence != self->sequence)) ||
        (value->kind == VM27_NATIVE_REQUEST_JOIN && (!self->joining || value->sequence != self->joinRequest.sequence)) ||
        (value->kind == VM27_NATIVE_REQUEST_DETACH && (!self->detaching || value->sequence != self->detachSequence))) {
        IOLockUnlock(self->lock); return kIOReturnNotReady;
    }
    self->managedAssociation = (value->reserved[0] & VM27_NATIVE_STATE_MANAGED_ASSOCIATION) != 0;
    self->explicitAssociationOnly = self->managedAssociation || (value->reserved[0] & VM27_NATIVE_STATE_EXPLICIT_ASSOCIATION) != 0;
    if (value->kind == VM27_NATIVE_REQUEST_SCAN) {
        bzero(self->cache, sizeof(*self->cache)); memcpy(self->cache, value, size);
        self->scanning = false; ++self->completedScans; cb = self->callbacks; complete = true;
    } else {
        self->cache->hostPowered = value->hostPowered; self->cache->hostAssociated = value->hostAssociated;
        self->pathConfigured = value->dataPathConfigured;
        bool changed = !value->recordCount || memcmp(self->hostNetwork.bssid,value->records[0].bssid,6);
        if (self->joined && (!value->hostPowered || !value->hostAssociated || !value->dataPathConfigured || changed)) {
            self->joined = false;self->txHead=self->txTail=0;linkDown=true;cb=self->callbacks;
        }
        bzero(&self->hostNetwork,sizeof(self->hostNetwork));
        if (value->recordCount) {
            self->hostNetwork=value->records[0];
            bool present=false;
            for(uint32_t i=0;i<self->cache->recordCount;++i)
                if(!memcmp(self->cache->records[i].bssid,self->hostNetwork.bssid,6)) {self->cache->records[i]=self->hostNetwork;present=true;break;}
            if(!present&&self->cache->recordCount<VM27_NATIVE_RADIO_MAX_BSS)
                self->cache->records[self->cache->recordCount++]=self->hostNetwork;
        }
        if(value->kind==VM27_NATIVE_REQUEST_JOIN) {
            self->joining=false;joinComplete=true;cb=self->callbacks;
            self->joined=self->guestPowered&&!value->status&&value->hostPowered&&value->hostAssociated&&value->dataPathConfigured&&
                self->hostNetwork.ssidLength==self->joinRequest.ssidLength&&
                !memcmp(self->hostNetwork.ssid,self->joinRequest.ssid,self->joinRequest.ssidLength)&&
                !memcmp(self->hostNetwork.bssid,self->joinRequest.bssid,6);
            bzero(&self->pendingJoin,sizeof(self->pendingJoin));
            linkUp=self->joined;memcpy(joinedBSSID,self->hostNetwork.bssid,6);
            self->txHead=self->txTail=0;self->txAccepted=self->rxDelivered=0;
        } else if(value->kind==VM27_NATIVE_REQUEST_DETACH) {
            if(!value->status) {
                self->detaching=false;self->detachSequence=0;
            } else if(self->joining) {
                // Do not release a queued network's key to the companion
                // until the preceding physical association has retired.
                self->joining=false;joinComplete=true;cb=self->callbacks;
                memcpy(joinedBSSID,self->joinRequest.bssid,6);
                bzero(&self->pendingJoin,sizeof(self->pendingJoin));
            }
        }
        else self->queueHostJoinLocked();
    }
    IOLockUnlock(self->lock);
    self->setProperty("HostPowered", value->hostPowered != 0);
    self->setProperty("NativeExplicitAssociationMode", self->explicitAssociationOnly);
    self->setProperty("SharesHostAssociation", !self->explicitAssociationOnly);
    self->setProperty("HostAssociated", value->hostAssociated != 0);
    if(linkDown||joinComplete)self->setProperty("NativeAssociationDataPathReady",false);
    if(linkDown&&cb.v1.link)cb.v1.link(cb.v1.ctx,0,0);
    if(linkUp&&cb.v1.link)cb.v1.link(cb.v1.ctx,1,0);
    if(joinComplete&&cb.join_result)cb.join_result(cb.v1.ctx,linkUp?MTK_JOIN_OK:MTK_JOIN_NOT_FOUND,joinedBSSID);
    if (complete) {
        self->setProperty("NativeScanResultCount", value->recordCount, 32);
        self->setProperty("NativeScanCompletionCount", self->completedScans, 32);
        if (cb.scan_done) cb.scan_done(cb.v1.ctx, value->status ? -1 : 0, value->status ? 0 : value->recordCount);
    }
    return kIOReturnSuccess;
}
void VM27SharedRadioBackendV1::queueHostJoinLocked(bool explicitRequest) {
    if((explicitAssociationOnly&&!explicitRequest)||!autoAttachWanted||!guestPowered||!online||joined||joining||detaching||!cache->hostPowered||!cache->hostAssociated||
       !hostNetwork.ssidLength||joinSequence==UINT32_MAX)return;
    bzero(&joinRequest,sizeof(joinRequest));
    bzero(&pendingJoin,sizeof(pendingJoin));
    joinRequest.version=VM27_NATIVE_RADIO_PROTOCOL;joinRequest.byteSize=sizeof(joinRequest);
    joinRequest.kind=VM27_NATIVE_REQUEST_JOIN;joinRequest.sequence=++joinSequence;
    joinRequest.ssidLength=hostNetwork.ssidLength;memcpy(joinRequest.ssid,hostNetwork.ssid,hostNetwork.ssidLength);
    memcpy(joinRequest.bssid,hostNetwork.bssid,6);memcpy(joinRequest.mac,mac,6);joining=true;
}
IOReturn VM27SharedRadioBackendV1::gatedGuestPower(OSObject *owner,void *power,void *,void *,void *) {
    auto *self=(VM27SharedRadioBackendV1 *)owner;
    IOLockLock(self->lock);self->guestPowered=power!=nullptr;self->autoAttachWanted=power!=nullptr;
    if(power)self->queueHostJoinLocked();IOLockUnlock(self->lock);
    if(!power)disconnect(self);
    self->setProperty("GuestRadioPowered",power!=nullptr);return kIOReturnSuccess;
}
IOReturn VM27SharedRadioBackendV1::pullPacket(VM27SharedRadioUserClientV1 *who, VM27NativeRadioPacketV1 *packet) {
    return gate?gate->runAction(gatedPullPacket,who,packet):kIOReturnNotReady;
}
IOReturn VM27SharedRadioBackendV1::gatedPullPacket(OSObject *owner,void *who,void *output,void *,void *) {
    auto *self=(VM27SharedRadioBackendV1 *)owner;auto *packet=(VM27NativeRadioPacketV1 *)output;
    mtk_fe_callbacks_v2 cb={};bool have=false;
    IOLockLock(self->lock);
    if(self->client!=who||self->stopping) {IOLockUnlock(self->lock);return kIOReturnNotOpen;}
    bzero(packet,sizeof(*packet));packet->version=VM27_NATIVE_RADIO_PROTOCOL;packet->byteSize=sizeof(*packet);
    if(self->txHead!=self->txTail) {*packet=self->txRing[self->txTail];self->txTail=(self->txTail+1)%PacketRingCount;have=true;cb=self->callbacks;}
    IOLockUnlock(self->lock);
    if(have&&cb.v1.tx_space)cb.v1.tx_space(cb.v1.ctx);
    if(have&&(self->txAccepted<=4||!(self->txAccepted&63)))self->setProperty("NativeDataTXFrames",self->txAccepted,64);
    return kIOReturnSuccess;
}
IOReturn VM27SharedRadioBackendV1::pushPacket(VM27SharedRadioUserClientV1 *who,const VM27NativeRadioPacketV1 *packet) {
    if(!packet||packet->version!=VM27_NATIVE_RADIO_PROTOCOL||packet->byteSize!=sizeof(*packet)||packet->reserved||
       packet->length<14||packet->length>sizeof(packet->bytes))return kIOReturnBadArgument;
    return gate?gate->runAction(gatedPushPacket,who,(void *)packet):kIOReturnNotReady;
}
IOReturn VM27SharedRadioBackendV1::gatedPushPacket(OSObject *owner,void *who,void *input,void *,void *) {
    auto *self=(VM27SharedRadioBackendV1 *)owner;const auto *packet=(const VM27NativeRadioPacketV1 *)input;
    mtk_fe_callbacks_v2 cb={};
    IOLockLock(self->lock);
    bool accepted=self->client==who&&!self->stopping&&self->joined&&self->enabled;
    if(accepted)cb=self->callbacks;
    IOLockUnlock(self->lock);
    if(!accepted||!cb.v1.rx_alloc||!cb.v1.rx)return kIOReturnNotReady;
    mbuf_t frame=cb.v1.rx_alloc(cb.v1.ctx,packet->length);
    if(!frame)return kIOReturnNoMemory;
    if(mbuf_copyback(frame,0,packet->length,packet->bytes,MBUF_DONTWAIT)) {mbuf_freem(frame);return kIOReturnNoMemory;}
    mbuf_pkthdr_setlen(frame,packet->length);cb.v1.rx(cb.v1.ctx,frame);
    if(cb.v1.rx_flush)cb.v1.rx_flush(cb.v1.ctx);
    ++self->rxDelivered;
    if(self->rxDelivered<=4||!(self->rxDelivered&63)) {
        self->setProperty("NativeDataRXFrames",self->rxDelivered,64);
        if(self->txAccepted)self->setProperty("NativeAssociationDataPathReady",true);
    }
    return kIOReturnSuccess;
}
int VM27SharedRadioBackendV1::setCallbacks(void *core, const mtk_fe_callbacks *value) {
    auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock);
    if (value && (value->size < sizeof(mtk_fe_callbacks_v2) || value->version != MTK_CORE_API_V4 ||
        (self->callbacks.v1.ctx && self->callbacks.v1.ctx != value->ctx))) { IOLockUnlock(self->lock); return -1; }
    bzero(&self->callbacks, sizeof(self->callbacks));
    if (value) memcpy(&self->callbacks, value, sizeof(self->callbacks));
    IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::tx(void *, mbuf_t) { return MTK_TX_DROPPED; }
int VM27SharedRadioBackendV1::txBytes(void *core, const uint8_t *bytes, uint32_t length) {
    auto *self=(VM27SharedRadioBackendV1 *)core;
    if(!bytes||length<14||length>1518)return MTK_TX_DROPPED;
    IOLockLock(self->lock);
    uint32_t next=(self->txHead+1)%PacketRingCount;
    int result=MTK_TX_DROPPED;
    if(self->joined&&self->enabled&&self->online) {
        if(next==self->txTail)result=MTK_TX_STALL;
        else {
            auto &packet=self->txRing[self->txHead];bzero(&packet,sizeof(packet));
            packet.version=VM27_NATIVE_RADIO_PROTOCOL;packet.byteSize=sizeof(packet);packet.length=length;
            memcpy(packet.bytes,bytes,length);self->txHead=next;++self->txAccepted;result=MTK_TX_OK;
        }
    }
    IOLockUnlock(self->lock);return result;
}
void VM27SharedRadioBackendV1::setEnabled(void *core, int value) {
    auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock); self->enabled = value != 0;
    if(value)self->queueHostJoinLocked();
    IOLockUnlock(self->lock);
    self->setProperty("GuestRadioEnabled", value != 0);
}
int VM27SharedRadioBackendV1::getMac(void *core, uint8_t out[6]) {
    if (!out) return -1; auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock); memcpy(out, self->mac, 6); IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::setMac(void *core, const uint8_t value[6]) {
    if (!value || (value[0] & 1)) return -1;
    unsigned nonzero = 0; for (unsigned i = 0; i < 6; ++i) nonzero |= value[i]; if (!nonzero) return -1;
    auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock); memcpy(self->mac, value, 6); IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::getLink(void *core, mtk_link_info *out) {
    if (!out) return -1; auto *self = (VM27SharedRadioBackendV1 *)core; bzero(out, sizeof(*out));
    IOLockLock(self->lock);out->enabled=self->guestPowered&&self->online&&self->cache->hostPowered;out->up=self->joined;
    if(self->joined) {memcpy(out->bssid,self->hostNetwork.bssid,6);out->channel=(uint8_t)self->hostNetwork.channel;
        out->center=out->channel;out->nss=1;memcpy(out->ssid,self->hostNetwork.ssid,self->hostNetwork.ssidLength);}
    IOLockUnlock(self->lock);return 0;
}
int VM27SharedRadioBackendV1::scan(void *core) {
    auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock);
    if (self->stopping || !self->online || self->scanning || !self->cache->hostPowered || self->sequence == UINT32_MAX) {
        IOLockUnlock(self->lock); return -2;
    }
    ++self->sequence; self->scanning = true;
    IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::status(void *core, mtk_status *out) {
    if (!out) return -1; auto *self = (VM27SharedRadioBackendV1 *)core; bzero(out, sizeof(*out));
    IOLockLock(self->lock);
    out->version = MTK_USER_API_VERSION; out->state = self->joined ? MTK_ST_CONNECTED : self->joining ? MTK_ST_JOINING : self->scanning ? MTK_ST_SCANNING : MTK_ST_IDLE;
    out->link_up=out->port_open=self->joined;out->want_active=self->joined||self->joining;
    if(self->joined) {out->channel=(uint8_t)self->hostNetwork.channel;out->rssi=self->hostNetwork.rssi;
        out->ssid_len=self->hostNetwork.ssidLength;memcpy(out->ssid,self->hostNetwork.ssid,out->ssid_len);
        memcpy(out->bssid,self->hostNetwork.bssid,6);out->security=(self->hostNetwork.capability&0x10)?MTK_SEC_RSN:MTK_SEC_OPEN;}
    out->scanning = self->scanning; out->front_end = MTK_FE_NATIVE;
    out->bss_count = self->cache->recordCount; out->scans = self->completedScans;
    IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::bss(void *core, uint32_t index, mtk_bss_info *out) {
    if (!out) return -1; auto *self = (VM27SharedRadioBackendV1 *)core;
    IOLockLock(self->lock);
    if (index >= self->cache->recordCount) { IOLockUnlock(self->lock); return -1; }
    const auto &row = self->cache->records[index];
    bzero(out, sizeof(*out)); memcpy(out->bssid, row.bssid, 6); out->channel = (uint8_t)row.channel;
    out->rssi = row.rssi; out->ssid_len = row.ssidLength; memcpy(out->ssid, row.ssid, row.ssidLength);
    out->capability = row.capability; out->beacon_interval = row.beaconInterval; out->ie_len = row.ieLength;
    memcpy(out->ie, row.ies, row.ieLength); out->age_ms = row.ageMS;
    out->security = (row.capability & 0x10) ? MTK_SEC_RSN : MTK_SEC_OPEN;
    IOLockUnlock(self->lock); return 0;
}
int VM27SharedRadioBackendV1::results(void *core, mtk_scan_result *out, uint32_t max, uint32_t *count) {
    if (!out || !count || max > VM27_NATIVE_RADIO_MAX_BSS) return -1;
    *count = 0; mtk_bss_info row;
    for (uint32_t i = 0; i < max && !bss(core, i, &row); ++i) {
        bzero(&out[i], sizeof(out[i])); memcpy(out[i].bssid, row.bssid, 6); out[i].ssid_len = row.ssid_len;
        memcpy(out[i].ssid, row.ssid, row.ssid_len); out[i].channel = row.channel; out[i].rssi = row.rssi;
        out[i].security = row.security; out[i].age_ms = row.age_ms; ++*count;
    }
    return 0;
}
int VM27SharedRadioBackendV1::join(void *core, const mtk_join_params *parameters) {
    if(!parameters||parameters->version!=MTK_USER_API_VERSION||!parameters->ssid_len||parameters->ssid_len>32)return -1;
    auto *self=(VM27SharedRadioBackendV1 *)core;IOLockLock(self->lock);
    if(self->managedAssociation) {
        const VM27NativeRadioBSSV1 *selected=nullptr;
        unsigned pinned=0;for(unsigned i=0;i<6;++i)pinned|=parameters->bssid[i];
        bool allowed=self->guestPowered&&self->online&&!self->stopping&&
            !self->joining&&self->cache->hostPowered&&self->joinSequence<UINT32_MAX&&
            (parameters->key_type==MTK_KEY_NONE||parameters->key_type==MTK_KEY_PMK);
        if(allowed)for(uint32_t i=0;i<self->cache->recordCount;i++) {
            const auto &row=self->cache->records[i];
            if(row.ssidLength!=parameters->ssid_len||memcmp(row.ssid,parameters->ssid,parameters->ssid_len)||
               (pinned&&memcmp(row.bssid,parameters->bssid,6)))continue;
            if(!selected||row.rssi>selected->rssi)selected=&row;
        }
        if(!selected){IOLockUnlock(self->lock);return allowed?VM27_NATIVE_CORE_JOIN_NO_CANDIDATE:-2;}
        if(!!(selected->capability&0x10)!=(parameters->key_type==MTK_KEY_PMK)){IOLockUnlock(self->lock);return -1;}
        bzero(&self->pendingJoin,sizeof(self->pendingJoin));bzero(&self->joinRequest,sizeof(self->joinRequest));
        auto &details=self->pendingJoin;details.version=VM27_NATIVE_JOIN_DETAILS_VERSION;details.byteSize=sizeof(details);
        details.sequence=++self->joinSequence;details.keyType=parameters->key_type;
        details.channel=selected->channel;details.ssidLength=parameters->ssid_len;
        memcpy(details.ssid,parameters->ssid,parameters->ssid_len);memcpy(details.bssid,selected->bssid,6);memcpy(details.mac,self->mac,6);
        if(parameters->key_type==MTK_KEY_PMK)memcpy(details.pmk,parameters->pmk,32);
        auto &request=self->joinRequest;request.version=VM27_NATIVE_RADIO_PROTOCOL;request.byteSize=sizeof(request);
        request.kind=VM27_NATIVE_REQUEST_JOIN;request.sequence=details.sequence;request.ssidLength=details.ssidLength;
        memcpy(request.ssid,details.ssid,details.ssidLength);memcpy(request.bssid,details.bssid,6);memcpy(request.mac,details.mac,6);
        // WCL submits the new network immediately after its asynchronous
        // leave request. Keep that intent while the companion finishes the
        // old detach. Poll still prioritizes detachSequence; its completion
        // cannot consume or invalidate this newer joinRequest sequence.
        bool deferred=self->detaching;
        if(deferred)++self->joinsDeferredUntilDetach;
        uint64_t deferredCount=self->joinsDeferredUntilDetach;
        self->autoAttachWanted=true;self->joining=true;self->joined=false;self->txHead=self->txTail=0;
        IOLockUnlock(self->lock);
        if(deferred)self->setProperty("NativeJoinsDeferredUntilDetach",deferredCount,64);
        return 0;
    }
    bool same=self->guestPowered&&self->online&&!self->detaching&&parameters->ssid_len==self->hostNetwork.ssidLength&&
        !memcmp(parameters->ssid,self->hostNetwork.ssid,parameters->ssid_len);
    unsigned pinned=0;for(unsigned i=0;i<6;++i)pinned|=parameters->bssid[i];
    if(pinned&&memcmp(parameters->bssid,self->hostNetwork.bssid,6))same=false;
    if(same) {self->autoAttachWanted=true;self->joined=false;self->joining=false;self->queueHostJoinLocked(true);same=self->joining;}
    IOLockUnlock(self->lock);return same?0:-2;
}
int VM27SharedRadioBackendV1::disconnect(void *core) {
    auto *self=(VM27SharedRadioBackendV1 *)core;mtk_fe_callbacks_v2 cb={};bool down;
    IOLockLock(self->lock);down=self->joined;self->autoAttachWanted=false;self->joined=self->joining=false;self->txHead=self->txTail=0;
    bzero(&self->pendingJoin,sizeof(self->pendingJoin));
    if(self->online&&self->joinSequence<UINT32_MAX) {self->detaching=true;self->detachSequence=++self->joinSequence;}
    cb=self->callbacks;IOLockUnlock(self->lock);
    self->setProperty("NativeAssociationDataPathReady",false);
    if(down&&cb.v1.link)cb.v1.link(cb.v1.ctx,0,0);return 0;
}
int VM27SharedRadioBackendV1::mode(void *, uint32_t value, uint32_t) { return value == MTK_FE_NATIVE ? 0 : -1; }
int VM27SharedRadioBackendV1::channels(void *, uint8_t *out, uint32_t max, uint32_t *count) {
    static const uint8_t values[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
    if (!out || !count) return -1; *count = max < sizeof(values) ? max : sizeof(values); memcpy(out, values, *count); return 0;
}
int VM27SharedRadioBackendV1::channels2(void *core, mtk_chan *out, uint32_t max, uint32_t *count) {
    uint8_t values[64]; uint32_t n = 0;
    if (!out || !count || channels(core, values, sizeof(values), &n)) return -1;
    *count = max < n ? max : n;
    for (uint32_t i = 0; i < *count; ++i) out[i] = {(uint8_t)(values[i] > 14 ? MTK_CHAN_5G : MTK_CHAN_2G), MTK_BW_20, values[i], values[i], MTK_CHAN_F_PASSIVE};
    return 0;
}
int VM27SharedRadioBackendV1::rate(void *, mtk_rate_info *) { return -2; }
int VM27SharedRadioBackendV1::country(void *, const char[2]) { return 0; }
int VM27SharedRadioBackendV1::chip(void *, mtk_chip_info *out) {
    if (!out || out->size < sizeof(*out)) return -1;
    bzero(out, sizeof(*out)); out->size = sizeof(*out); strlcpy(out->name, "iPad Shared", sizeof(out->name));
    strlcpy(out->fw_version, "host-shared-v1", sizeof(out->fw_version)); out->bands = MTK_CAP_2G | MTK_CAP_5G;
    out->nss = 1; out->max_bw = MTK_BW_20; return 0;
}
int VM27SharedRadioBackendV1::linkChannel(void *core, mtk_chan *out) {
    if(!out)return -1;auto *self=(VM27SharedRadioBackendV1 *)core;IOLockLock(self->lock);
    bool linked=self->joined;uint16_t channel=self->hostNetwork.channel;
    if(linked)*out={(uint8_t)(channel>14?MTK_CHAN_5G:MTK_CHAN_2G),MTK_BW_20,channel,channel,0};
    IOLockUnlock(self->lock);return linked?0:-2;
}

bool VM27SharedRadioUserClientV1::start(IOService *provider) {
    auto *value = OSDynamicCast(VM27SharedRadioBackendV1, provider);
    if (!value || !IOUserClient::start(provider) || value->claim(this) != kIOReturnSuccess) return false;
    backend = value; backend->retain(); return true;
}
IOReturn VM27SharedRadioUserClientV1::clientClose() {
    if (backend) backend->disconnectClient(this);
    terminate(); return kIOReturnSuccess;
}
void VM27SharedRadioUserClientV1::free() {
    if (backend) { backend->disconnectClient(this); backend->release(); backend = nullptr; }
    IOUserClient::free();
}
IOReturn VM27SharedRadioUserClientV1::externalMethod(uint32_t selector, IOExternalMethodArguments *args,
    IOExternalMethodDispatch *, OSObject *, void *) {
    if (!backend || !args || isInactive()) return kIOReturnNotOpen;
    if (args->scalarInputCount || args->scalarOutputCount || args->structureOutputDescriptor) return kIOReturnBadArgument;
    if(selector==VM27_NATIVE_METHOD_JOIN_DETAILS) {
        if(args->structureInputDescriptor||!args->structureInput||args->structureInputSize!=sizeof(uint32_t)||
           !args->structureOutput||args->structureOutputSize<sizeof(VM27NativeRadioJoinDetailsV1))return kIOReturnBadArgument;
        uint32_t sequence=0;memcpy(&sequence,args->structureInput,sizeof(sequence));
        auto result=backend->joinDetails(this,sequence,(VM27NativeRadioJoinDetailsV1 *)args->structureOutput);
        args->structureOutputSize=sizeof(VM27NativeRadioJoinDetailsV1);return result;
    }
    if (selector == VM27_NATIVE_METHOD_POLL) {
        if (args->structureInputSize || args->structureInputDescriptor || !args->structureOutput || args->structureOutputSize < sizeof(VM27NativeRadioRequestV1)) return kIOReturnBadArgument;
        auto result = backend->poll(this, (VM27NativeRadioRequestV1 *)args->structureOutput);
        args->structureOutputSize = sizeof(VM27NativeRadioRequestV1); return result;
    }
    if(selector==VM27_NATIVE_METHOD_TX_PULL) {
        if(args->structureInputSize||args->structureInputDescriptor||!args->structureOutput||
           args->structureOutputSize<sizeof(VM27NativeRadioPacketV1))return kIOReturnBadArgument;
        auto result=backend->pullPacket(this,(VM27NativeRadioPacketV1 *)args->structureOutput);
        args->structureOutputSize=sizeof(VM27NativeRadioPacketV1);return result;
    }
    if(selector==VM27_NATIVE_METHOD_RX_PUSH) {
        if(args->structureOutputSize||args->structureInputDescriptor||!args->structureInput||
           args->structureInputSize!=sizeof(VM27NativeRadioPacketV1))return kIOReturnBadArgument;
        return backend->pushPacket(this,(const VM27NativeRadioPacketV1 *)args->structureInput);
    }
    if (selector == VM27_NATIVE_METHOD_PUBLISH) {
        if (args->structureOutputSize) return kIOReturnBadArgument;
        if (args->structureInputDescriptor) {
            size_t size = args->structureInputDescriptor->getLength();
            if (size < offsetof(VM27NativeRadioSnapshotV1, records) || size > sizeof(VM27NativeRadioSnapshotV1)) return kIOReturnBadArgument;
            auto *copy = (VM27NativeRadioSnapshotV1 *)IOMallocZero(size);
            if (!copy) return kIOReturnNoMemory;
            // Large IOConnectCallStructMethod inputs arrive as pageable user
            // memory descriptors. readBytes requires a prepared descriptor;
            // otherwise IOGMD panics when it resolves the physical segments.
            auto *descriptor = args->structureInputDescriptor;
            IOReturn result = descriptor->prepare(kIODirectionOut);
            if (result != kIOReturnSuccess) { IOFree(copy, size); return result; }
            IOByteCount copied = descriptor->readBytes(0, copy, size);
            result = descriptor->complete(kIODirectionOut);
            if (result == kIOReturnSuccess)
                result = copied == size ? backend->publish(this, copy, size) : kIOReturnBadArgument;
            IOFree(copy, size); return result;
        }
        if (!args->structureInput) return kIOReturnBadArgument;
        return backend->publish(this, (const VM27NativeRadioSnapshotV1 *)args->structureInput, args->structureInputSize);
    }
    return kIOReturnUnsupported;
}
