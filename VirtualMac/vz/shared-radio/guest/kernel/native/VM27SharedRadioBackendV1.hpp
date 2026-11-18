#pragma once
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include "MtkCoreApi.h"
#include "../../../common/vm27_shared_radio_native_v1.h"

class VM27SharedRadioUserClientV1;
class VM27SharedRadioBackendV1 : public IOService {
    OSDeclareDefaultStructors(VM27SharedRadioBackendV1)
public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOWorkLoop *getWorkLoop() const override;
    IOReturn callPlatformFunction(const OSSymbol *, bool, void *, void *, void *, void *) override;
    IOReturn newUserClient(task_t, void *, UInt32, OSDictionary *, IOUserClient **) override;
    using IOService::newUserClient;
    IOReturn claim(VM27SharedRadioUserClientV1 *);
    void disconnectClient(VM27SharedRadioUserClientV1 *);
    IOReturn poll(VM27SharedRadioUserClientV1 *, VM27NativeRadioRequestV1 *);
    IOReturn joinDetails(VM27SharedRadioUserClientV1 *, uint32_t, VM27NativeRadioJoinDetailsV1 *);
    IOReturn publish(VM27SharedRadioUserClientV1 *, const VM27NativeRadioSnapshotV1 *, size_t);
    IOReturn pullPacket(VM27SharedRadioUserClientV1 *, VM27NativeRadioPacketV1 *);
    IOReturn pushPacket(VM27SharedRadioUserClientV1 *, const VM27NativeRadioPacketV1 *);
private:
    static IOReturn gatedPublish(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedDisconnect(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedPushPacket(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedPullPacket(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedGuestPower(OSObject *, void *, void *, void *, void *);
    void queueHostJoinLocked(bool explicitRequest = false);
    static int setCallbacks(void *, const mtk_fe_callbacks *);
    static int tx(void *, mbuf_t);
    static void setEnabled(void *, int);
    static int getMac(void *, uint8_t[6]);
    static int getLink(void *, mtk_link_info *);
    static int scan(void *);
    static int results(void *, mtk_scan_result *, uint32_t, uint32_t *);
    static int join(void *, const mtk_join_params *);
    static int disconnect(void *);
    static int status(void *, mtk_status *);
    static int mode(void *, uint32_t, uint32_t);
    static int bss(void *, uint32_t, mtk_bss_info *);
    static int channels(void *, uint8_t *, uint32_t, uint32_t *);
    static int txBytes(void *, const uint8_t *, uint32_t);
    static int setMac(void *, const uint8_t[6]);
    static int rate(void *, mtk_rate_info *);
    static int country(void *, const char[2]);
    static int chip(void *, mtk_chip_info *);
    static int channels2(void *, mtk_chan *, uint32_t, uint32_t *);
    static int linkChannel(void *, mtk_chan *);
    static const mtk_core_ops_v6 operations;
    IOWorkLoop *loop = nullptr;
    IOCommandGate *gate = nullptr;
    IOLock *lock = nullptr;
    VM27SharedRadioUserClientV1 *client = nullptr;
    VM27NativeRadioSnapshotV1 *cache = nullptr;
    VM27NativeRadioPacketV1 *txRing = nullptr;
    VM27NativeRadioRequestV1 joinRequest = {};
    VM27NativeRadioJoinDetailsV1 pendingJoin = {};
    VM27NativeRadioBSSV1 hostNetwork = {};
    mtk_fe_callbacks_v2 callbacks = {};
    uint8_t mac[6] = {0x02, 0x56, 0x4d, 0x27, 0, 1};
    uint32_t sequence = 0, completedScans = 0;
    uint32_t txHead = 0, txTail = 0, joinSequence = 0, detachSequence = 0;
    uint64_t joinsDeferredUntilDetach = 0;
    uint64_t txAccepted = 0, rxDelivered = 0;
    bool joining = false, joined = false, detaching = false, pathConfigured = false;
    bool autoAttachWanted = false, guestPowered = false;
    bool explicitAssociationOnly = false;
    bool managedAssociation = false;
    bool scanning = false, enabled = false, online = false, stopping = false;
};

class VM27SharedRadioUserClientV1 : public IOUserClient {
    OSDeclareDefaultStructors(VM27SharedRadioUserClientV1)
public:
    bool start(IOService *) override;
    IOReturn clientClose() override;
    void free() override;
    IOReturn externalMethod(uint32_t, IOExternalMethodArguments *, IOExternalMethodDispatch *, OSObject *, void *) override;
private:
    VM27SharedRadioBackendV1 *backend = nullptr;
};
