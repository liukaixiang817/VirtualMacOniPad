// End a timed-out, accepted join once. Keep its physical STA allocated and
// make the existing serial actor verify an idle state after the drain deadline.
// Waiting happens between RPCs; no extra sleep extends the association reply.
static BOOL OwnedPendingAbortAttempted,OwnedPendingRecoveryActive,OwnedPendingRecoveryTerminal;
static double OwnedPendingDrainDeadline,OwnedPendingRecoveryExpiry,OwnedPendingLastIdleSample;
static unsigned OwnedPendingIdleSamples;
static void resetOwnedPendingJoinRecovery(void){
 OwnedPendingAbortAttempted=OwnedPendingRecoveryActive=OwnedPendingRecoveryTerminal=NO;
 OwnedPendingDrainDeadline=OwnedPendingRecoveryExpiry=OwnedPendingLastIdleSample=0;
 OwnedPendingIdleSamples=0;
 for(NSString *key in @[@"timedOutJoinRecoveryScopeVerified",@"timedOutJoinNativeAbortStatus",@"timedOutJoinNativeAbortCommandCount",@"timedOutJoinWaitingForOwnedIdleDrain",@"timedOutJoinDrainMilliseconds",@"timedOutJoinStableIdleSamples",@"timedOutJoinRecoveryRefusedAfterDrain",@"timedOutJoinPendingClearedAfterOwnedIdleProof"])[Report removeObjectForKey:key];
}
// -1: foreign/unknown or unsafe scope; 0: owned requested link not yet idle;
// 1: owned endpoint has no SSID and no peer. No security-status getters.
static int ownedPendingJoinRecoveryState(void){
 if(Stop||!ManagedStationBroker||!OwnedStationRoleActive||!MACRecorded||
    OwnedLeaseLock<0||!Primary||!Auxiliary||Primary==Auxiliary||
    !TargetSSID.length||TargetSSID.length>32)return -1;
 uint8_t mac[6]={0},peer[6]={0},name[36]={0};uint32_t infra=0,length=0;
 int identity=iovar(NO,"cur_etheraddr",1,NULL,0,mac,6);
 int infrastructure=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
 BOOL owned=!identity&&!infrastructure&&infra==1&&!memcmp(mac,OwnedMAC,6);wipe(mac,sizeof(mac));
 if(!owned)return -1;
 int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,name,sizeof(name));
 int bs=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,sizeof(peer));memcpy(&length,name,4);
 unsigned bits=0;for(unsigned i=0;i<6;i++)bits|=peer[i];
 BOOL knownName=!ss&&length<=32&&(!length||(length==TargetSSID.length&&!memcmp(name+4,TargetSSID.bytes,length)));
 BOOL idlePeer=bs==(int)0xe3ff8111||(!bs&&!bits);
 BOOL knownPeer=idlePeer||(!bs&&bits&&!memcmp(peer,TargetBSSID,6));
 wipe(name,sizeof(name));wipe(peer,sizeof(peer));
 recordPrimaryAssociation();
 if(!knownName||!knownPeer||![Report[@"primaryAssociationPreserved"]boolValue])return -1;
 return !length&&idlePeer?1:0;
}
static BOOL beginOwnedTimedOutJoinRecovery(double now){
 if(!OwnedJoinStateKnown||!OwnedJoinPending||OwnedPendingAbortAttempted||
    OwnedPendingRecoveryActive||OwnedPendingRecoveryTerminal)return NO;
 int state=ownedPendingJoinRecoveryState();
 Report[@"timedOutJoinRecoveryScopeVerified"]=@(state>=0);
 if(state<0)return NO;
 OwnedPendingAbortAttempted=YES;
 // Exact JoinManager::abortFirmwareJoinSync on20B101: reason3, zero peer,
 // twelve bytes, WLC_DISASSOC52. This does not delete or cycle any BSS.
 uint8_t abort[12]={0};uint32_t reason=3;memcpy(abort,&reason,4);
 int status=request(Auxiliary,"ap1",YES,UINT32_MAX,52,abort,sizeof(abort));wipe(abort,sizeof(abort));
 Report[@"timedOutJoinNativeAbortStatus"]=@(status);
 Report[@"timedOutJoinNativeAbortCommandCount"]=@1;
 if(status){OwnedPendingRecoveryTerminal=YES;return NO;}
 OwnedPendingRecoveryActive=YES;OwnedPendingDrainDeadline=now+3;
 OwnedPendingRecoveryExpiry=now+8;OwnedPendingLastIdleSample=0;OwnedPendingIdleSamples=0;
 Report[@"timedOutJoinWaitingForOwnedIdleDrain"]=@YES;
 Report[@"timedOutJoinDrainMilliseconds"]=@3000;
 return YES;
}
static void advanceOwnedTimedOutJoinRecovery(double now){
 if(!OwnedPendingRecoveryActive||OwnedPendingRecoveryTerminal||Stop||
    now<OwnedPendingDrainDeadline)return;
 if(OwnedPendingLastIdleSample&&now-OwnedPendingLastIdleSample<.1)return;
 int state=ownedPendingJoinRecoveryState();OwnedPendingLastIdleSample=now;
 if(state<0||(state==0&&now>OwnedPendingRecoveryExpiry)){
  OwnedPendingRecoveryActive=NO;OwnedPendingRecoveryTerminal=YES;
  Report[@"timedOutJoinRecoveryRefusedAfterDrain"]=@YES;return;
 }
 OwnedPendingIdleSamples=state==1?OwnedPendingIdleSamples+1:0;
 Report[@"timedOutJoinStableIdleSamples"]=@(OwnedPendingIdleSamples);
 if(OwnedPendingIdleSamples<2)return;
 OwnedJoinPending=NO;OwnedJoinStateKnown=YES;OwnedPendingRecoveryActive=NO;
 Report[@"timedOutJoinWaitingForOwnedIdleDrain"]=@NO;
 Report[@"timedOutJoinPendingClearedAfterOwnedIdleProof"]=@YES;
}
