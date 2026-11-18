// Exact 20B101 clearWepKeysSync (0x2304c0) -> programKeySync (0x233668):
// four zero 164-byte wl_wsec_key records with only index=0..3, command45.
// The native virtual endpoint is translated to its firmware interface by
// handleCardSpecific -> wlc_ioctl -> runVirtualIOCtlSet/Get. Never use en0.
static BOOL clearOwnedStationDefaultKeys(void) {
 if(Stop||!ManagedStationBroker||!OwnedStationRoleActive||!MACRecorded||
    OwnedLeaseLock<0||!Primary||!Auxiliary||Primary==Auxiliary||
    PrimarySSIDBefore.length<1||PrimarySSIDBefore.length>32)return NO;
 uint8_t identity[6]={0},peer[6]={0};uint32_t infra=UINT32_MAX;
 int identityStatus=iovar(NO,"cur_etheraddr",1,NULL,0,identity,6);
 int endpointStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
 int peerStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,6);
 unsigned peerBits=0;for(unsigned i=0;i<6;i++)peerBits|=peer[i];
 BOOL scoped=!identityStatus&&!endpointStatus&&infra==1&&
    !memcmp(identity,OwnedMAC,6)&&
    (peerStatus==(int)0xe3ff8111||(!peerStatus&&!peerBits));
 memset(identity,0,sizeof(identity));memset(peer,0,sizeof(peer));
 recordPrimaryAssociation();
 Report[@"nativeDefaultKeyPreparationScopeVerified"]=@(scoped);
 if(!scoped||![Report[@"primaryAssociationPreserved"]boolValue]||Stop)return NO;
 NSMutableArray *statuses=[NSMutableArray array];
 Report[@"nativeDefaultKeyClearStatuses"]=statuses;
 for(uint32_t index=0;index<4&&!Stop;index++){
  uint8_t key[164]={0};memcpy(key,&index,4);
  int status=request(Auxiliary,"ap1",YES,UINT32_MAX,45,key,sizeof(key));
  wipe(key,sizeof(key));[statuses addObject:@(status)];if(status)return NO;
 }
 recordPrimaryAssociation();
 BOOL completed=!Stop&&statuses.count==4&&[Report[@"primaryAssociationPreserved"]boolValue];
 Report[@"nativeDefaultKeyPreparationCompleted"]=@(completed);return completed;
}
