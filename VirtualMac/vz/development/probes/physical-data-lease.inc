// Separate the physical STA lifetime from one authenticated guest data lease.
// Credential proof lives only in this root daemon; never adopt a live orphan.
static NSData *PhysicalVerifiedSSID;
static uint8_t PhysicalVerifiedBSSID[6];
static BOOL PhysicalVerifiedCredential;
static BOOL physicalPreparedIdentityValid(void){
 if(!PhysicalPrepared||!OwnedStationRoleActive||!MACRecorded||OwnedLeaseLock<0||Stop)return NO;
 uint8_t mac[6]={0};uint32_t infra=0;
 int identity=iovar(NO,"cur_etheraddr",1,NULL,0,mac,6);
 int modeStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
 BOOL valid=!identity&&!modeStatus&&infra==1&&!memcmp(mac,OwnedMAC,6);
 memset(mac,0,sizeof(mac));return valid;
}
// 1: confirmed unassociated; 2: the last credential-verified, authorized peer.
// 0: unknown/foreign state, which must not be exposed or modified.
static int physicalVerifiedAssociationState(void){
 uint8_t ssid[36]={0},peer[6]={0};uint32_t length=0;
 int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,ssid,sizeof(ssid));
 int bs=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,6);memcpy(&length,ssid,4);
 unsigned bits=0;for(unsigned i=0;i<6;i++)bits|=peer[i];
 if(!ss&&!length&&(bs==(int)0xe3ff8111||(!bs&&!bits)))return 1;
 if(ss||bs||!bits||!PhysicalVerifiedCredential||!ManagedActivePMKDigestValid||
    !PhysicalVerifiedSSID.length||length!=PhysicalVerifiedSSID.length||length>32||
    memcmp(ssid+4,PhysicalVerifiedSSID.bytes,length)||memcmp(peer,PhysicalVerifiedBSSID,6))return 0;
 // Same safe peer-scoped authorization query as the accepted native join.
 uint8_t info[512]={0};int status=iovar(NO,"sta_info",1,peer,6,info,sizeof(info));
 uint16_t version=0,size=0;uint32_t flags=0;
 if(!status){memcpy(&version,info,2);memcpy(&size,info+2,2);memcpy(&flags,info+8,4);}
 wipe(info,sizeof(info));wipe(ssid,sizeof(ssid));wipe(peer,sizeof(peer));
 return !status&&version>=3&&size>=16&&(flags&0x30)==0x30?2:0;
}
static BOOL physicalMayJoin(BOOL sameSSID,BOOL sameBSSID,BOOL sameCredential,int state){
 // A full-MAC SET_SSID can be a no-op for the already-connected peer.
 // Never accept a changed password using the old peer's authorized port.
 return state==1||(state==2&&(!sameSSID||!sameBSSID||sameCredential));
}
static BOOL physicalPrepareRetarget(BOOL sameSSID,BOOL sameBSSID,int state){
 if(state==2&&sameSSID&&sameBSSID)return YES;
 if((state!=1&&state!=2)||OwnedJoinPending)return NO;
 if(!physicalPreparedIdentityValid()||physicalVerifiedAssociationState()!=state)return NO;
 BOOL ready=state==1;
 if(state==2){
  uint8_t peer[6]={0},leave[12]={0};
  int read=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,sizeof(peer));
  if(read||memcmp(peer,PhysicalVerifiedBSSID,6)){wipe(peer,sizeof(peer));return NO;}
  int action=vm27_wifi_native_sta_leave_v1(read,peer,OwnedJoinStateKnown,OwnedJoinPending,leave);
  wipe(peer,sizeof(peer));int command=vm27_wifi_native_sta_command_v1(action,false);
  if(command!=52){wipe(leave,sizeof(leave));return NO;}
  int status=request(Auxiliary,"ap1",YES,UINT32_MAX,52,leave,sizeof(leave));wipe(leave,sizeof(leave));
  Report[@"physicalRetargetNativeLeaveStatus"]=@(status);Report[@"physicalRetargetNativeLeaveAction"]=@(action);
  if(status)return NO;
  for(unsigned i=0;i<20&&!Stop;i++){
   if(physicalPreparedIdentityValid()&&physicalVerifiedAssociationState()==1){ready=YES;break;}
   usleep(100000);
  }
  if(!ready)return NO;
  usleep(3000000);ready=!Stop&&physicalPreparedIdentityValid()&&physicalVerifiedAssociationState()==1;
 }
 Report[@"physicalRetargetSameActorUnassociatedVerified"]=@(ready);
 if(ready){
  // The complete native key/INFRA/auth/MFP/SETSSID sequence below owns
  // activation. Do not start an AP-style cached BSS before this target.
  ReusingQuiescedStation=NO;ManagedStationAssociated=NO;
  OwnedJoinStateKnown=YES;OwnedJoinPending=NO;
  PhysicalVerifiedCredential=NO;ManagedActivePMKDigestValid=NO;
  wipe(ManagedActivePMKDigest,sizeof(ManagedActivePMKDigest));
 }
 return ready;
}
static void physicalRememberVerifiedCredential(NSData *ssid,NSData *bssid){
 PhysicalVerifiedSSID=[ssid copy];memcpy(PhysicalVerifiedBSSID,bssid.bytes,6);
 PhysicalVerifiedCredential=YES;
}
