// Called only after the native AP owner reports idle and this actor holds
// the exclusive physical lease. Infer a missing marker in memory; never
// adopt a live orphan or weaken the subsequent fresh-credential join.
static NSDictionary *recoverMissingOwnedIdleMarker(NSDictionary *record){
 if(!record||record[@"retainedQuiescedStation"]||Stop||OwnedLeaseLock<0)return record;
 NSData *expected=[[NSData alloc]initWithBase64EncodedString:record[@"ownedAuxiliaryMACBase64"]options:0];
 NSData *nonce=[[NSData alloc]initWithBase64EncodedString:record[@"generatedSSIDBase64"]options:0];
 struct timeval boot={0};size_t size=sizeof(boot);
 if(![record[@"ownedStationRoleActive"]isEqual:@YES]||![record[@"build"]isEqual:@"20B101"]||
    [record[@"ownedFirmwareInterfaceIndex"]intValue]!=1||expected.length!=6||!nonce.length||nonce.length>32||
    sysctlbyname("kern.boottime",&boot,&size,NULL,0)||[record[@"ifEventFilterBootSeconds"]longLongValue]!=boot.tv_sec)return record;
 const uint8_t *mac=expected.bytes;unsigned bits=0;for(unsigned i=0;i<6;i++)bits|=mac[i];
 if(!bits||(mac[0]&1))return record;
 for(unsigned pass=0;pass<2;pass++){
  if(Stop)return record;
  uint8_t actual[6]={0};int identity=iovar(NO,"cur_etheraddr",1,NULL,0,actual,6);
  BOOL same=!identity&&!memcmp(actual,expected.bytes,6);wipe(actual,sizeof(actual));if(!same)return record;
  uint32_t infra=0;int modeStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
  if(modeStatus||infra!=1)return record;
  uint8_t name[36]={0};uint32_t length=0;int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,name,sizeof(name));
  memcpy(&length,name,4);wipe(name,sizeof(name));if(ss||length)return record;
  uint8_t peer[6]={0};int peerStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,sizeof(peer));
  unsigned present=0;for(unsigned i=0;i<6;i++)present|=peer[i];wipe(peer,sizeof(peer));
  if(peerStatus!=(int)0xe3ff8111&&(peerStatus||present))return record;
  for(NSString *key in @[@"wpa_auth",@"wsec",@"sup_wpa"]){
   uint32_t value=UINT32_MAX,wanted=[key isEqual:@"wpa_auth"]?128:[key isEqual:@"wsec"]?4:1;
   if(iovar(NO,key.UTF8String,1,NULL,0,&value,4)||value!=wanted)return record;
  }
  if(!pass)usleep(200000);
 }
 NSMutableDictionary *inferred=[record mutableCopy];inferred[@"retainedQuiescedStation"]=@YES;
 inferred[@"retainedAuthenticationConfigured"]=@YES;
 Report[@"ownedIdleMissingMarkerRecoveredFromStableReadOnlyProof"]=@YES;
 return inferred;
}
