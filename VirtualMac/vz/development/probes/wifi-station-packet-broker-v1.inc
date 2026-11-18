// Bounded development endpoint for the real auxiliary STA. Loopback only,
// per-session random token, one authenticated VM, no IP/NAT/default-route use.
#include "../../shared-radio/common/vm27_shared_radio_wire_v1.h"
#include "../../shared-radio/common/vm27_wifi_mac_translation_v1.h"
#include "../../shared-radio/common/vm27_wifi_host_isolation_v1.h"
static BOOL brokerHostAddresses(VM27WiFiHostAddressV1 host[VM27_WIFI_HOST_ADDRESS_LIMIT],size_t *count){
 *count=0;struct ifaddrs *rows=NULL;if(getifaddrs(&rows))return NO;BOOL valid=YES;
 for(struct ifaddrs *row=rows;row;row=row->ifa_next){
  if(!row->ifa_addr)continue;const uint8_t *bytes=NULL;unsigned family=0,size=0;
  if(row->ifa_addr->sa_family==AF_INET&&row->ifa_addr->sa_len>=sizeof(struct sockaddr_in)){
   const struct sockaddr_in *address=(const void *)row->ifa_addr;if(!address->sin_addr.s_addr)continue;
   bytes=(const uint8_t *)&address->sin_addr;family=4;size=4;
  }else if(row->ifa_addr->sa_family==AF_INET6&&row->ifa_addr->sa_len>=sizeof(struct sockaddr_in6)){
   const struct sockaddr_in6 *address=(const void *)row->ifa_addr;if(IN6_IS_ADDR_UNSPECIFIED(&address->sin6_addr))continue;
   bytes=address->sin6_addr.s6_addr;family=6;size=16;
  }else continue;
  if(*count==VM27_WIFI_HOST_ADDRESS_LIMIT){valid=NO;break;}
  host[*count].family=(uint8_t)family;memcpy(host[*count].bytes,bytes,size);++*count;
 }
 freeifaddrs(rows);return valid&&*count>0;
}
static NSArray *BrokerScanRows;static NSDictionary *BrokerNetwork;static BOOL BrokerScanDone;static double BrokerScanCompletedTime;
static BOOL brokerChannelEligible(unsigned channel){
 if(!channel||channel>196)return NO;
#ifdef VM27_WIFI_OPPOSITE_BAND_ONLY
 // This development profile has demonstrated data only with one STA in
 // each band. Advertise actual eligible BSSs of any SSID; same-band MCC is
 // unverified and must not be attempted merely because a BSS was scanned.
 return PrimaryChannel&&((channel>14)!=(PrimaryChannel>14));
#else
 return YES;
#endif
}
static NSString *brokerPacketKind(const uint8_t *p,size_t n){
 if(n<14)return @"short";unsigned type=read16(p+12);if(type==0x0806)return @"arp";if(type==0x86dd)return @"ipv6";if(type!=0x0800||n<34)return @"other";
 const uint8_t *ip=p+14;size_t ihl=(ip[0]&15)*4,total=read16(ip+2);if(ihl<20||total<ihl||total>n-14)return @"malformed-ipv4";if(ip[9]!=17)return ip[9]==6?@"ipv4-tcp":@"ipv4-other";
 if(total<ihl+8)return @"short-udp";const uint8_t *udp=ip+ihl;size_t length=read16(udp+4);if(length<248||length>total-ihl||!((read16(udp)==67&&read16(udp+2)==68)||(read16(udp)==68&&read16(udp+2)==67)))return @"ipv4-udp";
 const uint8_t *d=udp+8;if(memcmp(d+236,"\x63\x82\x53\x63",4))return @"udp-without-dhcp-cookie";
 for(size_t at=240;at<length-8;){uint8_t type=d[at++];if(type==255)break;if(!type)continue;if(at>=length-8)break;uint8_t count=d[at++];if(count>length-8-at)break;if(type==53&&count==1)return [NSString stringWithFormat:@"dhcp-%u",d[at]];at+=count;}return @"dhcp-without-type";
}
static id brokerProperty(CFTypeRef x){if(!x)return NSNull.null;id value=(__bridge id)x;if([value isKindOfClass:NSData.class])return @{@"base64":[value base64EncodedStringWithOptions:0]};return [value isKindOfClass:NSString.class]||[value isKindOfClass:NSNumber.class]?value:NSNull.null;}
static BOOL brokerAddress(id value,uint8_t mac[6]){
 if([value isKindOfClass:NSDictionary.class]){NSData *d=[[NSData alloc]initWithBase64EncodedString:value[@"base64"]options:0];if(d.length!=6)return NO;memcpy(mac,d.bytes,6);return YES;}
 if(![value isKindOfClass:NSString.class])return NO;NSArray *parts=[value componentsSeparatedByString:@":"];if(parts.count!=6)return NO;
 for(unsigned i=0;i<6;i++){unsigned n=0;NSScanner *s=[NSScanner scannerWithString:parts[i]];if(![s scanHexInt:&n]||!s.isAtEnd||n>255)return NO;mac[i]=(uint8_t)n;}return YES;
}
#include "native-scan-lease.inc"
static BOOL stationFirmwareProfileVerified(void){
 uint32_t spec=0;int status=iovar(NO,"chanspec",0,NULL,0,&spec,4);
 BOOL format=!status&&(spec&0xc000)==(PrimaryChannel>14?0xc000:0)&&(spec&0x3800)>=0x1000;
 Report[@"nativeChanspecFormatReadStatus"]=@(status);Report[@"nativeD11ACChanspecFormatVerified"]=@(format);
 uint8_t version[16]={0};status=iovar(NO,"wlc_ver",0,NULL,0,version,sizeof(version));
 uint16_t actualVersion=0;memcpy(&actualVersion,version+12,2);FirmwareInterfaceVersion=actualVersion;
 Report[@"firmwareInterfaceVersionReadStatus"]=@(status);Report[@"firmwareInterfaceVersion"]=@(FirmwareInterfaceVersion);
 return format&&!status&&FirmwareInterfaceVersion>=3&&FirmwareInterfaceVersion<18;
}
static BOOL brokerSelectNativeChanspec(NSDictionary *row){
#ifdef VM27_WIFI_USE_ACTUAL_SCAN_CHANSPEC
 id flags=row[@"CHANNEL_FLAGS"],width=row[@"CHANNEL_WIDTH"];
 if(![flags isKindOfClass:NSNumber.class]||![width isKindOfClass:NSNumber.class])return NO;
 NSData *ies=nil;id encoded=row[@"IE"];
 if([encoded isKindOfClass:NSDictionary.class]&&[encoded[@"base64"]isKindOfClass:NSString.class])
  ies=[[NSData alloc]initWithBase64EncodedString:encoded[@"base64"]options:0];
 uint16_t spec=0;
 if(!vm27_wifi_native_chanspec_v1([row[@"CHANNEL"]unsignedIntValue],[flags unsignedIntValue],
     [width unsignedIntValue],ies.bytes,ies.length,&spec))return NO;
 TargetNativeChanspec=spec;TargetNativeBandwidth=[width unsignedIntValue];
#else
 (void)row;
#endif
 return YES;
}
static BOOL selectStationCandidate(void){
 if(!scanStationRows())return NO;NSDictionary *selected=nil;BOOL opposite=NO;unsigned count=0;NSMutableArray *candidateChannels=[NSMutableArray array];
 for(NSDictionary *row in BrokerScanRows)if([row[@"ssidBase64"]isEqual:[TargetSSID base64EncodedStringWithOptions:0]]){
  uint8_t address[6];if(!brokerAddress(row[@"BSSID"],address))continue;uint32_t channel=[row[@"CHANNEL"]unsignedIntValue];if(!channel||channel>196)continue;count++;BOOL different=(channel>14)!=(PrimaryChannel>14);
  [candidateChannels addObject:@{@"channel":@(channel),@"RSSI":row[@"RSSI"]?:NSNull.null}];
  BOOL preferred=different;
#ifdef VM27_WIFI_PREFER_SAME_BAND
  preferred=!different;
#endif
  BOOL selectedPreferred=selected?(([[selected objectForKey:@"CHANNEL"]unsignedIntValue]>14)!=(PrimaryChannel>14)):NO;
#ifdef VM27_WIFI_PREFER_SAME_BAND
  selectedPreferred=!selectedPreferred;
#endif
  if(!selected||(preferred&&!selectedPreferred)||(preferred==selectedPreferred&&[row[@"RSSI"]intValue]>[selected[@"RSSI"]intValue])){selected=row;opposite=different;}
 }
 Report[@"stationCandidateCount"]=@(count);Report[@"stationCandidateOppositeBand"]=@(opposite);Report[@"primaryChannel"]=@(PrimaryChannel);
 Report[@"requestedTargetCandidateChannels"]=candidateChannels;
 if(!selected)return NO;TargetChannel=[selected[@"CHANNEL"]unsignedIntValue];Report[@"targetChannel"]=@(TargetChannel);if(!brokerAddress(selected[@"BSSID"],TargetBSSID))return NO;
 return brokerSelectNativeChanspec(selected)&&stationFirmwareProfileVerified();
}
static BOOL brokerPrimaryLeaseStillValid(void){
 uint8_t bytes[36]={0};uint32_t count=0;
 int status=request(Primary,"en0",NO,UINT32_MAX,25,bytes,sizeof(bytes));memcpy(&count,bytes,4);
 BOOL same=!status&&count>0&&count<=32&&count==PrimarySSIDBefore.length&&!memcmp(bytes+4,PrimarySSIDBefore.bytes,count);
 memset(bytes,0,sizeof(bytes));if(!same)return NO;
 CFTypeRef network=CurrentNetwork(PrimaryDevice);
 CFTypeRef value=network?NetworkProperty(network,CFSTR("CHANNEL")):NULL;
 unsigned channel=value&&CFGetTypeID(value)==CFNumberGetTypeID()?[(__bridge NSNumber *)value unsignedIntValue]:0;
 if(network)CFRelease(network);
 if(!channel||channel>196||(channel>14)!=(PrimaryChannel>14))return NO;
 PrimaryChannel=channel;return YES;
}
static BOOL brokerReadNetwork(void){
 uint8_t expected[6]={0};if(ManagedStationBroker&&!ManagedStationAssociated)memcpy(expected,TargetBSSID,6);else{int status=request(Auxiliary,"ap1",NO,UINT32_MAX,23,expected,6);if(status)return NO;}
 for(NSDictionary *row in BrokerScanRows){uint8_t address[6];if(brokerAddress(row[@"BSSID"],address)&&!memcmp(address,expected,6)&&[row[@"ssidBase64"]isEqual:[TargetSSID base64EncodedStringWithOptions:0]]){BrokerNetwork=row;break;}}
 Report[ManagedStationBroker&&!ManagedStationAssociated?@"brokerPreviewBSSMatched":@"brokerActualBSSMatched"]=@(BrokerNetwork!=nil);memset(expected,0,sizeof(expected));return BrokerNetwork!=nil;
}
#include "physical-data-lease.inc"
#include "persistent-data-descriptor.inc"
static BOOL brokerManagedAssociate(NSDictionary *input,uint8_t guestMAC[6],int *bpf,BOOL *accepted){
 *accepted=NO;unsigned joinCallsBefore=[Report[@"networkAssociationCalls"]unsignedIntValue];
 NSData *ssid=[input[@"ssidBase64"]isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:input[@"ssidBase64"]options:0]:nil;
 NSData *bssid=[input[@"bssidBase64"]isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:input[@"bssidBase64"]options:0]:nil;
 NSData *mac=[input[@"macBase64"]isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:input[@"macBase64"]options:0]:nil;
 NSMutableData *pmk=[input[@"pmkBase64"]isKindOfClass:NSString.class]?[[[NSData alloc]initWithBase64EncodedString:input[@"pmkBase64"]options:0]mutableCopy]:nil;
 BOOL valid=ssid.length>0&&ssid.length<=32&&bssid.length==6&&mac.length==6&&pmk.length==32&&[input[@"keyType"]isEqual:@1]&&!(((const uint8_t *)mac.bytes)[0]&1);
 if(ManagedDevelopmentBSSRestriction&&(![ssid isEqual:ManagedAllowedSSID]||![bssid isEqual:ManagedAllowedBSSID])){
  valid=NO;Report[@"managedDevelopmentRequestsRejectedBeforeHardware"]=@([Report[@"managedDevelopmentRequestsRejectedBeforeHardware"]unsignedIntValue]+1);
  Report[@"managedRejectedSSIDMatchesPreview"]=@([ssid isEqual:ManagedAllowedSSID]);Report[@"managedRejectedBSSIDMatchesPreview"]=@([bssid isEqual:ManagedAllowedBSSID]);Report[@"managedRejectedRequestedChannel"]=input[@"channel"]?:@0;
 }
 NSDictionary *selected=nil;
 // Select only a real BSS from the last physical scan, using every identity
 // field from the native guest's request. Unsupported security fails closed.
 if(valid&&!brokerChannelEligible([input[@"channel"]unsignedIntValue])){
  valid=NO;Report[@"managedUnsupportedBandRequestsRejectedBeforeHardware"]=@([Report[@"managedUnsupportedBandRequestsRejectedBeforeHardware"]unsignedIntValue]+1);
 }
 if(valid)for(NSDictionary *row in BrokerScanRows){uint8_t address[6]={0};if([row[@"ssidBase64"]isEqual:input[@"ssidBase64"]]&&brokerAddress(row[@"BSSID"],address)&&!memcmp(address,bssid.bytes,6)&&[row[@"CHANNEL"]isEqual:input[@"channel"]]){selected=row;break;}}
 valid=valid&&selected!=nil;
 if(valid)valid=brokerSelectNativeChanspec(selected);
 // An ineligible candidate must leave an already authenticated link alone.
 // Native auto-join can try another saved BSS while the user is connecting.
 if(valid){*accepted=YES;valid=brokerReleaseDataPlane(bpf);}
 uint8_t digest[CC_SHA256_DIGEST_LENGTH]={0};if(valid)CC_SHA256(pmk.bytes,(CC_LONG)pmk.length,digest);
 if(valid&&PhysicalPrepared){
  int state=physicalPreparedIdentityValid()?physicalVerifiedAssociationState():0;
  BOOL sameSSID=PhysicalVerifiedCredential&&[ssid isEqual:PhysicalVerifiedSSID];
  BOOL sameBSSID=PhysicalVerifiedCredential&&!memcmp(bssid.bytes,PhysicalVerifiedBSSID,6);
  BOOL sameCredential=ManagedActivePMKDigestValid&&!memcmp(digest,ManagedActivePMKDigest,sizeof(digest));
  if(!physicalMayJoin(sameSSID,sameBSSID,sameCredential,state)){
   Report[@"physicalCredentialOrIdentityMismatchRefusedBeforeJoin"]=@YES;valid=NO;
  }else if(state==2&&sameSSID&&sameBSSID&&sameCredential){
   TargetSSID=ssid;TargetChannel=[selected[@"CHANNEL"]unsignedIntValue];memcpy(TargetBSSID,bssid.bytes,6);
   BrokerNetwork=selected;ManagedStationAssociated=YES;memcpy(guestMAC,mac.bytes,6);
   [pmk resetBytesInRange:NSMakeRange(0,pmk.length)];wipe(digest,sizeof(digest));
   Report[@"physicalAuthorizedAssociationReusedWithMatchingCredential"]=@YES;return YES;
  }else if(!physicalPrepareRetarget(sameSSID,sameBSSID,state)){
   Report[@"physicalRetargetRefusedBeforeNewJoin"]=@YES;valid=NO;
  }
 }
 if(valid){
  TargetSSID=ssid;Report[@"differentSSIDRequested"]=@(![TargetSSID isEqual:PrimarySSIDBefore]);
  TargetChannel=[selected[@"CHANNEL"]unsignedIntValue];Report[@"actualGuestRequestedChannel"]=@(TargetChannel);
  memcpy(TargetBSSID,bssid.bytes,6);TargetPMK=pmk;TargetPassword=nil;
  ManagedStationAssociated=NO;
  if(!PhysicalPrepared){valid=prepareOwnedStation();if(valid)PhysicalPrepared=YES;}
  else valid=physicalPreparedIdentityValid();
  if(valid)valid=associateStation();
  if(valid){BrokerNetwork=selected;memcpy(guestMAC,mac.bytes,6);ManagedStationAssociated=YES;
   memcpy(ManagedActivePMKDigest,digest,sizeof(digest));ManagedActivePMKDigestValid=YES;
   physicalRememberVerifiedCredential(ssid,bssid);
   Report[@"brokerActualBSSMatched"]=@YES;Report[@"managedGuestPMKAssociationVerified"]=@YES;}
 }
 if(pmk.length)[pmk resetBytesInRange:NSMakeRange(0,pmk.length)];wipe(digest,sizeof(digest));TargetPMK=nil;
 // Emit numeric state immediately, before a persistent worker exits. Never
 // log the request, credentials, SSID, BSSID or controller identity.
 NSMutableDictionary *diagnostic=[@{@"phase":@"owned-native-join",@"accepted":@(*accepted),@"completed":@(valid),@"physicalJoinIssued":@([Report[@"networkAssociationCalls"]unsignedIntValue]>joinCallsBefore)}mutableCopy];
#ifdef VM27_WIFI_RETAIN_RECENT_NATIVE_BSS
 diagnostic[@"selectedNativeBSSAgeMS"]=@(selected?brokerObservedScanAgeMS(selected,NSProcessInfo.processInfo.systemUptime):UINT32_MAX);
 for(NSString *key in @[@"nativeScanFreshBSSCount",@"nativeScanRecentBSSRetainedCount",@"nativeScanRecentBSSLifetimeMS"])
  if(Report[key])diagnostic[key]=Report[key];
#endif
 for(NSString *key in @[@"nativeTDPolicyIdentityVerified",@"nativeTDPolicySetStatus",@"nativeTDPolicyValue",@"nativeTDPolicySetCalls",@"timedOutJoinRecoveryScopeVerified",@"timedOutJoinNativeAbortStatus",@"timedOutJoinNativeAbortCommandCount",@"timedOutJoinWaitingForOwnedIdleDrain",@"timedOutJoinDrainMilliseconds",@"timedOutJoinStableIdleSamples",@"timedOutJoinRecoveryRefusedAfterDrain",@"timedOutJoinPendingClearedAfterOwnedIdleProof",@"nativeDefaultKeyPreparationScopeVerified",@"nativeDefaultKeyClearStatuses",@"nativeDefaultKeyPreparationCompleted",@"nativeJoinInfrastructureSetStatus",@"nativeJoinInfrastructureReadStatus",@"nativeJoinInfrastructureReadValue",@"nativeJoinPreparationFailureRefusedBeforeWrites",@"stationNativeMFPValue",@"stationSetNativeMFPStatus",@"stationNativeMFPFailureRefusedBeforeWrites",@"physicalRetargetNativeLeaveStatus",@"physicalRetargetNativeLeaveAction",@"physicalRetargetSameActorUnassociatedVerified",@"physicalRetargetRefusedBeforeNewJoin",@"actualGuestRequestedChannel",@"brokerNativeScanCompletedCallbacks",@"brokerNativeScanCancellationCalls",@"brokerNativeScanIgnoredCallbacks",@"ownedIdleMissingMarkerRecoveredFromStableReadOnlyProof",@"ownedBssVerifiedFirmwareIndex",@"ownedBssOperationUsesExactVerifiedFirmwareIndex",@"ownedRetargetBSSDisabledBeforeTargetStatus",@"authorizationMaximumWaitMilliseconds",@"physicalRetargetUsesNativeSetSSIDWithoutPreLeave",@"physicalRetargetReadOnlyState",@"nativeJoinV17Flags",@"nativeJoinTargetChanspec",@"nativeJoinTargetBandwidthMHz",@"stationSetSSIDStatus",@"secondStationAuthorized",@"associationSamples",
     @"retainedStationResumedBeforeNewAuthentication",@"retainedStationJoinAbortAfterResumeStatus",@"retainedStationUnassociatedAfterResumeVerified",
     @"retainedStationJoinConfiguredBeforeBSSResume",@"retainedStationBSSResumeStatus",@"retainedStationResumeIdentityVerified",
     @"retainedStationJoinStartedAfterBSSResumeStatus",@"retainedStationBSSReadStatus",@"retainedStationBSSReadValue",
     @"retainedStationEnabledReadStatus",@"retainedStationEnabledBeforeJoin",@"retainedStationNoExplicitBSSCycle",
     @"originalAuxiliaryModeReadStatus",@"originalAuxiliaryMode",@"originalAuxiliaryEndpointStatus",@"originalAuxiliarySSIDStatus",
     @"retainedStationIdentityReadStatus",@"retainedStationNativeEndpointWakeStatus",@"retainedStationInactiveSSIDReadStatus",
     @"retainedQuiescedStationIdentityAndSecurityVerified",@"retainedNativeEndpointAbsentVerified",@"priorInactiveReceiptRetired",
     @"nativeAuxiliaryBootstrapStatus",@"auxiliaryFirmwareEndpointStatus",@"stationConversionEndpointVerified",
     @"cleanupUsesSingleNativeStationRetirement",@"cleanupNativeSTAAction",@"cleanupNativeSTAReason",@"cleanupNativeSTACommandCount",@"cleanupNativeSTACommand",
     @"stationNativeAuxiliaryPowerReadStatus",@"stationNativeAuxiliaryPowerState",@"stationNativeAuxiliaryPowerSaveEnabled",
     @"nativeReaderRenewalEligibility",@"nativeControlReadersClosedAndReopened",@"nativeReaderRenewalAbsenceSamples",@"nativeOwnerRetiredAuxiliaryBeforeRejoin",
     @"nativeStationJoinManagesBSSState",
     @"retainedStationAuthReadStatus",@"retainedStationAuthReadValue",@"retainedStationEncryptionReadStatus",@"retainedStationEncryptionReadValue",
     @"stationRoleBeforeJoinReadStatus",@"stationRoleBeforeJoinValue",@"stationInfraBeforeJoinReadStatus",@"stationInfraBeforeJoinValue",
     @"stationRoleAfterResumeReadStatus",@"stationRoleAfterResumeValue",@"stationInfraAfterResumeReadStatus",@"stationInfraAfterResumeValue",
     @"retainedStationSecurityRestoredAfterBSSResumeStatus",@"ownedBssConfigIdentityMatchCount",@"ownedVerifiedBssConfigIndex",
     @"explicitOwnedBssResumeStatus",@"explicitOwnedBssDownStatus"])
  if(Report[key])diagnostic[key]=Report[key];
 NSData *diagnosticBytes=[NSJSONSerialization dataWithJSONObject:diagnostic options:NSJSONWritingSortedKeys error:NULL];
 if(diagnosticBytes){fwrite(diagnosticBytes.bytes,1,diagnosticBytes.length,stderr);fputc('\n',stderr);fflush(stderr);}
 return valid;
}
static NSDictionary *brokerWiFiState(BOOL attached){
 BOOL associated=(!ManagedStationBroker||ManagedStationAssociated)&&attached;
 NSMutableDictionary *wifi=[@{@"hostPowered":@YES,@"hostAssociated":@(associated),@"guestAttached":@(attached),@"dataPathConfigured":@(attached),@"mode":ManagedStationBroker?@"independent-native-managed-station":@"independent-native-auxiliary-station"}mutableCopy];
 if(associated&&BrokerNetwork)wifi[@"network"]=BrokerNetwork;
 return @{@"ok":@YES,@"wifi":wifi};
}
static int brokerTransfer(int fd,void *bytes,size_t length,BOOL sending){
 uint8_t *p=bytes;size_t used=0;double end=NSProcessInfo.processInfo.systemUptime+4;
 while(used<length&&!Stop){if(NSProcessInfo.processInfo.systemUptime>end)return ETIMEDOUT;struct pollfd item={fd,sending?POLLOUT:POLLIN,0};int ready=poll(&item,1,100);if(ready<=0){if(ready<0&&errno!=EINTR)return errno;continue;}ssize_t n=sending?send(fd,p+used,length-used,0):recv(fd,p+used,length-used,0);if(n>0){used+=(size_t)n;continue;}if(n<0&&(errno==EINTR||errno==EAGAIN))continue;return n<0?errno:EPIPE;}return used==length?0:ECANCELED;
}
static BOOL brokerAssociationLive(void){
 static double nextValidation;double now=NSProcessInfo.processInfo.systemUptime;if(now<nextValidation)return YES;
 for(unsigned attempt=0;attempt<8&&!Stop;attempt++){
  uint8_t bytes[36]={0},address[6]={0},expected[6]={0};uint32_t length=0;
  int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,bytes,sizeof(bytes)),bs=request(Auxiliary,"ap1",NO,UINT32_MAX,23,address,6);memcpy(&length,bytes,4);
  if(!ss&&!bs){BOOL valid=length==TargetSSID.length&&length<=32&&!memcmp(bytes+4,TargetSSID.bytes,length)&&brokerAddress(BrokerNetwork[@"BSSID"],expected)&&!memcmp(address,expected,6);if(valid)nextValidation=NSProcessInfo.processInfo.systemUptime+.5;return valid;}
  Report[@"brokerLastSSIDReadStatus"]=@(ss);Report[@"brokerLastBSSIDReadStatus"]=@(bs);usleep(250000);
 }return NO;
}
static BOOL brokerOpenDataPlane(int *descriptor,unsigned *capacity){
 if(ManagedStationBroker)return physicalOpenDataPlane(descriptor,capacity);
 struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));unsigned one=1,zero=0;
 int fd=-1;for(unsigned i=0;i<256;i++){char path[32];snprintf(path,sizeof(path),"/dev/bpf%u",i);fd=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC);if(fd>=0||errno!=EBUSY)break;}
 if(fd<0)return NO;
 if(ioctl(fd,VM27_BIOCSETIF,&interface)||ioctl(fd,VM27_BIOCGBLEN,capacity)||*capacity<20||*capacity>524288||ioctl(fd,VM27_BIOCIMMEDIATE,&one)||ioctl(fd,VM27_BIOCSHDRCMPLT,&one)||ioctl(fd,VM27_BIOCSSEESENT,&zero)){close(fd);return NO;}
 *descriptor=fd;return YES;
}
static BOOL serveStationPackets(NSData *token){
 BOOL owned=OwnedStationSessionFD>=0;BOOL sessionStopped=NO;
 if(!owned&&(token.length!=32||!brokerReadNetwork()))return NO;
 const char *metadata="/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1/native-network-v1.json";
 if(!owned){
 NSData *networkData=[NSJSONSerialization dataWithJSONObject:BrokerNetwork options:0 error:NULL];int metadataFD=open(metadata,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(metadataFD<0)return NO;
 BOOL metadataSaved=write(metadataFD,networkData.bytes,networkData.length)==(ssize_t)networkData.length&&!fsync(metadataFD);close(metadataFD);if(!metadataSaved){unlink(metadata);return NO;}
 }
 int bpf=-1,control=-1,listener=-1,peer=owned?OwnedStationSessionFD:-1;BOOL flagsChanged=NO,attached=NO,authenticated=NO;short originalFlags=0;unsigned capacity=0,one=1,zero=0;uint8_t guestMAC[6]={0};BOOL guestMACSet=NO;
 NSMutableDictionary *txKinds=[NSMutableDictionary dictionary],*rxKinds=[NSMutableDictionary dictionary];
 uint64_t generation=0,lastSequence=0,tx=0,rx=0,dropped=0;arc4random_buf(&generation,sizeof(generation));if(!generation)generation=1;
 struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));
 if(!ManagedStationBroker){
 control=socket(AF_INET,SOCK_DGRAM,0);if(control<0||ioctl(control,SIOCGIFFLAGS,&interface))goto done;originalFlags=interface.ifr_flags;
 if(!(originalFlags&IFF_UP)){
  NSMutableDictionary *receipt=[[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL]mutableCopy];if(!receipt)goto done;receipt[@"originalAuxiliaryBSDFlags"]=@(originalFlags);
  NSData *saved=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];int identity=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW);if(identity<0)goto done;BOOL persisted=write(identity,saved.bytes,saved.length)==(ssize_t)saved.length&&!fsync(identity);close(identity);if(!persisted)goto done;
  interface.ifr_flags=originalFlags|IFF_UP;if(ioctl(control,SIOCSIFFLAGS,&interface))goto done;flagsChanged=YES;
 }
 for(unsigned i=0;i<256;i++){char path[32];snprintf(path,sizeof(path),"/dev/bpf%u",i);bpf=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC);if(bpf>=0||errno!=EBUSY)break;}
 if(bpf<0||ioctl(bpf,VM27_BIOCSETIF,&interface)||ioctl(bpf,VM27_BIOCGBLEN,&capacity)||capacity<20||capacity>524288||ioctl(bpf,VM27_BIOCIMMEDIATE,&one)||ioctl(bpf,VM27_BIOCSHDRCMPLT,&one)||ioctl(bpf,VM27_BIOCSSEESENT,&zero))goto done;
 }
 if(owned){
  setsockopt(peer,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
  Report[@"brokerOwnedUnixSession"]=@YES;
 }else{
  listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)goto done;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));struct sockaddr_in address={.sin_len=sizeof(address),.sin_family=AF_INET,.sin_port=htons(39034),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
  if(bind(listener,(void *)&address,sizeof(address))||listen(listener,1))goto done;
  fputs("VM27_AUXILIARY_WIFI_PACKET_BROKER_READY\n",stderr);fflush(stderr);Report[@"brokerLoopbackListenerReady"]=@YES;
 }
 if(ManagedStationBroker){Report[@"managedAssociationDeferredUntilGuest"]=@YES;Report[@"managedAssociationCallsBeforeGuestRequest"]=Report[@"networkAssociationCalls"]?:@0;}
 {
  NSMutableData *buffer=[NSMutableData dataWithLength:capacity];double end=owned?DBL_MAX:NSProcessInfo.processInfo.systemUptime+240,idleEnd=NSProcessInfo.processInfo.systemUptime+45,lastActivity=NSProcessInfo.processInfo.systemUptime;
  while(!Stop&&!sessionStopped&&NSProcessInfo.processInfo.systemUptime<end){@autoreleasepool{
   advanceOwnedTimedOutJoinRecovery(NSProcessInfo.processInfo.systemUptime);
   if(owned&&peer<0)break;
   if(owned&&!authenticated&&NSProcessInfo.processInfo.systemUptime-lastActivity>20){Report[@"ownedUnauthenticatedSessionExpired"]=@YES;break;}
   if(!Sent&&!authenticated&&NSProcessInfo.processInfo.systemUptime>idleEnd){Report[@"unclaimedDevelopmentSessionExpired"]=@YES;break;}
   if(peer<0){struct pollfd item={listener,POLLIN,0};if(poll(&item,1,100)<=0)continue;peer=accept(listener,NULL,NULL);if(peer<0)continue;setsockopt(peer,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));authenticated=NO;lastSequence=0;}
   struct pollfd item={peer,POLLIN,0};int ready=poll(&item,1,100);if(ready<=0)continue;
   uint8_t header[32];struct vm27_radio_frame_v1 frame;if(brokerTransfer(peer,header,32,NO)||vm27_radio_header_decode_v1(header,32,&frame)||frame.request_id<=lastSequence){close(peer);peer=-1;attached=NO;if(authenticated||owned){Report[@"brokerClientClosed"]=@YES;sessionStopped=YES;}continue;}
   lastActivity=NSProcessInfo.processInfo.systemUptime;
   NSMutableData *payload=[NSMutableData dataWithLength:frame.payload_bytes];if(brokerTransfer(peer,payload.mutableBytes,payload.length,NO)){close(peer);peer=-1;attached=NO;continue;}
   NSDictionary *input=[NSJSONSerialization JSONObjectWithData:payload options:0 error:NULL];wipe(payload.mutableBytes,payload.length);NSDictionary *reply=@{@"ok":@NO,@"error":@{@"code":@(EINVAL)}};
   if(![input isKindOfClass:NSDictionary.class]){close(peer);peer=-1;continue;}lastSequence=frame.request_id;
   if(frame.type==VM27_RADIO_HELLO&&!authenticated){
    if(owned)authenticated=[input[@"protocol"]isEqual:@1]&&frame.generation==0;
    else{NSData *supplied=[input[@"tokenBase64"]isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:input[@"tokenBase64"]options:0]:nil;unsigned difference=0;if(supplied.length==32)for(unsigned i=0;i<32;i++)difference|=((const uint8_t *)supplied.bytes)[i]^((const uint8_t *)token.bytes)[i];authenticated=supplied.length==32&&!difference;}
    reply=@{@"ok":@(authenticated),@"protocol":@1};
   }
   else if(authenticated&&frame.type==VM27_RADIO_REQUEST&&frame.generation==generation){
    NSString *method=input[@"method"];
    if(owned&&([method isEqual:@"wifi.state"]||[method isEqual:@"wifi.scan"]||[method isEqual:@"wifi.associate"])&&!brokerPrimaryLeaseStillValid()){
     // Renew the physical lease after a host network/band change. Its saved
     // primary identity and eligible-band policy must not survive that change.
     Report[@"brokerPrimaryNetworkChangedLeaseRenewalRequested"]=@YES;sessionStopped=YES;continue;
    }
    if((!ManagedStationBroker||ManagedStationAssociated)&&!brokerAssociationLive()){Report[@"brokerStoppedAfterAssociationStateUnavailable"]=@YES;sessionStopped=YES;continue;}
    if(ManagedStationBroker&&[method isEqual:@"wifi.attachShared"]){sessionStopped=YES;Report[@"managedLegacyAttachRejected"]=@YES;continue;}
    if(ManagedStationBroker&&[method isEqual:@"wifi.associate"]){
     BOOL accepted=NO;BOOL joined=brokerManagedAssociate(input,guestMAC,&bpf,&accepted);
     if(accepted){
      [buffer resetBytesInRange:NSMakeRange(0,buffer.length)];
      if(joined)joined=brokerOpenDataPlane(&bpf,&capacity);
      if(joined)[buffer setLength:capacity];else{ManagedStationAssociated=NO;}
      guestMACSet=joined;attached=joined;
     }
     if(joined)reply=brokerWiFiState(attached);else{NSMutableDictionary *failure=[brokerWiFiState(attached)mutableCopy];failure[@"ok"]=@NO;failure[@"error"]=@{@"code":@(ENETUNREACH)};reply=failure;}
    }
    if([method isEqual:@"wifi.attachShared"]){attached=[input[@"ssidBase64"]isEqual:BrokerNetwork[@"ssidBase64"]];NSString *encoded=input[@"macBase64"];NSData *mac=[encoded isKindOfClass:NSString.class]?[[NSData alloc]initWithBase64EncodedString:encoded options:0]:nil;if(mac.length==6&&!(((const uint8_t *)mac.bytes)[0]&1)){memcpy(guestMAC,mac.bytes,6);guestMACSet=YES;}}
    else if([method isEqual:@"wifi.detachShared"]){
     (void)brokerReleaseDataPlane(&bpf);
     [buffer resetBytesInRange:NSMakeRange(0,buffer.length)];
     wipe(guestMAC,sizeof(guestMAC));
     Report[@"guestDataLeaseDetachedPhysicalAssociationRetained"]=@YES;
     attached=NO;guestMACSet=NO;
    }
    if([method isEqual:@"wifi.state"]||[method isEqual:@"wifi.attachShared"]||[method isEqual:@"wifi.detachShared"]){reply=brokerWiFiState(attached);}
    else if([method isEqual:@"wifi.scan"]){
     if(ManagedStationBroker){
      BOOL scanned=YES;if(!Sent||Stopped||(owned&&NSProcessInfo.processInfo.systemUptime-BrokerScanCompletedTime>5))scanned=scanStationRows();else Report[@"managedConnectedScanUsesPhysicalCache"]=@YES;
      unsigned age=(unsigned)MIN(UINT32_MAX,(NSProcessInfo.processInfo.systemUptime-BrokerScanCompletedTime)*1000);NSMutableArray *rows=[NSMutableArray array];
      for(NSDictionary *row in BrokerScanRows){
       if(!brokerChannelEligible([row[@"CHANNEL"]unsignedIntValue]))continue;
       if(ManagedDevelopmentBSSRestriction){uint8_t address[6]={0};if(![row[@"ssidBase64"]isEqual:[ManagedAllowedSSID base64EncodedStringWithOptions:0]]||!brokerAddress(row[@"BSSID"],address)||memcmp(address,ManagedAllowedBSSID.bytes,6))continue;}
       NSMutableDictionary *copy=[row mutableCopy];
#ifdef VM27_WIFI_RETAIN_RECENT_NATIVE_BSS
       unsigned rowAge=brokerObservedScanAgeMS(row,NSProcessInfo.processInfo.systemUptime);
       if(rowAge>=BrokerObservedScanLifetimeMS)continue;
       copy[@"ageMS"]=@(rowAge);
#else
       copy[@"ageMS"]=@(age);
#endif
       [rows addObject:copy];
      }
      reply=@{@"ok":@(scanned),@"networks":rows,@"source":@"native-wifid-scan",@"cacheAgeMS":@(age)};
     }
     else{
     // This bounded prototype has one pre-authorized physical BSS. Do not
     // offer another BSSID of that SSID as an eligible candidate for its link.
     NSMutableArray *eligible=[NSMutableArray array];for(NSDictionary *row in BrokerScanRows)if(![row[@"ssidBase64"]isEqual:BrokerNetwork[@"ssidBase64"]]||[row[@"BSSID"]isEqual:BrokerNetwork[@"BSSID"]])[eligible addObject:row];
     Report[@"brokerTargetBSSFilterEnabled"]=@YES;reply=@{@"ok":@YES,@"networks":eligible,@"source":@"native-wifid-scan"};
     }
    }
    else if([method isEqual:@"wifi.data"]&&attached){
     VM27WiFiHostAddressV1 hostAddresses[VM27_WIFI_HOST_ADDRESS_LIMIT]={0};size_t hostCount=0;
     BOOL hostSnapshot=brokerHostAddresses(hostAddresses,&hostCount);
     NSArray *frames=input[@"frames"];NSMutableArray *received=[NSMutableArray array];BOOL valid=[frames isKindOfClass:NSArray.class]&&frames.count<=24;
     if(valid)for(id encoded in frames){NSMutableData *packet=[encoded isKindOfClass:NSString.class]?[[[NSData alloc]initWithBase64EncodedString:encoded options:0]mutableCopy]:nil;if(packet.length<14||packet.length>1518){valid=NO;break;}uint8_t *p=packet.mutableBytes;
      if(!guestMACSet){unsigned nonzero=0;for(unsigned i=0;i<6;i++)nonzero|=p[6+i];if(!nonzero||(p[6]&1)){valid=NO;break;}memcpy(guestMAC,p+6,6);guestMACSet=YES;}
      if(!vm27_wifi_host_frame_allowed_v1(p,packet.length,hostAddresses,hostCount,hostSnapshot)){
       dropped++;unsigned long long rejected=[Report[@"hostIsolationRejectedTXFrames"]unsignedLongLongValue]+1;
       Report[@"hostIsolationRejectedTXFrames"]=@(rejected);
       if(rejected<=8)fprintf(stderr,"[OwnedWiFi] host-isolation rejected guest TX frame count=%llu\n",rejected);
       continue;
      }
      if(memcmp(p+6,guestMAC,6)||vm27_wifi_mac_translate_v1(p,packet.length,guestMAC,OwnedMAC)<0){dropped++;continue;}
      NSString *kind=brokerPacketKind(p,packet.length);txKinds[kind]=@([txKinds[kind]unsignedIntValue]+1);
      if(write(bpf,p,packet.length)==(ssize_t)packet.length)tx++;else dropped++;
     }
     if(valid&&guestMACSet)for(unsigned batch=0;batch<8&&received.count<24;batch++){
      ssize_t n=read(bpf,buffer.mutableBytes,buffer.length);if(n<=0)break;uint8_t *bytes=buffer.mutableBytes;size_t pos=0;
      while(pos+sizeof(struct VM27BPFHeader)<=(size_t)n&&received.count<24){struct VM27BPFHeader h;memcpy(&h,bytes+pos,sizeof(h));if(h.header<18||h.header>(size_t)n-pos||h.captured>(size_t)n-pos-h.header){dropped++;break;}
       uint8_t *p=bytes+pos+h.header;if(h.captured>=14&&h.captured<=1518&&vm27_wifi_host_frame_allowed_v1(p,h.captured,hostAddresses,hostCount,hostSnapshot)&&vm27_wifi_mac_translate_v1(p,h.captured,OwnedMAC,guestMAC)>=0){NSString *kind=brokerPacketKind(p,h.captured);rxKinds[kind]=@([rxKinds[kind]unsignedIntValue]+1);[received addObject:[[NSData dataWithBytes:p length:h.captured]base64EncodedStringWithOptions:0]];rx++;}else dropped++;
       size_t step=(h.header+h.captured+3)&~(size_t)3;if(step>(size_t)n-pos)break;pos+=step;
      }
     }
     reply=@{@"ok":@(valid),@"frames":received,@"sent":@(tx),@"dropped":@(dropped)};
    }
   }
   NSData *output=[NSJSONSerialization dataWithJSONObject:reply options:0 error:NULL];struct vm27_radio_frame_v1 response={frame.type==VM27_RADIO_HELLO?VM27_RADIO_HELLO_REPLY:VM27_RADIO_REPLY,(uint32_t)output.length,frame.request_id,generation};
   if(!output||vm27_radio_header_encode_v1(header,&response)||brokerTransfer(peer,header,32,YES)||brokerTransfer(peer,(void *)output.bytes,output.length,YES)){close(peer);peer=-1;attached=NO;}
   else if(!authenticated){close(peer);peer=-1;}
  }}
  [buffer resetBytesInRange:NSMakeRange(0,buffer.length)];
 }
done:
 if(!owned)unlink(metadata);
 if(peer>=0)close(peer);if(listener>=0)close(listener);(void)brokerReleaseDataPlane(&bpf);wipe(guestMAC,sizeof(guestMAC));
 if(flagsChanged){interface.ifr_flags=originalFlags;Report[@"brokerBSDFlagsRestored"]=@(!ioctl(control,SIOCSIFFLAGS,&interface));}if(control>=0)close(control);
 Report[@"brokerFramesTransmitted"]=@(tx);Report[@"brokerFramesReceived"]=@(rx);Report[@"brokerFramesDropped"]=@(dropped);Report[@"brokerTXPacketKinds"]=txKinds;Report[@"brokerRXPacketKinds"]=rxKinds;return tx&&rx;
}
