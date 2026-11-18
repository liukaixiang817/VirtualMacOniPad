// Native JoinManager::setAssocWsecInfo(type=0x10c, TD policy=0).
// Actual 20B101 machine-code oracle: native-prune-reason39-audit-v1.
// A new guest-requested WPA2 profile must not inherit another network's
// Transition Disable policy. No primary interface or global policy is set.
static BOOL OwnedNativeTDPolicyRefused;
static int configureOwnedNativeTDPolicy(void) {
 if(OwnedNativeTDPolicyRefused||Stop)return EPERM;
 if(!OwnedStationRoleActive||!MACRecorded||OwnedLeaseLock<0||!Auxiliary)return EPERM;
 uint8_t identity[6]={0};
 int status=iovar(NO,"cur_etheraddr",1,NULL,0,identity,sizeof(identity));
 BOOL owned=!status&&!memcmp(identity,OwnedMAC,sizeof(identity));
 memset(identity,0,sizeof(identity));
 Report[@"nativeTDPolicyIdentityVerified"]=@(owned);
 if(!owned)return EPERM;
 uint8_t packet[12]={1,0,0,1};
 uint16_t type=0x10c,length=4;uint32_t mode=0;
 memcpy(packet+4,&type,2);memcpy(packet+6,&length,2);memcpy(packet+8,&mode,4);
 status=iovar(YES,"wsec_info",1,packet,sizeof(packet),NULL,0);
 memset(packet,0,sizeof(packet));
 Report[@"nativeTDPolicySetStatus"]=@(status);
 Report[@"nativeTDPolicyValue"]=@(mode);
 Report[@"nativeTDPolicySetCalls"]=@([Report[@"nativeTDPolicySetCalls"]unsignedIntValue]+1);
 if(status)OwnedNativeTDPolicyRefused=YES;
 return status;
}
