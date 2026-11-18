// 20B101 auxiliary interface bootstrap experiment. Uses the native network
// converter to create a hidden WPA2 network with a fresh random password,
// without DHCP, routing or forwarding. Verifies ap1's firmware endpoint, then
// stops this temporary network and verifies the original inactive AP state.
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <float.h>
#include "../../shared-radio/independent/VM27OwnedWiFiAdmissionV1.h"
#include "../../shared-radio/common/vm27_wifi_native_chanspec_v1.h"
#include "../../shared-radio/common/vm27_wifi_native_sta_leave_v1.h"
#include "../../shared-radio/common/vm27_wifi_native_reader_renewal_v1.h"
#if defined(VM27_WIFI_SINGLE_NATIVE_STA_LEAVE) && (defined(VM27_WIFI_NATIVE_STA_LEAVE) || defined(VM27_WIFI_ABORT_STA_JOIN_BEFORE_REMOVE))
#error Native single STA retirement excludes APSTA peer removal and unconditional post-leave abort
#endif
#if defined(VM27_WIFI_SINGLE_NATIVE_STA_DEAUTH) && !defined(VM27_WIFI_SINGLE_NATIVE_STA_LEAVE)
#error Native peer deauthentication requires the validated single-retirement planner
#endif
#if defined(VM27_WIFI_RETAIN_QUIESCED_STA) && ((!defined(VM27_WIFI_CLEAR_STA_SECURITY_AFTER_LEAVE) && !defined(VM27_WIFI_PERSIST_STA_AUTH)) || (!defined(VM27_WIFI_STA_BSS_DOWN_BEFORE_REMOVE) && !defined(VM27_WIFI_RETAIN_QUIESCED_STA_UP)))
#error Retained station experiments require security shutdown and an explicit BSS lifetime profile
#endif
#if defined(VM27_WIFI_PERSIST_STA_AUTH) && (!defined(VM27_WIFI_RETAIN_QUIESCED_STA_UP) || !defined(VM27_WIFI_SINGLE_NATIVE_STA_LEAVE) || defined(VM27_WIFI_CLEAR_STA_SECURITY_AFTER_LEAVE) || defined(VM27_WIFI_STA_BSS_DOWN_BEFORE_REMOVE))
#error A persistent supplicant requires one native STA leave and an allocated enabled BSS, without security clearing
#endif
#if defined(VM27_WIFI_RETAIN_NATIVE_BSD_UP) && !defined(VM27_WIFI_RETAIN_QUIESCED_STA)
#error Native BSD lifetime preservation requires the retained owned station
#endif
#if defined(VM27_WIFI_RETAIN_QUIESCED_STA_UP) && (!defined(VM27_WIFI_RETAIN_NATIVE_BSD_UP) || (!defined(VM27_WIFI_RESUME_BEFORE_JOIN_CONFIGURATION) && !defined(VM27_WIFI_OWNED_BSS_STAGE_LIFECYCLE)) || defined(VM27_WIFI_STA_BSS_DOWN_BEFORE_REMOVE))
#error The unassociated enabled STA profile requires retained BSD and authentication after resume, without BSS-down
#endif
struct RawRequest {char name[16];uint32_t type,value,length,reserved;void *data;};
_Static_assert(sizeof(struct RawRequest)==40,"native raw request");
typedef int (*RawCall)(void *,struct RawRequest *);
static void *Primary,*Auxiliary;static RawCall Get,Set;
static int (*SetObject)(void *,int,int,CFTypeRef,int);
static CFTypeRef WiFiManager,AuxiliaryDevice,PrimaryDevice;
static int (*StateInfo)(CFTypeRef,CFDictionaryRef *);
static CFTypeRef (*CurrentNetwork)(CFTypeRef);
static CFTypeRef (*NetworkProperty)(CFTypeRef,CFStringRef);
static uint8_t OwnedMAC[6];static BOOL MACRecorded;
static BOOL NativeBootstrapSucceeded;
static BOOL OwnedStationRoleActive;
static BOOL ReusingQuiescedStation;
static BOOL OwnedJoinStateKnown,OwnedJoinPending;
static int OwnedStationSessionFD=-1;
static NSData *OwnedSSID;static BOOL Sent,Stopped;static NSMutableDictionary *Report;
static NSData *PrimarySSIDBefore;
static NSData *TargetSSID;
static NSMutableData *TargetPassword;
static NSMutableData *TargetPMK;
static BOOL ManagedStationBroker,ManagedStationAssociated;
static BOOL PhysicalNativeInitialized,PhysicalPrepared;
static uint8_t ManagedActivePMKDigest[32];static BOOL ManagedActivePMKDigestValid;
static BOOL ManagedDevelopmentBSSRestriction;
static NSData *ManagedAllowedSSID,*ManagedAllowedBSSID;
static int OwnedLeaseLock=-1;
static BOOL PreserveNativeDataMAC;
static uint32_t PrimaryChannel,TargetChannel;
#ifdef VM27_WIFI_USE_ACTUAL_SCAN_CHANSPEC
static uint16_t TargetNativeChanspec;
static unsigned TargetNativeBandwidth;
#endif
static uint32_t FirmwareInterfaceVersion;
static uint8_t TargetBSSID[6];
static BOOL selectStationCandidate(void);
static BOOL prepareOwnedStation(void);
static BOOL InPlaceStationConversion;
static const char *Receipt="/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1/identity.json";
static volatile sig_atomic_t Stop;
#include "wifi-bpf-dhcp-probe-v1.inc"
static void wipe(void *bytes,size_t length){volatile uint8_t *p=bytes;while(length--)*p++=0;}
static void eraseStationPMKOnReturn(uint8_t (*bytes)[0x108]){wipe(*bytes,0x108);}
static BOOL absentEndpoint(int result){return result==-19||result==(int)0xe3ff8101;}
static void recordPrimaryAssociation(void);
static int finish(int status){
 recordPrimaryAssociation();
 Report[@"processStatus"]=@(status);Report[@"bootstrapSent"]=@(Sent);
 NSData *output=[NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingSortedKeys error:NULL];
 if(!output)return 65;fwrite(output.bytes,1,output.length,stdout);fputc('\n',stdout);fflush(stdout);return status;
}
static void stopSignal(int value){(void)value;Stop=1;}
static int request(void *handle,const char *name,BOOL write,uint32_t type,uint32_t value,void *bytes,uint32_t length){
 struct RawRequest r={.type=type,.value=value,.length=length,.data=bytes};strlcpy(r.name,name,sizeof(r.name));return (write?Set:Get)(handle,&r);
}
static void recordPrimaryAssociation(void){
 if(!PrimarySSIDBefore||!Primary)return;
 uint8_t b[36]={0};int status=request(Primary,"en0",NO,UINT32_MAX,25,b,sizeof(b));uint32_t length=0;memcpy(&length,b,4);
 Report[@"primarySSIDReadStatusAfter"]=@(status);
 Report[@"primaryAssociationPreserved"]=@(!status&&length>0&&length<=32&&[PrimarySSIDBefore isEqual:[NSData dataWithBytes:b+4 length:length]]);
 memset(b,0,sizeof(b));
}
// Native interface index and firmware BSS configuration index are different
// namespaces. Route through the bound native endpoint; never synthesize bsscfg
// prefixes from a native interface index.
static int iovar(BOOL write,const char *key,int interfaceIndex,const void *input,size_t count,void *output,size_t capacity){
 if(interfaceIndex < -1 || interfaceIndex>1)return EINVAL;
 if(!strncmp(key,"bsscfg:",7))key+=7;
 uint8_t b[512]={0};size_t prefix=strlen(key)+1;if(prefix+count>sizeof(b))return EINVAL;
 memcpy(b,key,prefix);if(count)memcpy(b+prefix,input,count);
 void *handle=interfaceIndex==1?Auxiliary:Primary;const char *name=interfaceIndex==1?"ap1":"en0";
 int status=request(handle,name,write,UINT32_MAX,write?263:262,b,write?(uint32_t)(prefix+count):sizeof(b));
 if(!status&&output)memcpy(output,b,MIN(capacity,sizeof(b)));memset(b,0,sizeof(b));return status;
}
#include "wifi-interface-event-filter-v1.inc"
#include "wifi-auxiliary-power-lease-v1.inc"

static BOOL releaseRetainedStationBSDLease(void){
#ifdef VM27_WIFI_RETAIN_NATIVE_BSD_UP
 // The physical STA outlives one VM. Restoring IFF_DOWN between leases makes
 // the native APSTA owner perform a separate interface shutdown/startup on
 // the already-converted STA. Keep only this owned BSD endpoint up; the
 // caller has already verified no peer, disabled the supplicant and erased
 // its authentication state. Preserve the original flags in the receipt.
 struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));
 int fd=LeaseBSDControl>=0?LeaseBSDControl:socket(AF_INET,SOCK_DGRAM,0);
 BOOL up=fd>=0&&!ioctl(fd,SIOCGIFFLAGS,&interface)&&(interface.ifr_flags&IFF_UP);
 if(fd>=0)close(fd);LeaseBSDControl=-1;
 if(up)LeaseBSDChanged=NO;
 Report[@"retainedOwnedNativeBSDInterfaceStaysUp"]=@(up);
 return up;
#else
 return releaseAuxiliaryBSDDataLease()&&recoverAuxiliaryBSDDataLease(readFilterReceipt());
#endif
}

static int readVerifiedOwnedBssIndex(int32_t *index){
 if(!index||!MACRecorded)return EPERM;
 *index=-1;
 uint8_t current[6]={0};int identity=iovar(NO,"cur_etheraddr",1,NULL,0,current,6);
 BOOL owned=!identity&&!memcmp(current,OwnedMAC,6);memset(current,0,sizeof(current));
 Report[@"ownedBssBoundIdentityReadStatus"]=@(identity);
 Report[@"ownedBssBoundIdentityMatched"]=@(owned);
 if(!owned)return identity?:EPERM;
 int32_t actual=-1;int status=iovar(NO,"bsscfg_idx",1,NULL,0,&actual,4);
 Report[@"ownedBssFirmwareIndexReadStatus"]=@(status);
 if(status||actual<=0||actual>255)return status?:EPERM;
 // Native interfaceID1 and firmware BSS index are different namespaces.
 // Read only the exact index just returned by the owned endpoint, then
 // require its MAC to match the root receipt. Never probe guessed slots.
 uint8_t query[128]={0};const char key[]="bsscfg:cur_etheraddr";
 memcpy(query,key,sizeof(key));memcpy(query+sizeof(key),&actual,4);
 int indexed=request(Primary,"en0",NO,UINT32_MAX,262,query,sizeof(query));
 BOOL matched=!indexed&&!memcmp(query,OwnedMAC,6);memset(query,0,sizeof(query));
 Report[@"ownedBssExactReturnedIndexIdentityStatus"]=@(indexed);
 Report[@"ownedBssExactReturnedIndexIdentityMatched"]=@(matched);
 if(!matched)return indexed?:EPERM;
 *index=actual;Report[@"ownedBssVerifiedFirmwareIndex"]=@(actual);return 0;
}
static int setVerifiedOwnedBssEnabled(uint32_t enabled){
 if(enabled>1)return EPERM;
 int32_t index=-1;int verified=readVerifiedOwnedBssIndex(&index);
 if(verified)return verified;
#ifdef VM27_WIFI_REPRODUCE_BROKER15_LIFECYCLE
 // Reproduce the previously measured broker15 native APSTA operation ABI.
 // The verified firmware index is diagnostic identity; this API's bound
 // selector remains -1, as in that immutable successful binary.
 index=-1;
 Report[@"ownedBssUsesMeasuredBroker15BoundSelector"]=@YES;
#endif
 int32_t operation[2]={index,(int32_t)enabled};
 Report[@"ownedBssOperationUsesExactVerifiedFirmwareIndex"]=@(index>0);
 int status=iovar(YES,"bss",1,operation,sizeof(operation),NULL,0);
 Report[enabled?@"explicitOwnedBssResumeStatus":@"explicitOwnedBssDownStatus"]=@(status);
 return status;
}
static int readVerifiedOwnedBssEnabled(uint32_t *enabled){
 if(!enabled)return EPERM;
 int32_t bound=-1;int verified=readVerifiedOwnedBssIndex(&bound);
 if(verified)return verified;
#ifdef VM27_WIFI_REPRODUCE_BROKER15_LIFECYCLE
 bound=-1;
#endif
 *enabled=UINT32_MAX;
 return iovar(NO,"bss",1,&bound,sizeof(bound),enabled,sizeof(*enabled));
}
#include "native-default-key-preparation.inc"
#include "owned-pending-join-recovery.inc"
static BOOL OwnedNativeJoinPreparationRefused;
static BOOL prepareCompleteOwnedNativeJoin(void){
 if(OwnedNativeJoinPreparationRefused||Stop)return NO;
 // Exact native order: clearWepKeysSync at22de40, then SET_INFRA20 at
 // 22de90..22deac, then WPA2 parameters and optional MFP before SETSSID.
 // The native key helper requires the identity-verified auxiliary STA
 // to be unassociated; a live verified peer left and drained above.
 if(!clearOwnedStationDefaultKeys()){
  if(!Stop)OwnedNativeJoinPreparationRefused=YES;
  return NO;
 }
 uint32_t infrastructure=1,actual=0;
 int status=request(Auxiliary,"ap1",YES,UINT32_MAX,20,&infrastructure,4);
 Report[@"nativeJoinInfrastructureSetStatus"]=@(status);
 if(status){OwnedNativeJoinPreparationRefused=YES;return NO;}
 int read=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&actual,4);
 Report[@"nativeJoinInfrastructureReadStatus"]=@(read);
 Report[@"nativeJoinInfrastructureReadValue"]=@(actual);
 if(read||actual!=1){OwnedNativeJoinPreparationRefused=YES;return NO;}
 return YES;
}
// Native JoinManager parses this exact RSN IE's capabilities as optional
// MFP=1, then configures the four-byte "mfp" value before SET_SSID.
// See native-rsn-mfp-emulation-v1 (actual native instruction execution).
// This uses only the already identity-verified owned auxiliary endpoint.
// A failed setter is terminal for this actor: never repeat unsupported writes.
static BOOL OwnedNativeMFPSetRefused;
static int configureOwnedNativeMFP(void){
 if(OwnedNativeMFPSetRefused)return EPERM;
 uint32_t optional=1;
 int status=iovar(YES,"mfp",1,&optional,sizeof(optional),NULL,0);
 Report[@"stationNativeMFPValue"]=@(optional);
 Report[@"stationSetNativeMFPStatus"]=@(status);
 if(status)OwnedNativeMFPSetRefused=YES;
 return status;
}
#include "native-td-policy.inc"
// All key, authentication and join commands use the identity-verified ap1
// handle. No primary-interface association or route modification is performed.
static BOOL associateStation(void){
 Report[@"secondStationAuthorized"]=@NO;Report[@"secondStationSSIDAndBSSIDVerified"]=@NO;
 Report[@"associationSamples"]=@[];
 if(OwnedNativeTDPolicyRefused)return NO;
 if(OwnedNativeJoinPreparationRefused){Report[@"nativeJoinPreparationFailureRefusedBeforeWrites"]=@YES;return NO;}
 if(OwnedNativeMFPSetRefused){Report[@"stationNativeMFPFailureRefusedBeforeWrites"]=@YES;return NO;}
 uint8_t identity[6]={0};int result=iovar(NO,"cur_etheraddr",1,NULL,0,identity,sizeof(identity));
 if(result||!MACRecorded||memcmp(identity,OwnedMAC,6))return NO;
 memset(identity,0,sizeof(identity));
#ifdef VM27_WIFI_SINGLE_NATIVE_STA_DEAUTH
 uint8_t nativePower[28]={0};uint32_t powerVersion=1;memcpy(nativePower,&powerVersion,4);
 int powerStatus=request(Primary,"en0",NO,347,1,nativePower,sizeof(nativePower));
 Report[@"stationNativeAuxiliaryPowerReadStatus"]=@(powerStatus);
 if(!powerStatus){Report[@"stationNativeAuxiliaryPowerState"]=@(nativePower[22]);Report[@"stationNativeAuxiliaryPowerSaveEnabled"]=@(nativePower[23]);}
 memset(nativePower,0,sizeof(nativePower));
#endif
#ifdef VM27_WIFI_RESUME_BEFORE_JOIN_CONFIGURATION
 if(ReusingQuiescedStation){
  // Resume the native BSS before giving its new supplicant any key or join
  // configuration. A SET_SSID while down followed by another after up can
  // race the firmware's channel transition with two concurrent join starts.
  BOOL needsResume=YES;
#ifdef VM27_WIFI_RETAIN_QUIESCED_STA_UP
  uint32_t bss=UINT32_MAX;int bssRead=readVerifiedOwnedBssEnabled(&bss);
  Report[@"retainedStationEnabledReadStatus"]=@(bssRead);
  Report[@"retainedStationEnabledBeforeJoin"]=@(bss);
  if(bssRead||bss>1)return NO;
  needsResume=bss==0;
#ifdef VM27_WIFI_STA_JOIN_MANAGES_BSS
  // The infrastructure leave path can disable its BSS configuration. Its
  // next normal SET_SSID owns activation, as on the original STA route.
  // An AP-style BSS-up here starts the cached old SSID before replacement.
  needsResume=NO;
  Report[@"nativeStationJoinManagesBSSState"]=@YES;
#endif
#endif
  int resumed=needsResume?setVerifiedOwnedBssEnabled(1):0;
  Report[@"retainedStationBSSResumeStatus"]=@(resumed);
  Report[@"retainedStationResumedBeforeNewAuthentication"]=@(needsResume);
  if(resumed)return NO;
  uint8_t actual[6]={0};int identityAfter=iovar(NO,"cur_etheraddr",1,NULL,0,actual,6);
  BOOL owned=!identityAfter&&!memcmp(actual,OwnedMAC,6);memset(actual,0,sizeof(actual));
  Report[@"retainedStationResumeIdentityVerified"]=@(owned);if(!owned)return NO;
  // BSS-up may resume the old cached join. Abort that identity-verified STA
  // state machine before setting the new network's authentication material.
  uint8_t abortJoin[12]={0};uint32_t reason=3;memcpy(abortJoin,&reason,4);
  int aborted=needsResume?request(Auxiliary,"ap1",YES,UINT32_MAX,52,abortJoin,sizeof(abortJoin)):0;
  memset(abortJoin,0,sizeof(abortJoin));
  Report[@"retainedStationJoinAbortAfterResumeStatus"]=@(aborted);if(aborted)return NO;
  BOOL idle=NO;
  for(unsigned attempt=0;attempt<20&&!Stop;attempt++){
   uint8_t peer[6]={0};int read=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,6);
   unsigned bits=0;for(unsigned j=0;j<6;j++)bits|=peer[j];memset(peer,0,sizeof(peer));
   if(read==(int)0xe3ff8111||(!read&&!bits)){idle=YES;break;}usleep(100000);
  }
  Report[@"retainedStationUnassociatedAfterResumeVerified"]=@(idle);if(!idle)return NO;
 }
#endif
 if(ReusingQuiescedStation){
  // Restore the already-owned retained STA as one complete native BSS
  // lifecycle. Stage its new target while disabled, enable, restore its
  // PMK and issue the normal post-enable join below. Never delete it.
  int disabled=setVerifiedOwnedBssEnabled(0);
  Report[@"ownedRetargetBSSDisabledBeforeTargetStatus"]=@(disabled);if(disabled)return NO;
 }
 if(!prepareCompleteOwnedNativeJoin())return NO;
 uint32_t actualRole=UINT32_MAX,actualInfrastructure=UINT32_MAX;
 Report[@"stationRoleBeforeJoinReadStatus"]=@(request(Auxiliary,"ap1",NO,UINT32_MAX,117,&actualRole,4));
 Report[@"stationRoleBeforeJoinValue"]=@(actualRole);
 Report[@"stationInfraBeforeJoinReadStatus"]=@(request(Auxiliary,"ap1",NO,UINT32_MAX,19,&actualInfrastructure,4));
 Report[@"stationInfraBeforeJoinValue"]=@(actualInfrastructure);
 uint32_t zero=0,wsec=4,wpaAuth=128,enabled=1;
 // The bounded broker authorizes one physical BSS; leave roaming decisions
 // to its guest instead of the auxiliary firmware silently changing BSS.
 uint32_t originalRoam=0,actualRoam=0;
 result=iovar(NO,"roam_off",1,NULL,0,&originalRoam,4);Report[@"ownedStationRoamingReadStatus"]=@(result);if(result)return NO;
 result=iovar(YES,"roam_off",1,&enabled,4,NULL,0);Report[@"ownedStationDisableFirmwareRoamingStatus"]=@(result);if(result)return NO;
 result=iovar(NO,"roam_off",1,NULL,0,&actualRoam,4);Report[@"ownedStationFirmwareRoamingDisabledVerified"]=@(!result&&actualRoam==1);if(result||actualRoam!=1)return NO;
 Report[@"ownedStationOriginalRoamingDisabled"]=@(originalRoam);
 uint32_t currentPM=UINT32_MAX;int pmRead=request(Auxiliary,"ap1",NO,UINT32_MAX,85,&currentPM,4);Report[@"ownedStationFirmwarePMReadStatus"]=@(pmRead);if(!pmRead)Report[@"ownedStationFirmwarePM"]=@(currentPM);
 result=request(Auxiliary,"ap1",YES,UINT32_MAX,22,&zero,4);Report[@"stationSetOpenAuthenticationStatus"]=@(result);if(result)return NO;
 result=iovar(YES,"wsec",1,&wsec,4,NULL,0);Report[@"stationSetWsecStatus"]=@(result);if(result)return NO;
 result=iovar(YES,"wpa_auth",1,&wpaAuth,4,NULL,0);Report[@"stationSetWPA2PSKStatus"]=@(result);if(result)return NO;
 result=iovar(YES,"sup_wpa",1,&enabled,4,NULL,0);Report[@"stationEnableFirmwareSupplicantStatus"]=@(result);if(result)return NO;
 const uint8_t rsn[]={0x30,0x14,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,4,1,0,0,0x0f,0xac,2,0,0};
 result=iovar(YES,"wpaie",1,rsn,sizeof(rsn),NULL,0);Report[@"stationSetRSNIEStatus"]=@(result);if(result)return NO;
 uint8_t pmk[0x108] __attribute__((cleanup(eraseStationPMKOnReturn)))={0};uint16_t keyLength=32;memcpy(pmk,&keyLength,2);
 if(TargetPMK.length==32){Report[@"stationPMKFromNativeGuest"]=@YES;memcpy(pmk+4,TargetPMK.bytes,32);result=0;[TargetPMK resetBytesInRange:NSMakeRange(0,TargetPMK.length)];TargetPMK=nil;}
 else result=CCKeyDerivationPBKDF(kCCPBKDF2,TargetPassword.bytes,TargetPassword.length,TargetSSID.bytes,TargetSSID.length,kCCPRFHmacAlgSHA1,4096,pmk+4,32);
 [TargetPassword resetBytesInRange:NSMakeRange(0,TargetPassword.length)];TargetPassword=nil;
 Report[@"stationPMKDerivationStatus"]=@(result);if(result){wipe(pmk,sizeof(pmk));return NO;}
 result=request(Auxiliary,"ap1",YES,UINT32_MAX,268,pmk,sizeof(pmk));Report[@"stationSetPMKStatus"]=@(result);if(result)return NO;
 result=configureOwnedNativeMFP();if(result)return NO;
 result=configureOwnedNativeTDPolicy();if(result)return NO;
 // Exact JoinManager::join layout in this device's driver, 0x22eef4..
 // 0x22f0e8 and 0x22fc14: the newer interface adds four bytes after SSID.
 // bssid_count=1 implies one chanspec and one trailing BSSID; the ordinary
 // chanspec_num stays zero. A Linux-style 52-byte layout is too short here.
 uint8_t join[60]={0};uint32_t length=(uint32_t)TargetSSID.length;memcpy(join,&length,4);memcpy(join+4,TargetSSID.bytes,TargetSSID.length);
 size_t extra=FirmwareInterfaceVersion>16?4:0;uint16_t count=1,chanspec=(uint16_t)(0x1000|(TargetChannel>14?0xc000:0)|TargetChannel);
#ifdef VM27_WIFI_USE_ACTUAL_SCAN_CHANSPEC
 if(!TargetNativeChanspec){memset(join,0,sizeof(join));return NO;}
 chanspec=TargetNativeChanspec;
 Report[@"nativeJoinTargetChanspec"]=@(chanspec);
 Report[@"nativeJoinTargetBandwidthMHz"]=@(TargetNativeBandwidth);
#endif
 // Exact 20B101 JoinManager, driver SHA pinned in the native emulation.
 // v17 chanspec adds 0x4 at 0x22f214. WPA2-PSK Apple upper-auth 0x20
 // maps to firmware wpa_auth 0x80, and the LOWER auth branch at
 // 0x22fe44..fe60 tests bit 32 in mask 0x100000012 before OR'ing 0x2
 // at 0x22ff04. The complete native WPA2-PSK flags are therefore 0x6.
 // Checking only the later upper-auth 0x80/0x800 cases misses this path.
 // Version16 has no new four-byte flags field and retains zero here.
 uint16_t joinFlags=(uint16_t)(extra?6:0);
 memcpy(join+38,&joinFlags,2);memcpy(join+42+extra,&count,2);memcpy(join+48+extra,&chanspec,2);memcpy(join+50+extra,TargetBSSID,6);
 Report[@"nativeJoinV17Flags"]=@(joinFlags);
 resetOwnedPendingJoinRecovery();
 OwnedJoinStateKnown=YES;OwnedJoinPending=YES;
 Report[@"networkAssociationCalls"]=@([Report[@"networkAssociationCalls"]unsignedIntValue]+1);Report[@"nativeJoinPayloadLength"]=@(56+extra);result=request(Auxiliary,"ap1",YES,UINT32_MAX,26,join,(uint32_t)(56+extra));Report[@"stationSetSSIDStatus"]=@(result);if(result){memset(join,0,sizeof(join));return NO;}
#ifndef VM27_WIFI_RESUME_BEFORE_JOIN_CONFIGURATION
 if(ReusingQuiescedStation){
  // Replace the preceding lease's join configuration while its BSS is down.
  // Resuming first can start that old network with the new network's keys.
  int resumed=setVerifiedOwnedBssEnabled(1);
  Report[@"retainedStationJoinConfiguredBeforeBSSResume"]=@YES;
  Report[@"retainedStationBSSResumeStatus"]=@(resumed);if(resumed){memset(join,0,sizeof(join));return NO;}
  // SET_SSID while down stages the target but does not reliably start this
  // firmware's STA join state machine after a host-network change. Submit
  // the same guest-requested join once the verified auxiliary BSS is up.
  // This never creates a second user request or touches the primary BSS.
  usleep(200000);
  uint8_t identityAfterResume[6]={0};
  int identityStatus=iovar(NO,"cur_etheraddr",1,NULL,0,identityAfterResume,6);
  BOOL stillOwned=!identityStatus&&!memcmp(identityAfterResume,OwnedMAC,6);
  memset(identityAfterResume,0,sizeof(identityAfterResume));
  Report[@"retainedStationResumeIdentityVerified"]=@(stillOwned);
  if(!stillOwned){memset(join,0,sizeof(join));return NO;}
  // BSS-up may initialize a new supplicant context. Restore this guest's
  // complete authentication configuration after up, before starting its join.
  // The stack PMK is erased on every return, including all error paths.
  int security=request(Auxiliary,"ap1",YES,UINT32_MAX,22,&zero,4);
  if(!security)security=iovar(YES,"wsec",1,&wsec,4,NULL,0);
  if(!security)security=iovar(YES,"wpa_auth",1,&wpaAuth,4,NULL,0);
  if(!security)security=iovar(YES,"sup_wpa",1,&enabled,4,NULL,0);
  if(!security)security=iovar(YES,"wpaie",1,rsn,sizeof(rsn),NULL,0);
  if(!security)security=request(Auxiliary,"ap1",YES,UINT32_MAX,268,pmk,sizeof(pmk));
  if(!security)security=configureOwnedNativeMFP();
  if(!security)security=configureOwnedNativeTDPolicy();
  Report[@"retainedStationSecurityRestoredAfterBSSResumeStatus"]=@(security);
  if(security){memset(join,0,sizeof(join));return NO;}
  int started=request(Auxiliary,"ap1",YES,UINT32_MAX,26,join,(uint32_t)(56+extra));
  Report[@"retainedStationJoinStartedAfterBSSResumeStatus"]=@(started);
  if(started){memset(join,0,sizeof(join));return NO;}
  uint32_t actualBSS=UINT32_MAX,actualAuth=UINT32_MAX,actualEncryption=UINT32_MAX;
  Report[@"retainedStationBSSReadStatus"]=@(readVerifiedOwnedBssEnabled(&actualBSS));
  Report[@"retainedStationBSSReadValue"]=@(actualBSS);
  Report[@"retainedStationAuthReadStatus"]=@(iovar(NO,"wpa_auth",1,NULL,0,&actualAuth,4));
  Report[@"retainedStationAuthReadValue"]=@(actualAuth);
  Report[@"retainedStationEncryptionReadStatus"]=@(iovar(NO,"wsec",1,NULL,0,&actualEncryption,4));
  Report[@"retainedStationEncryptionReadValue"]=@(actualEncryption);
  actualRole=UINT32_MAX;actualInfrastructure=UINT32_MAX;
  Report[@"stationRoleAfterResumeReadStatus"]=@(request(Auxiliary,"ap1",NO,UINT32_MAX,117,&actualRole,4));
  Report[@"stationRoleAfterResumeValue"]=@(actualRole);
  Report[@"stationInfraAfterResumeReadStatus"]=@(request(Auxiliary,"ap1",NO,UINT32_MAX,19,&actualInfrastructure,4));
  Report[@"stationInfraAfterResumeValue"]=@(actualInfrastructure);
 }
#else
 if(ReusingQuiescedStation)Report[@"retainedStationJoinStartedAfterBSSResumeStatus"]=@(result);
#endif
 memset(join,0,sizeof(join));
 BOOL associated=NO;NSMutableArray *samples=[NSMutableArray array];
 // The guest RPC allows 30 seconds and its host forwarder allows 27.
 // Keep this wait at 20 seconds, leaving room for the existing owned-peer
 // drain and configuration. Twelve seconds can abort a still-pending join.
 Report[@"authorizationMaximumWaitMilliseconds"]=@20000;
 for(unsigned i=0;i<40&&!Stop;i++){
  usleep(500000);uint8_t bssid[6]={0},ssidBytes[36]={0};uint32_t count=0;
  int bs=request(Auxiliary,"ap1",NO,UINT32_MAX,23,bssid,sizeof(bssid));int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,ssidBytes,sizeof(ssidBytes));memcpy(&count,ssidBytes,4);
  BOOL addressPresent=NO;for(unsigned j=0;j<6;j++)addressPresent|=bssid[j]!=0;
  BOOL ssidMatches=!ss&&count==TargetSSID.length&&count<=32&&!memcmp(ssidBytes+4,TargetSSID.bytes,count);
  // Never query sup_auth_status here. On 20B101 an idle or not-yet-ready
  // firmware supplicant returns BCOM Not Ready, which Commander escalates
  // to a chip watchdog instead of an ordinary polling error. Authorization
  // comes from the requested, actually-associated peer's sta_info below.
  BOOL requestedPeer=!bs&&addressPresent&&ssidMatches&&!memcmp(bssid,TargetBSSID,6);
  uint8_t info[512]={0};int infoStatus=!requestedPeer?ENOTCONN:iovar(NO,"sta_info",1,bssid,sizeof(bssid),info,sizeof(info));uint16_t version=0,infoLength=0;uint32_t flags=0;
  if(!infoStatus){memcpy(&version,info,2);memcpy(&infoLength,info+2,2);memcpy(&flags,info+8,4);}
  // Firmware association and WPA authorization are separate observations.
  BOOL authorized=!infoStatus&&version>=3&&infoLength>=16&&(flags&0x30)==0x30;
  associated=requestedPeer;
  [samples addObject:@{@"bssidReadStatus":@(bs),@"bssidPresent":@(addressPresent),@"ssidReadStatus":@(ss),@"targetSSIDMatches":@(ssidMatches),@"supplicantStatusQueryIssued":@NO,@"stationInfoReadStatus":@(infoStatus),@"stationInfoVersion":@(version),@"stationInfoLength":@(infoLength),@"stationFlags":@(flags),@"authorized":@(authorized)}];
  memset(bssid,0,sizeof(bssid));memset(ssidBytes,0,sizeof(ssidBytes));memset(info,0,sizeof(info));
   if(associated&&authorized){Report[@"secondStationAuthorized"]=@YES;break;}
 }
 Report[@"associationSamples"]=samples;Report[@"secondStationSSIDAndBSSIDVerified"]=@(associated);recordPrimaryAssociation();
 if(associated&&[Report[@"secondStationAuthorized"]boolValue])OwnedJoinPending=NO;
 else if(!Stop&&ManagedStationBroker&&OwnedJoinPending)
  (void)beginOwnedTimedOutJoinRecovery(NSProcessInfo.processInfo.systemUptime);
 return associated&&[Report[@"secondStationAuthorized"]boolValue]&&[Report[@"primaryAssociationPreserved"]boolValue];
}
static BOOL recordOwnedStationRole(void){
 OwnedStationRoleActive=YES;NSMutableDictionary *record=[readFilterReceipt()mutableCopy];
 if(!record)return NO;record[@"ownedStationRoleActive"]=@YES;
 NSData *data=[NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
 int fd=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC);
 BOOL saved=fd>=0&&write(fd,data.bytes,data.length)==(ssize_t)data.length&&!fsync(fd);
 if(fd>=0)close(fd);return saved;
}
static BOOL convertStation(void){
 uint8_t mac[6]={0},primary[6]={0};int ms=iovar(NO,"bsscfg:cur_etheraddr",1,NULL,0,mac,6),ps=iovar(NO,"bsscfg:cur_etheraddr",0,NULL,0,primary,6);
 BOOL nonzero=NO;for(unsigned i=0;i<6;i++)nonzero|=mac[i]!=0;
 BOOL own=!ms&&!ps&&nonzero&&!(mac[0]&1);Report[@"ownedAuxiliaryIdentityReadStatus"]=@(ms);Report[@"primaryIdentityReadStatus"]=@(ps);Report[@"ownedAuxiliaryValidIdentity"]=@(own);Report[@"originalAuxiliarySharesPrimaryMAC"]=@(!memcmp(mac,primary,6));
 if(!own)return NO;
 // The native AP bootstrap already supplied a fresh per-lease random MAC.
 // Retain it for data-path experiments so BSD/Skywalk and firmware agree.
 if(PreserveNativeDataMAC)memcpy(OwnedMAC,mac,6);else{arc4random_buf(OwnedMAC,6);OwnedMAC[0]=(OwnedMAC[0]|2)&0xfe;}
 MACRecorded=YES;Report[@"stationRetainsNativeAuxiliaryMAC"]=@(PreserveNativeDataMAC);
 NSMutableDictionary *receipt=[[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL]mutableCopy];
 receipt[@"originalAuxiliaryMACBase64"]=[[NSData dataWithBytes:mac length:6]base64EncodedStringWithOptions:0];receipt[@"ownedAuxiliaryMACBase64"]=[[NSData dataWithBytes:OwnedMAC length:6]base64EncodedStringWithOptions:0];receipt[@"ownedFirmwareInterfaceIndex"]=@1;
 NSData *identity=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];int fd=openat(AT_FDCWD,Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW);if(fd<0)return NO;
 BOOL saved=write(fd,identity.bytes,identity.length)==(ssize_t)identity.length&&!fsync(fd);close(fd);if(!saved||Stop)return NO;
 if(PreserveNativeDataMAC&&!acquireAuxiliaryBSDDataLease())return NO;
 uint8_t current[6]={0};int cs=iovar(NO,"bsscfg:cur_etheraddr",1,NULL,0,current,6);if(cs||memcmp(current,mac,6))return NO;
 if(!acquireOwnedAuxiliaryPowerLease()||!beginOwnedIFEventFilter())return NO;
 int32_t down[2]={-1,0};int downStatus=iovar(YES,"bss",1,down,sizeof(down),NULL,0);Report[@"ownedAuxiliaryBSSDownStatus"]=@(downStatus);if(downStatus)return NO;
#ifdef VM27_WIFI_INPLACE_BSS_ROLE
 {
 // Bounded alternative from the vendor's per-BSS AP/STA role operation;
 // unlike WLC_SET_AP, this is scoped to the already verified auxiliary BSS.
 int32_t ownedBSS=-1;
 int verifiedIndex=readVerifiedOwnedBssIndex(&ownedBSS);
 Report[@"inPlaceBSSIdentityReadStatus"]=@(verifiedIndex);if(verifiedIndex)return NO;
 Report[@"inPlaceBSSVerifiedConfigIndex"]=@(ownedBSS);
 struct {int32_t cfg,role;uint8_t mac[6],pad[2];} change={.cfg=ownedBSS,.role=3};memcpy(change.mac,OwnedMAC,6);
 int changed=iovar(YES,"bss",1,&change,sizeof(change),NULL,0);
 Report[@"inPlaceBSSStationRoleStatus"]=@(changed);memset(&change,0,sizeof(change));
 if(changed)return NO;
 uint32_t one=1;int infrastructure=request(Auxiliary,"ap1",YES,UINT32_MAX,20,&one,4);
 Report[@"inPlaceBSSSetInfrastructureStatus"]=@(infrastructure);
 uint8_t afterMAC[6]={0};int identity=iovar(NO,"cur_etheraddr",1,NULL,0,afterMAC,6);
 uint32_t infra=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
 BOOL verified=!infrastructure&&!identity&&!endpoint&&infra==1&&!memcmp(afterMAC,OwnedMAC,6);
 memset(afterMAC,0,sizeof(afterMAC));
 if(FilterInterfaceEvents){usleep(2000000);verified=restoreOwnedIFEventFilter(IFEventFilterNonce)&&verified;}
 Report[@"stationConversionUsesPerBSSRoleSwitch"]=@YES;Report[@"stationInPlaceRoleIdentityVerified"]=@(verified);
 if(verified)verified=recordOwnedStationRole();return verified;
 }
#endif
 if(InPlaceStationConversion){
  // Keep the native auxiliary endpoint and firmware interface identity. A
  // remove/create sequence can deliver a later IF_DEL event to the native
  // driver after the replacement STA has already authenticated.
  uint32_t primaryAP=UINT32_MAX,auxiliaryAP=UINT32_MAX,zero=0,one=1;
  int primaryRead=request(Primary,"en0",NO,UINT32_MAX,117,&primaryAP,4);
  int auxiliaryRead=request(Auxiliary,"ap1",NO,UINT32_MAX,117,&auxiliaryAP,4);
  Report[@"inPlacePrimaryAPReadStatus"]=@(primaryRead);Report[@"inPlaceAuxiliaryAPReadStatus"]=@(auxiliaryRead);
  Report[@"inPlacePrimaryAPBefore"]=@(primaryAP);Report[@"inPlaceAuxiliaryAPBefore"]=@(auxiliaryAP);
  if(primaryRead||auxiliaryRead||primaryAP!=0||auxiliaryAP!=1)return NO;
  int switched=request(Auxiliary,"ap1",YES,UINT32_MAX,118,&zero,4);
  Report[@"inPlaceAuxiliarySetAPStatus"]=@(switched);if(switched)return NO;
  int infrastructure=request(Auxiliary,"ap1",YES,UINT32_MAX,20,&one,4);
  Report[@"inPlaceAuxiliarySetInfrastructureStatus"]=@(infrastructure);if(infrastructure)return NO;
  uint32_t actualAP=UINT32_MAX,actualPrimary=UINT32_MAX,infra=0;uint8_t actualMAC[6]={0};
  int modeRead=request(Auxiliary,"ap1",NO,UINT32_MAX,117,&actualAP,4);
  int primaryAfter=request(Primary,"en0",NO,UINT32_MAX,117,&actualPrimary,4);
  int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
  int identityRead=iovar(NO,"cur_etheraddr",1,NULL,0,actualMAC,6);
  BOOL verified=!modeRead&&!primaryAfter&&!endpoint&&!identityRead&&actualAP==0&&actualPrimary==primaryAP&&infra==1&&!memcmp(actualMAC,OwnedMAC,6);
  Report[@"stationConversionUsesInterfaceRemove"]=@NO;Report[@"stationInPlaceRoleVerified"]=@(verified);
  recordPrimaryAssociation();return verified&&[Report[@"primaryAssociationPreserved"]boolValue];
 }
 usleep(100000);
 int removed=iovar(YES,"bsscfg:interface_remove",1,NULL,0,NULL,0);Report[@"ownedAPContextRemoveStatus"]=@(removed);if(removed)return NO;
 struct {uint16_t version,length,fixedLength;uint8_t type,wlc;uint32_t flags;uint8_t mac[6],bssid[6],index,pad[3];} create={.version=3,.length=28,.fixedLength=28,.type=0,.wlc=1,.flags=14,.index=1};
 // Exact iPad14,6 / 20B101 route validated with real guest DHCP and HTTPS.
 // Automatic core assignment caused firmware watchdogs; do not regress it.
 Report[@"ownedStationExplicitWLCIndex"]=@(create.wlc);
 _Static_assert(sizeof(create)==28,"firmware v3 create");memcpy(create.mac,OwnedMAC,6);
 uint8_t result[64]={0};int created=iovar(NO,"interface_create",-1,&create,sizeof(create),result,sizeof(result));Report[@"ownedStationContextCreateStatus"]=@(created);
 if(!created){uint16_t version=0,length=0;memcpy(&version,result,2);memcpy(&length,result+2,2);Report[@"stationCreateResponseVersion"]=@(version);
  if(version==2&&length>=28&&length<=sizeof(result)){Report[@"stationCreateResponseIdentityMatches"]=@(!memcmp(result+4,OwnedMAC,6));Report[@"stationCreateResponseBSSConfigIndex"]=@(result[10]);Report[@"stationCreateResponseInterfaceIndex"]=@(result[11]);}
  else if(version==1){Report[@"stationCreateResponseIdentityMatches"]=@(!memcmp(result+2,OwnedMAC,6));Report[@"stationCreateResponseBSSConfigIndex"]=@(result[24]);}
 }
 memset(result,0,sizeof(result));memset(&create,0,sizeof(create));
 if(FilterInterfaceEvents){usleep(2000000);BOOL restored=restoreOwnedIFEventFilter(IFEventFilterNonce);Report[@"interfaceEvent54RestoredAfterConversion"]=@(restored);if(!restored)return NO;}
 if(created){
 create.version=3;create.length=28;create.fixedLength=28;create.type=1;create.flags=10;create.index=1;memcpy(create.mac,mac,6);
 int recovery=iovar(NO,"interface_create",-1,&create,sizeof(create),result,sizeof(result));Report[@"ownedAPRecoveryCreateStatus"]=@(recovery);if(!recovery)memcpy(OwnedMAC,mac,6);
 memset(result,0,sizeof(result));memset(&create,0,sizeof(create));
 }
 cs=iovar(NO,"bsscfg:cur_etheraddr",1,NULL,0,current,6);BOOL verified=!created&&!cs&&!memcmp(current,OwnedMAC,6);Report[@"ownedStationIdentityVerified"]=@(verified);
 uint32_t infra=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,sizeof(infra));Report[@"stationNativeEndpointStatus"]=@(endpoint);Report[@"stationInfrastructureMode"]=@(infra);
 BOOL converted=verified&&!endpoint&&infra==1;
 if(converted)converted=recordOwnedStationRole();
 memset(mac,0,sizeof(mac));memset(primary,0,sizeof(primary));memset(current,0,sizeof(current));return converted;
}
static int mode(uint32_t *out){
 CFDictionaryRef state=NULL;int result=StateInfo(AuxiliaryDevice,&state);if(result)return result;
 CFTypeRef enabled=state?CFDictionaryGetValue(state,CFSTR("WiFiHostApStateEnable")):NULL;
 if(enabled&&(CFGetTypeID(enabled)==CFBooleanGetTypeID()||CFGetTypeID(enabled)==CFNumberGetTypeID()))*out=[(__bridge NSNumber *)enabled boolValue]?8:0;
 else result=ENODATA;if(state)CFRelease(state);return result;
}
static int initializeStateReader(void){
 void *lib=dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi",RTLD_NOW|RTLD_LOCAL);
 CFTypeRef (*create)(CFAllocatorRef,int)=(void *)dlsym(lib,"WiFiManagerClientCreate");
 CFArrayRef (*interfaces)(CFTypeRef)=(void *)dlsym(lib,"WiFiManagerClientCopyInterfaces");
 CFStringRef (*name)(CFTypeRef)=(void *)dlsym(lib,"WiFiDeviceClientGetInterfaceName");
 StateInfo=(void *)dlsym(lib,"WiFiDeviceClientCopyInterfaceStateInfo");CurrentNetwork=(void *)dlsym(lib,"WiFiDeviceClientCopyCurrentNetwork");NetworkProperty=(void *)dlsym(lib,"WiFiNetworkGetProperty");
 if(!create||!interfaces||!name||!StateInfo||!CurrentNetwork||!NetworkProperty)return ENOSYS;
 WiFiManager=create(kCFAllocatorDefault,0);if(!WiFiManager)return EIO;CFArrayRef rows=interfaces(WiFiManager);
 if(rows)for(CFIndex i=0;i<CFArrayGetCount(rows);++i){CFTypeRef d=CFArrayGetValueAtIndex(rows,i);CFStringRef n=name(d);
  if(n&&CFEqual(n,CFSTR("ap1")))AuxiliaryDevice=CFRetain(d);if(n&&CFEqual(n,CFSTR("en0")))PrimaryDevice=CFRetain(d);}
 if(rows)CFRelease(rows);return AuxiliaryDevice&&PrimaryDevice?0:ENODEV;
}
static NSData *ssid(int *status){uint8_t b[36]={0};*status=request(Auxiliary,"ap1",NO,UINT32_MAX,25,b,sizeof(b));
 uint32_t n=0;memcpy(&n,b,4);return !*status&&n<=32?[NSData dataWithBytes:b+4 length:n]:nil;}
#if defined(VM27_WIFI_RENEW_NATIVE_READERS_BEFORE_REUSE) || defined(VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME)
static VM27WiFiNativeReaderStateV1 readNativeRenewalState(void){
 VM27WiFiNativeReaderStateV1 state={.peerStatus=ENODATA,.authStatus=ENODATA,.wsecStatus=ENODATA};
 state.modeStatus=mode(&state.mode);
 state.identityStatus=iovar(NO,"cur_etheraddr",1,NULL,0,state.identity,6);
 state.infraStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&state.infra,4);
 NSData *value=ssid(&state.ssidStatus);(void)value;
 // Do not issue additional firmware reads after endpoint absence.
 if(!state.identityStatus&&!state.infraStatus){
  state.peerStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,23,state.peer,6);
  state.authStatus=iovar(NO,"wpa_auth",1,NULL,0,&state.auth,4);
  state.wsecStatus=iovar(NO,"wsec",1,NULL,0,&state.wsec,4);
 }
 return state;
}
#endif
#ifdef VM27_WIFI_RENEW_NATIVE_READERS_BEFORE_REUSE
static BOOL renewQuiescedNativeReaders(NSDictionary *record){
 struct timeval boot={0};size_t bootSize=sizeof(boot);
 NSData *expected=[[NSData alloc]initWithBase64EncodedString:record[@"ownedAuxiliaryMACBase64"]options:0];
 if(![record[@"ownedStationRoleActive"]isEqual:@YES]||![record[@"build"]isEqual:@"20B101"]||
    [record[@"ownedFirmwareInterfaceIndex"]intValue]!=1||expected.length!=6||
    sysctlbyname("kern.boottime",&boot,&bootSize,NULL,0)||[record[@"ifEventFilterBootSeconds"]longLongValue]!=boot.tv_sec)return NO;
 VM27WiFiNativeReaderStateV1 before=readNativeRenewalState();
 int eligible=vm27_wifi_native_reader_renewal_v1(&before,expected.bytes);
 Report[@"nativeReaderRenewalEligibility"]=@(eligible);
 if(eligible==VM27NativeReaderAbsentV1)return YES;
 if(eligible!=VM27NativeReaderOwnedIdleV1)return NO;
 void *library=dlopen("/System/Library/PrivateFrameworks/IO80211.framework/IO80211",RTLD_NOW|RTLD_LOCAL);
 int (*openControl)(void **)=(void *)dlsym(library,"Apple80211Open");
 int (*bindControl)(void *,io_service_t,CFStringRef,unsigned)=(void *)dlsym(library,"Apple80211BindToInterfaceWithService");
 int (*closeControl)(void *)=(void *)dlsym(library,"Apple80211Close");
 if(!openControl||!bindControl||!closeControl||!restoreOwnedIFEventFilter(nil))return NO;
 // Close only our native control handles and MobileWiFi reader objects.
 // Native ownership performs its own retirement; no BSS, delete, power or
 // primary-interface setter is issued here. The authenticated VM socket
 // remains open while the already-detached guest waits for a fresh join.
 closeControl(Auxiliary);Auxiliary=NULL;closeControl(Primary);Primary=NULL;
 if(AuxiliaryDevice)CFRelease(AuxiliaryDevice);AuxiliaryDevice=NULL;
 if(PrimaryDevice)CFRelease(PrimaryDevice);PrimaryDevice=NULL;
 if(WiFiManager)CFRelease(WiFiManager);WiFiManager=NULL;
 usleep(250000);
 io_iterator_t iterator=0;
 if(IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("IOUserNetworkWLAN"),&iterator)){Stop=1;return NO;}
 for(io_service_t service;(service=IOIteratorNext(iterator));IOObjectRelease(service)){
  CFTypeRef value=IORegistryEntryCreateCFProperty(service,CFSTR("IOInterfaceName"),kCFAllocatorDefault,0);
  NSString *name=value&&CFGetTypeID(value)==CFStringGetTypeID()?(__bridge NSString *)value:nil;
  void **slot=[name isEqual:@"en0"]?&Primary:[name isEqual:@"ap1"]?&Auxiliary:NULL;
  if(slot){int status=openControl(slot);if(!status)status=bindControl(*slot,service,(__bridge CFStringRef)name,0);
   if(status&&*slot){closeControl(*slot);*slot=NULL;}}
  if(value)CFRelease(value);
 }IOObjectRelease(iterator);
 if(!Primary||!Auxiliary||initializeStateReader()){Stop=1;return NO;}
 Report[@"nativeControlReadersClosedAndReopened"]=@YES;
 BOOL absent=NO;unsigned samples=0;
 for(unsigned attempt=0;attempt<60&&!Stop;attempt++){
  VM27WiFiNativeReaderStateV1 state=readNativeRenewalState();samples++;
  int status=vm27_wifi_native_reader_renewal_v1(&state,expected.bytes);
  if(status==VM27NativeReaderAbsentV1){absent=YES;break;}
  if(status!=VM27NativeReaderOwnedIdleV1)break;
  usleep(100000);
 }
 Report[@"nativeReaderRenewalAbsenceSamples"]=@(samples);
 Report[@"nativeOwnerRetiredAuxiliaryBeforeRejoin"]=@(absent);
 recordPrimaryAssociation();
 return absent&&[Report[@"primaryAssociationPreserved"]boolValue];
}
#endif
static BOOL quiesceOwnedStation(void){
 if(!OwnedStationRoleActive)return YES;
 NSDictionary *record=readFilterReceipt();NSData *original=[[NSData alloc]initWithBase64EncodedString:record[@"originalAuxiliaryMACBase64"]options:0];
 if(original.length!=6)return NO;
 uint8_t current[6]={0};int status=iovar(NO,"cur_etheraddr",1,NULL,0,current,6);
 if(status||memcmp(current,OwnedMAC,6))return NO;
 // A BSS-down operation does not complete the associated STA's leave path.
 // Quiesce the bound STA and its firmware supplicant before removing it.
 // The native 20B101 leaveNetworkSync command uses a 12-byte reason/MAC
 // payload (0x1f9de0..0x1f9e48); never issue this on the primary handle.
 uint8_t leave[12]={0};uint32_t reason=8;memcpy(leave,&reason,4);
 int peerRead=request(Auxiliary,"ap1",NO,UINT32_MAX,23,leave+4,6);
 Report[@"cleanupOwnedSTAPeerReadStatus"]=@(peerRead);
#ifdef VM27_WIFI_SINGLE_NATIVE_STA_LEAVE
 uint8_t peer[6];memcpy(peer,leave+4,6);
 int action=vm27_wifi_native_sta_leave_v1(peerRead,peer,OwnedJoinStateKnown,OwnedJoinPending,leave);
 memset(peer,0,sizeof(peer));Report[@"cleanupNativeSTAAction"]=@(action);
 if(action<0){memset(leave,0,sizeof(leave));return NO;}
 memcpy(&reason,leave,4);Report[@"cleanupNativeSTAReason"]=@(reason);
 Report[@"cleanupNativeSTACommandCount"]=@(action==VM27STAIdleV1?0:1);
 BOOL deauthenticate=NO;
#ifdef VM27_WIFI_SINGLE_NATIVE_STA_DEAUTH
 deauthenticate=YES;
#endif
 int command=vm27_wifi_native_sta_command_v1(action,deauthenticate);
 Report[@"cleanupNativeSTACommand"]=@(command);
 if(command<0){memset(leave,0,sizeof(leave));return NO;}
 int disassociated=command?request(Auxiliary,"ap1",YES,UINT32_MAX,(uint32_t)command,leave,sizeof(leave)):0;
 Report[@"cleanupUsesSingleNativeStationRetirement"]=@YES;
#elif defined(VM27_WIFI_NATIVE_STA_LEAVE)
 // Audited 20B101 APSTA::setSTA_DISASSOCIATE (0xa3e54): version,
 // reason, six-byte peer. Its native dispatcher issues WLC command 201.
 uint8_t nativeLeave[16]={0};uint32_t version=1;memcpy(nativeLeave,&version,4);
 memcpy(nativeLeave+4,&reason,4);memcpy(nativeLeave+8,leave+4,6);
 int disassociated=peerRead==(int)0xe3ff8111?0:peerRead?peerRead:request(Auxiliary,"ap1",YES,75,1,nativeLeave,sizeof(nativeLeave));
 memset(nativeLeave,0,sizeof(nativeLeave));Report[@"cleanupUsesNativeAPSTAPeerRemoval"]=@YES;
#else
 int disassociated=request(Auxiliary,"ap1",YES,UINT32_MAX,52,leave,sizeof(leave));
 Report[@"cleanupUsesNativeStationDisassociate"]=@YES;
 Report[@"cleanupNativeStationDisassociateCommand"]=@52;
#endif
 memset(leave,0,sizeof(leave));Report[@"cleanupOwnedSTADisassociateStatus"]=@(disassociated);
 if(disassociated)return NO;
 OwnedJoinStateKnown=YES;OwnedJoinPending=NO;
#ifdef VM27_WIFI_ABORT_STA_JOIN_BEFORE_REMOVE
 // 20B101 JoinManager::abortFirmwareJoinSync (0x233d18) uses WLC_DISASSOC
 // with reason 3 and a zero peer, rather than a peer-specific SCB removal.
 // Scope that association-state-machine abort to our verified ap1 endpoint.
 uint8_t abortJoin[12]={0};uint32_t abortReason=3;
 memcpy(abortJoin,&abortReason,4);
 int abortStatus=request(Auxiliary,"ap1",YES,UINT32_MAX,52,abortJoin,sizeof(abortJoin));
 memset(abortJoin,0,sizeof(abortJoin));
 Report[@"cleanupOwnedSTAJoinStateAbortStatus"]=@(abortStatus);
 if(abortStatus)return NO;
#endif
 BOOL unassociated=NO;
 for(unsigned attempt=0;attempt<20;attempt++){
  uint8_t peer[6]={0};int read=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,6);
  unsigned present=0;for(unsigned i=0;i<6;i++)present|=peer[i];
  Report[@"cleanupOwnedSTALastPeerReadStatus"]=@(read);
  // This exact firmware maps BCME_NOTASSOCIATED to e3ff8111. A direct
  // bound read observed that code after the successful leave operation.
  if((!read&&!present)||read==(int)0xe3ff8111){unassociated=YES;break;}
  usleep(100000);
 }
 Report[@"cleanupOwnedSTAUnassociatedVerified"]=@(unassociated);if(!unassociated)return NO;
#ifndef VM27_WIFI_PERSIST_STA_AUTH
 uint32_t zero=0;
 int supplicant=iovar(YES,"sup_wpa",1,&zero,4,NULL,0);
 Report[@"cleanupOwnedSTASupplicantDisableStatus"]=@(supplicant);if(supplicant)return NO;
#else
 // The retained physical STA is not being destroyed. Native disassociation
 // ends its link; preserve the firmware supplicant for the next explicit
 // guest-requested network instead of tearing down a live controller's
 // authentication object. No guest packets are forwarded after detach.
 uint32_t auth=UINT32_MAX,encryption=UINT32_MAX,supplicant=UINT32_MAX;
 int authStatus=iovar(NO,"wpa_auth",1,NULL,0,&auth,4);
 int encryptionStatus=iovar(NO,"wsec",1,NULL,0,&encryption,4);
 int supplicantStatus=iovar(NO,"sup_wpa",1,NULL,0,&supplicant,4);
 BOOL configured=!authStatus&&!encryptionStatus&&!supplicantStatus&&auth==128&&encryption==4&&supplicant==1;
 Report[@"cleanupOwnedSTAAuthenticationRetained"]=@(configured);
 if(!configured)return NO;
#endif
#ifdef VM27_WIFI_CLEAR_STA_SECURITY_AFTER_LEAVE
 // Clear the owned BSS's authentication state after the peer has left.
 // Supplicant shutdown alone does not prove all security callbacks retired.
 int auth=iovar(YES,"wpa_auth",1,&zero,4,NULL,0);
 int encryption=auth?auth:iovar(YES,"wsec",1,&zero,4,NULL,0);
 int informationElement=encryption?encryption:iovar(YES,"wpaie",1,NULL,0,NULL,0);
 Report[@"cleanupOwnedSTAClearAuthenticationStatus"]=@(auth);
 Report[@"cleanupOwnedSTAClearEncryptionStatus"]=@(encryption);
 Report[@"cleanupOwnedSTAClearRSNIEStatus"]=@(informationElement);
 if(auth||encryption||informationElement)return NO;
 uint32_t actualAuth=UINT32_MAX,actualEncryption=UINT32_MAX;
 int authRead=iovar(NO,"wpa_auth",1,NULL,0,&actualAuth,4);
 int encryptionRead=iovar(NO,"wsec",1,NULL,0,&actualEncryption,4);
 BOOL cleared=!authRead&&!encryptionRead&&!actualAuth&&!actualEncryption;
 Report[@"cleanupOwnedSTASecurityDisabledReadBack"]=@(cleared);
 if(!cleared)return NO;
#endif
 // NOTASSOCIATED precedes completion of queued firmware TX/event work.
 // Keep the owned context alive through a bounded drain before teardown.
#ifndef VM27_WIFI_STATION_DRAIN_SECONDS
#define VM27_WIFI_STATION_DRAIN_SECONDS 3
#endif
 _Static_assert(VM27_WIFI_STATION_DRAIN_SECONDS>=1&&VM27_WIFI_STATION_DRAIN_SECONDS<=60,"bounded firmware drain");
 Report[@"cleanupFirmwareDrainSeconds"]=@VM27_WIFI_STATION_DRAIN_SECONDS;
 usleep(VM27_WIFI_STATION_DRAIN_SECONDS*1000000);
 uint8_t drainedPeer[6]={0};int drained=request(Auxiliary,"ap1",NO,UINT32_MAX,23,drainedPeer,6);
 unsigned present=0;for(unsigned i=0;i<6;i++)present|=drainedPeer[i];
 uint8_t identity[6]={0};int identityRead=iovar(NO,"cur_etheraddr",1,NULL,0,identity,6);
 BOOL drainedOK=(drained==(int)0xe3ff8111||(!drained&&!present))&&!identityRead&&!memcmp(identity,OwnedMAC,6);
 memset(drainedPeer,0,sizeof(drainedPeer));memset(identity,0,sizeof(identity));
 Report[@"cleanupOwnedSTADrainedUnassociatedIdentityVerified"]=@(drainedOK);if(!drainedOK)return NO;
 Report[@"cleanupOwnedSTAQuiesced"]=@YES;
 memset(current,0,sizeof(current));return YES;
}
static BOOL retireOwnedStation(void){
 if(!OwnedStationRoleActive)return NO;
 uint8_t before[6]={0};int identity=iovar(NO,"cur_etheraddr",1,NULL,0,before,6);
 if(identity||!MACRecorded||memcmp(before,OwnedMAC,6))return NO;
 // Stop the native BSD/Skywalk producer before destroying its firmware
 // endpoint. Closing our BPF descriptor alone does not stop native traffic.
#ifndef VM27_WIFI_RETAIN_QUIESCED_STA
 BOOL flags=releaseAuxiliaryBSDDataLease()&&recoverAuxiliaryBSDDataLease(readFilterReceipt());
 Report[@"cleanupBSDUpRestoredBeforeFirmwareRemove"]=@(flags);if(!flags)return NO;
#endif
 if(!quiesceOwnedStation())return NO;
#ifdef VM27_WIFI_RETAIN_QUIESCED_STA_UP
 uint32_t bssEnabled=UINT32_MAX;
 int bssRead=readVerifiedOwnedBssEnabled(&bssEnabled);
 Report[@"cleanupUnassociatedBSSReadStatus"]=@(bssRead);
 Report[@"cleanupUnassociatedBSSEnabled"]=@(bssEnabled);
 if(bssRead||bssEnabled>1)return NO;
#endif
#ifdef VM27_WIFI_STA_BSS_DOWN_BEFORE_REMOVE
 // Disassociation clears the peer, but may leave this BSS configuration up.
 // Exercise only the verified auxiliary endpoint's BSS-down operation before
 // deleting its context; never issue a controller-wide WLC_DOWN here.
 int downStatus=setVerifiedOwnedBssEnabled(0);
 Report[@"cleanupOwnedSTABSSDownBeforeRemoveStatus"]=@(downStatus);
 if(downStatus)return NO;
 usleep(1000000);
 uint8_t identityAfterDown[6]={0};
 int identityAfterDownStatus=iovar(NO,"cur_etheraddr",1,NULL,0,identityAfterDown,6);
 BOOL stillOwned=!identityAfterDownStatus&&!memcmp(identityAfterDown,OwnedMAC,6);
 memset(identityAfterDown,0,sizeof(identityAfterDown));
 Report[@"cleanupOwnedSTABSSDownIdentityVerified"]=@(stillOwned);
 if(!stillOwned)return NO;
#endif
 #ifdef VM27_WIFI_RETAIN_QUIESCED_STA
 // Keep the native control endpoint awake through disassociation, security
 // clearing and BSS-down. No firmware context is destroyed on this path.
 BOOL flags=releaseRetainedStationBSDLease();
 Report[@"cleanupBSDFlagsRestoredAfterQuiesce"]=@(flags);if(!flags)return NO;
 // Separate a VM lease from the physical controller's lifetime. Keep the
 // identity-verified BSS allocated and without security state, so a
 // later VM lease can reuse it. Never describe this as deleting the context.
 NSMutableDictionary *retained=[readFilterReceipt()mutableCopy];
 if(!retained)return NO;retained[@"retainedQuiescedStation"]=@YES;
#ifdef VM27_WIFI_PERSIST_STA_AUTH
 retained[@"retainedAuthenticationConfigured"]=@YES;
#endif
#ifdef VM27_WIFI_RETAIN_NATIVE_BSD_UP
 retained[@"retainedOwnedNativeBSDInterfaceUp"]=@YES;
#endif
 NSData *retainedData=[NSJSONSerialization dataWithJSONObject:retained options:0 error:NULL];
 int retainedFD=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC);
 BOOL retainedSaved=retainedFD>=0&&write(retainedFD,retainedData.bytes,retainedData.length)==(ssize_t)retainedData.length&&!fsync(retainedFD);
 if(retainedFD>=0)close(retainedFD);
 Report[@"ownedStationQuiescedContextRetained"]=@(retainedSaved);
 return retainedSaved;
 #endif
 // A converted STA is not an AP: do not send the native AP BSS-down
 // sequence to it. Remove this verified, unassociated STA directly and
 // let its final IF_DEL reach the native interface owner.
 int removed=iovar(YES,"interface_remove",1,NULL,0,NULL,0);
 Report[@"cleanupDirectSTAInterfaceRemoveStatus"]=@(removed);if(removed)return NO;
 BOOL inactive=NO;
 for(unsigned attempt=0;attempt<20;attempt++){
  usleep(100000);uint32_t infra=0,m=UINT32_MAX;uint8_t identity[6]={0};int ss=0;
  int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4);
  int address=iovar(NO,"cur_etheraddr",1,NULL,0,identity,6);ssid(&ss);
  int modeStatus=mode(&m);
  inactive=!modeStatus&&!m&&absentEndpoint(endpoint)&&absentEndpoint(address)&&absentEndpoint(ss);
  if(inactive)break;
 }
 Report[@"cleanupDirectSTAInterfaceAbsentVerified"]=@(inactive);
 if(inactive)OwnedStationRoleActive=NO;
#ifdef VM27_WIFI_NATIVE_AP_STOP_AFTER_STA_REMOVE
 if(inactive){
  // The native owner was bootstrapped as an AP. After the converted STA is
  // demonstrably absent, let that owner clear its concurrency/roam state.
  // Running this AP operation while the STA still exists is a different,
  // previously failed sequence and is deliberately excluded here.
  uint8_t empty[0x5dc]={0};uint32_t version=1;memcpy(empty,&version,4);
  int nativeStop=request(Primary,"en0",YES,25,1,empty,sizeof(empty));
  Report[@"cleanupNativeAPStopAfterSTAAbsentStatus"]=@(nativeStop);
  if(nativeStop)return NO;
 }
#endif
 return inactive;
}
static void cleanup(void){
 wipe(ManagedActivePMKDigest,sizeof(ManagedActivePMKDigest));ManagedActivePMKDigestValid=NO;
 if(!Sent||Stopped||!Primary||!Auxiliary)return;
 Report[@"cleanupAttemptCount"]=@([Report[@"cleanupAttemptCount"]unsignedIntValue]+1);
 if(!restoreOwnedIFEventFilter(nil)){Report[@"interfaceEventRestoreFailedReceiptRetained"]=@YES;return;}
 uint32_t m=0;int ms=mode(&m),ss=0;NSData *current=ssid(&ss);
 Report[@"cleanupModeReadStatus"]=@(ms);Report[@"cleanupSSIDReadStatus"]=@(ss);
 // A native bootstrap may fail before it sets any SSID. Only an empty SSID
 // or this lease's exact nonce is eligible for stopping an originally-idle AP.
 uint8_t mac[6]={0};int macStatus=MACRecorded?iovar(NO,"bsscfg:cur_etheraddr",1,NULL,0,mac,6):ENODATA;
 BOOL matches=MACRecorded&&!macStatus&&!memcmp(mac,OwnedMAC,6);memset(mac,0,sizeof(mac));
 BOOL own=!ms&&((m==0&&absentEndpoint(ss))||matches||(current&&(current.length==0||[current isEqual:OwnedSSID])));
 Report[@"cleanupIdentityMatched"]=@(own);if(!own)return;
 if(!restoreOwnedAuxiliaryPowerLease())return;
 if(m==0&&absentEndpoint(ss)){
  uint32_t value=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&value,4);
  if(absentEndpoint(endpoint)&&absentEndpoint(macStatus)){
   Stopped=releaseAuxiliaryBSDDataLease();Report[@"auxiliaryAlreadyInactiveBeforeNativeStop"]=@YES;Report[@"originalAuxiliaryInactiveRestored"]=@(Stopped);if(Stopped)unlink(Receipt);return;
  }
 }
 if(!NativeBootstrapSucceeded&&m==0&&absentEndpoint(ss)){Stopped=releaseAuxiliaryBSDDataLease();Report[@"bootstrapDidNotActivateEndpoint"]=@YES;Report[@"originalAuxiliaryInactiveRestored"]=@(Stopped);if(Stopped)unlink(Receipt);return;}
 if(OwnedStationRoleActive){
  if(!retireOwnedStation()){Report[@"cleanupDirectSTAReleaseFailedReceiptRetained"]=@YES;return;}
  if([Report[@"ownedStationQuiescedContextRetained"]boolValue]){
   Stopped=releaseAuxiliaryBSDDataLease();
   Report[@"guestStationLeaseReleasedPhysicalContextRetained"]=@(Stopped);
   Report[@"originalAuxiliaryInactiveRestored"]=@NO;
   return;
  }
  Stopped=releaseAuxiliaryBSDDataLease();Report[@"originalAuxiliaryInactiveRestored"]=@(Stopped);
  if(Stopped)unlink(Receipt);return;
 }
 uint8_t empty[0x5dc]={0};uint32_t version=1;memcpy(empty,&version,4);
 int status=request(Primary,"en0",YES,25,1,empty,sizeof(empty));
 BOOL flagsRestored=releaseAuxiliaryBSDDataLease();
 Report[@"nativeAuxiliaryStopStatus"]=@(status);m=UINT32_MAX;ms=mode(&m);
 uint32_t infrastructure=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infrastructure,sizeof(infrastructure));
 Report[@"auxiliaryEndpointStatusAfterStop"]=@(endpoint);
 int afterSSIDStatus=0;NSData *afterSSID=ssid(&afterSSIDStatus);(void)afterSSID;
 Report[@"auxiliarySSIDStatusAfterStop"]=@(afterSSIDStatus);
 Stopped=!status&&flagsRestored&&!ms&&m==0&&absentEndpoint(endpoint)&&absentEndpoint(afterSSIDStatus);Report[@"originalAuxiliaryInactiveRestored"]=@(Stopped);if(Stopped)unlink(Receipt);
}
#include "owned-idle-recovery.inc"
static BOOL prepareOwnedStation(void){
 if(Sent&&!Stopped)return NO;
 Sent=NO;Stopped=NO;MACRecorded=NO;NativeBootstrapSucceeded=NO;OwnedStationRoleActive=NO;OwnedSSID=nil;ReusingQuiescedStation=NO;
 OwnedJoinStateKnown=YES;OwnedJoinPending=NO;
 uint32_t m=UINT32_MAX;int status=mode(&m);Report[@"originalAuxiliaryModeReadStatus"]=@(status);Report[@"originalAuxiliaryMode"]=@(m);
 if(status||m!=0)return NO;
#ifdef VM27_WIFI_RETAIN_QUIESCED_STA
 NSDictionary *record=recoverMissingOwnedIdleMarker(readFilterReceipt());
 if([record[@"retainedQuiescedStation"]isEqual:@YES]){
#ifdef VM27_WIFI_RENEW_NATIVE_READERS_BEFORE_REUSE
  if(!renewQuiescedNativeReaders(record))return NO;
#endif
  NSData *mac=[[NSData alloc]initWithBase64EncodedString:record[@"ownedAuxiliaryMACBase64"]options:0];
  NSData *nonce=[[NSData alloc]initWithBase64EncodedString:record[@"generatedSSIDBase64"]options:0];
  struct timeval boot={0};size_t bootSize=sizeof(boot);
  BOOL receiptValid=[record[@"ownedStationRoleActive"]isEqual:@YES]&&
   [record[@"build"]isEqual:@"20B101"]&&[record[@"ownedFirmwareInterfaceIndex"]intValue]==1&&mac.length==6&&nonce.length>0&&nonce.length<=32&&
   !sysctlbyname("kern.boottime",&boot,&bootSize,NULL,0)&&[record[@"ifEventFilterBootSeconds"]longLongValue]==boot.tv_sec;
  if(!receiptValid)return NO;
  memcpy(OwnedMAC,mac.bytes,6);MACRecorded=YES;
  // Never enumerate firmware BSS slots. The 20B101 native commander treats
  // a missing bsscfg:cur_etheraddr as a watchdog failure, including a GET.
  // Wake the already-bound auxiliary endpoint, then authenticate it against
  // the root-only receipt before issuing any association or BSS operation.
  if(!restoreOwnedIFEventFilter(nil)||!acquireAuxiliaryBSDDataLease()){
   releaseAuxiliaryBSDDataLease();MACRecorded=NO;return NO;
  }
  // IFF_UP can complete asynchronously. Before key/association operations,
  // require the native auxiliary handle to refer to this same firmware STA.
  uint8_t actual[6]={0},peer[6]={0};uint32_t auth=UINT32_MAX,encryption=UINT32_MAX,infra=0;
  int identity=EIO,endpoint=EIO;
  for(unsigned attempt=0;attempt<30&&!Stop;attempt++){
   identity=iovar(NO,"cur_etheraddr",1,NULL,0,actual,6);
   endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,sizeof(infra));
   if(!identity&&!endpoint&&!memcmp(actual,OwnedMAC,6)&&infra==1)break;
   usleep(100000);
  }
  int peerStatus=request(Auxiliary,"ap1",NO,UINT32_MAX,23,peer,sizeof(peer));unsigned peerBits=0;for(unsigned i=0;i<6;i++)peerBits|=peer[i];
  int authStatus=iovar(NO,"wpa_auth",1,NULL,0,&auth,4),encryptionStatus=iovar(NO,"wsec",1,NULL,0,&encryption,4);
  BOOL authenticationReady=!authStatus&&!encryptionStatus&&!auth&&!encryption;
#ifdef VM27_WIFI_PERSIST_STA_AUTH
  uint32_t supplicant=UINT32_MAX;int supplicantStatus=iovar(NO,"sup_wpa",1,NULL,0,&supplicant,4);
  BOOL configured=!authStatus&&!encryptionStatus&&!supplicantStatus&&auth==128&&encryption==4&&supplicant==1;
  // A legacy zero-security receipt may be migrated once. After our own
  // configured-session receipt is written, losing that state is a mismatch.
  authenticationReady=configured||(authenticationReady&&![record[@"retainedAuthenticationConfigured"]boolValue]&&!supplicantStatus&&!supplicant);
  Report[@"retainedAuthenticationConfiguredReadback"]=@(configured);
#endif
  BOOL adopt=!identity&&!endpoint&&infra==1&&!memcmp(actual,mac.bytes,6)&&(peerStatus==(int)0xe3ff8111||(!peerStatus&&!peerBits))&&authenticationReady;
  memset(actual,0,sizeof(actual));memset(peer,0,sizeof(peer));
  Report[@"retainedQuiescedStationIdentityAndSecurityVerified"]=@(adopt);
  Report[@"retainedStationIdentityReadStatus"]=@(identity);
  Report[@"retainedStationNativeEndpointWakeStatus"]=@(endpoint);
  if(!adopt){
   int absentSSIDStatus=0;NSData *absentSSID=ssid(&absentSSIDStatus);(void)absentSSID;
   Report[@"retainedStationInactiveSSIDReadStatus"]=@(absentSSIDStatus);
   BOOL nativeEndpointAbsent=absentEndpoint(identity)&&absentEndpoint(endpoint)&&absentEndpoint(absentSSIDStatus);
   BOOL released=releaseAuxiliaryBSDDataLease();MACRecorded=NO;
   // A native interface can disappear when its actual owner exits, while our
   // root-only receipt still says retained. Do not repeatedly try to adopt
   // that missing endpoint. The same inactive mode/INFRA/SSID preflight used
   // by a fresh bootstrap below must pass again before retiring the receipt.
   Report[@"retainedNativeEndpointAbsentVerified"]=@(nativeEndpointAbsent);
   if(!released||!nativeEndpointAbsent)return NO;
  }else{
  OwnedSSID=nonce;OwnedStationRoleActive=YES;
  Sent=YES;NativeBootstrapSucceeded=YES;ReusingQuiescedStation=YES;atexit(cleanup);
  Report[@"stationConversionEndpointVerified"]=@YES;Report[@"retainedStationReusedWithoutAPBootstrap"]=@YES;
#ifdef VM27_WIFI_RETAIN_QUIESCED_STA_UP
  // A retained infrastructure STA can remain enabled while unassociated and
  // with its security cleared. Cycling its BSS starts the cached previous
  // SET_SSID during resume, before a replacement network is configured.
  // The normal STA leave/join path does not need that AP-style BSS cycle.
  Report[@"retainedStationNoExplicitBSSCycle"]=@YES;
  return YES;
#else
  return setVerifiedOwnedBssEnabled(0)==0;
#endif
  }
 }
#endif
 uint32_t originalInfra=0;int originalEndpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&originalInfra,sizeof(originalInfra));
 Report[@"originalAuxiliaryEndpointStatus"]=@(originalEndpoint);
 if(!absentEndpoint(originalEndpoint))return NO;
 int originalSSIDStatus=0;NSData *originalSSID=ssid(&originalSSIDStatus);(void)originalSSID;
 Report[@"originalAuxiliarySSIDStatus"]=@(originalSSIDStatus);if(!absentEndpoint(originalSSIDStatus))return NO;
 uint32_t channel[3]={1,0,0};CFTypeRef current=CurrentNetwork(PrimaryDevice);
 CFTypeRef number=current?NetworkProperty(current,CFSTR("CHANNEL")):NULL,flags=current?NetworkProperty(current,CFSTR("CHANNEL_FLAGS")):NULL;
 if(number&&flags&&CFGetTypeID(number)==CFNumberGetTypeID()&&CFGetTypeID(flags)==CFNumberGetTypeID()){
  channel[1]=[(__bridge NSNumber *)number unsignedIntValue];channel[2]=[(__bridge NSNumber *)flags unsignedIntValue];
 }if(current)CFRelease(current);status=channel[1]?0:ENODATA;Report[@"primaryChannelReadStatus"]=@(status);if(status)return NO;PrimaryChannel=channel[1];
 const char *folder="/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1";struct stat st;
 if(mkdir(folder,0700)&&errno!=EEXIST)return NO;if(lstat(folder,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0700)return NO;
 struct stat old;if(!lstat(Receipt,&old)){
  if(!S_ISREG(old.st_mode)||old.st_uid||old.st_nlink!=1||(old.st_mode&0777)!=0600||old.st_size>4096)return NO;
  NSData *data=[NSData dataWithContentsOfFile:@(Receipt)];NSDictionary *previous=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
  if(![previous isKindOfClass:NSDictionary.class]||![previous[@"build"]isEqual:@"20B101"]||[previous[@"originalAuxiliaryMode"]unsignedIntValue]!=0)return NO;
  // Preflight above has independently verified the original inactive,
  // firmware-unassigned state. Retire only our stale local identity receipt.
  if(!restoreOwnedIFEventFilter(nil)||!recoverAuxiliaryBSDDataLease(previous))return NO;
  if(unlink(Receipt))return NO;Report[@"priorInactiveReceiptRetired"]=@YES;
 }
 NSString *nonce=NSUUID.UUID.UUIDString;OwnedSSID=[[NSString stringWithFormat:@"VM27-%@",[nonce substringToIndex:12]]dataUsingEncoding:NSUTF8StringEncoding];
 NSString *password=[NSUUID.UUID.UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
 NSData *receipt=[NSJSONSerialization dataWithJSONObject:@{@"schema":@1,@"build":@"20B101",@"originalAuxiliaryMode":@0,@"generatedSSIDBase64":[OwnedSSID base64EncodedStringWithOptions:0],@"primaryChannel":@(channel[1]),@"originalChannelFlags":@(channel[2])}options:0 error:NULL];
 int fd=openat(AT_FDCWD,Receipt,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return NO;
 BOOL saved=write(fd,receipt.bytes,receipt.length)==(ssize_t)receipt.length&&!fsync(fd);close(fd);if(!saved||Stop)return NO;
 // The local constructor's type 6 path derives a 32-byte PMK and stores
 // key_cipher_type=6. Type 5 reaches a legacy converter that rejects it before
 // any IOCTL, so its -3903 result was not a hardware capability verdict.
 NSDictionary *network=@{@"AP_MODE_AUTH_LOWER":@1,@"AP_MODE_AUTH_UPPER":@32,@"CHANNEL":@(channel[1]),@"CHANNEL_FLAGS":@(channel[2]),@"AP_MODE_CYPHER_TYPE":@6,@"AP_MODE_SSID_BYTES":OwnedSSID,@"AP_MODE_KEY":password,@"SOFTAP_SOFTAP_HIDDEN_NETWORK":@YES};
 // HOST_AP_MODE is a controller request routed through the primary service.
 // The ap1 virtual interface dispatcher does not implement request 25 (102).
 if(!SetObject)return NO;
 Sent=YES;atexit(cleanup);status=SetObject(Primary,25,0,(__bridge CFTypeRef)network,0);network=nil;password=nil;NativeBootstrapSucceeded=status==0;Report[@"nativeAuxiliaryBootstrapStatus"]=@(status);
 m=UINT32_MAX;int ms=mode(&m);Report[@"auxiliaryModeReadStatusAfterBootstrap"]=@(ms);Report[@"auxiliaryModeAfterBootstrap"]=@(m);
 uint32_t infra=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,sizeof(infra));Report[@"auxiliaryFirmwareEndpointStatus"]=@(endpoint);if(!endpoint)Report[@"auxiliaryFirmwareInfrastructureMode"]=@(infra);
 int ss=0;NSData *observed=ssid(&ss);Report[@"auxiliarySSIDReadStatus"]=@(ss);Report[@"auxiliarySSIDMatchesLease"]=@([observed isEqual:OwnedSSID]);
 if(status||endpoint||Stop)return NO;
 Report[@"stationConversionEndpointVerified"]=@(convertStation());
 return [Report[@"stationConversionEndpointVerified"]boolValue];
}
#include "wifi-station-packet-broker-v1.inc"
int main(int argc,const char **argv){@autoreleasepool{
 BOOL privateNativeSession=NO,readNativeRetirement=NO;
#ifdef VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME
 privateNativeSession=argc==3&&!strcmp(argv[1],"--serve-owned-native-station-fd");
 readNativeRetirement=argc==2&&!strcmp(argv[1],"--read-owned-native-retirement");
#endif
 BOOL ownedSession=privateNativeSession||(argc==3&&!strcmp(argv[1],"--serve-owned-station-fd"));
 if(ownedSession){
  char *end=NULL;long fd=strtol(argv[2],&end,10);
  const char *peer=privateNativeSession?"/var/jb/usr/local/libexec/virtualmac-owned-wifi-v1":"/var/jb/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27";
  if(!end||*end||fd<3||fd>1023||!VM27OwnedWiFiPeerAllowedV1((int)fd,privateNativeSession?0:501,peer))return 77;
  OwnedStationSessionFD=(int)fd;
  if(fcntl(OwnedStationSessionFD,F_SETFD,FD_CLOEXEC))return 77;
#ifdef VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME
  if(!privateNativeSession){
   char targetModel[32]={0},targetBuild[32]={0};size_t modelSize=sizeof(targetModel),buildSize=sizeof(targetBuild);
   if(geteuid()||sysctlbyname("hw.machine",targetModel,&modelSize,NULL,0)||strcmp(targetModel,"iPad14,6")||
      sysctlbyname("kern.osversion",targetBuild,&buildSize,NULL,0)||strcmp(targetBuild,"20B101"))return 77;
   return VM27OwnedWiFiSessionProxyV1(OwnedStationSessionFD,0);
  }
#endif
 }
 ManagedStationBroker=ownedSession||(argc==2&&!strcmp(argv[1],"--serve-development-managed-station"));
 ActiveAuxiliaryPower=argc==2&&(!strcmp(argv[1],"--serve-development-auxiliary-station-power-active")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-power-active"));
 BOOL validateLifetime=argc==2&&!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-validated-join");
 BOOL filterGuardian=argc==4&&!strcmp(argv[1],"--restore-owned-interface-event-filter");
 FilterInterfaceEvents=ManagedStationBroker||validateLifetime||ActiveAuxiliaryPower||(argc==2&&(!strcmp(argv[1],"--serve-development-auxiliary-station-filter-if-events")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-filter-if-events")));
 BOOL recoverOnly=argc==2&&!strcmp(argv[1],"--recover-owned-auxiliary-station");
 InPlaceStationConversion=argc==2&&(!strcmp(argv[1],"--serve-development-auxiliary-station-in-place")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-in-place"));
 BOOL serve=ManagedStationBroker||(argc==2&&(!strcmp(argv[1],"--serve-development-auxiliary-station")||!strcmp(argv[1],"--serve-development-auxiliary-station-in-place")||!strcmp(argv[1],"--serve-development-auxiliary-station-filter-if-events")||!strcmp(argv[1],"--serve-development-auxiliary-station-power-active")));NSData *brokerToken=nil;
 BOOL dhcp=validateLifetime||(argc==2&&(!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-in-place")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-filter-if-events")||!strcmp(argv[1],"--associate-dhcp-and-release-auxiliary-station-power-active")));
 PreserveNativeDataMAC=dhcp||serve;
 BOOL associate=serve||dhcp||(argc==2&&!strcmp(argv[1],"--associate-and-release-auxiliary-station"));
 if(!filterGuardian&&!recoverOnly&&!readNativeRetirement&&!associate&&(argc!=2||strcmp(argv[1],"--convert-and-release-auxiliary-station")))return 64;
 if(ownedSession&&PhysicalNativeInitialized){
  Report[@"brokerBidirectionalFramesObserved"]=@(serveStationPackets(nil));
  OwnedStationSessionFD=-1;return finish(0);
 }
 char build[32]={0},model[32]={0};size_t n=sizeof(build),modelSize=sizeof(model);if(geteuid()||sysctlbyname("kern.osversion",build,&n,NULL,0)||strcmp(build,"20B101")||sysctlbyname("hw.machine",model,&modelSize,NULL,0)||strcmp(model,"iPad14,6"))return 77;
 signal(SIGALRM,stopSignal);signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);alarm(ownedSession?0:serve?300:(validateLifetime?85:40));
 void *lib=dlopen("/System/Library/PrivateFrameworks/IO80211.framework/IO80211",RTLD_NOW|RTLD_LOCAL);
 int (*openControl)(void **)=(void *)dlsym(lib,"Apple80211Open");int (*bind)(void *,io_service_t,CFStringRef,unsigned)=(void *)dlsym(lib,"Apple80211BindToInterfaceWithService");
 int (*closeControl)(void *)=(void *)dlsym(lib,"Apple80211Close");Get=(void *)dlsym(lib,"Apple80211RawGet");Set=(void *)dlsym(lib,"Apple80211RawSet");
 SetObject=(void *)dlsym(lib,"Apple80211Set");if(!openControl||!bind||!closeControl||!Get||!Set||!SetObject)return 69;
 io_iterator_t iterator=0;if(IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("IOUserNetworkWLAN"),&iterator))return 69;
 Report=[@{@"schema":@1,@"networkAssociationCalls":@0,@"guestDataPathVerified":@NO,@"stationConversionRequested":@YES,@"temporaryHiddenNetwork":@YES,@"temporaryWPA2RandomCredential":@YES,@"routingOrDHCPConfigured":@NO}mutableCopy];
 for(io_service_t service;(service=IOIteratorNext(iterator));IOObjectRelease(service)){
  CFTypeRef value=IORegistryEntryCreateCFProperty(service,CFSTR("IOInterfaceName"),kCFAllocatorDefault,0);NSString *name=value&&CFGetTypeID(value)==CFStringGetTypeID()?(__bridge NSString *)value:nil;
  void **slot=[name isEqual:@"en0"]?&Primary:[name isEqual:@"ap1"]?&Auxiliary:NULL;
  if(slot){int result=openControl(slot);if(!result)result=bind(*slot,service,(__bridge CFStringRef)name,0);Report[[name stringByAppendingString:@"BindStatus"]]=@(result);if(result&&*slot){closeControl(*slot);*slot=NULL;}}
  if(value)CFRelease(value);
 }IOObjectRelease(iterator);
 if(filterGuardian){char *end=NULL;long fd=strtol(argv[3],&end,10);NSString *nonce=@(argv[2]);int result=75;if(Primary&&fd>=3&&fd<1024&&end&&!*end&&[[NSUUID alloc]initWithUUIDString:nonce])result=runIFEventGuardian(nonce,(int)fd);if(Auxiliary)closeControl(Auxiliary);if(Primary)closeControl(Primary);return result;}
 if(!Primary||!Auxiliary)return finish(69);
 const char *ownedFolder="/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1";struct stat ownedFolderInfo;
 if(mkdir(ownedFolder,0700)&&errno!=EEXIST)return finish(73);
 if(lstat(ownedFolder,&ownedFolderInfo)||!S_ISDIR(ownedFolderInfo.st_mode)||ownedFolderInfo.st_uid||(ownedFolderInfo.st_mode&0777)!=0700)return finish(73);
 OwnedLeaseLock=open("/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1/lease.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
 struct stat lockInfo;if(OwnedLeaseLock<0||fstat(OwnedLeaseLock,&lockInfo)||!S_ISREG(lockInfo.st_mode)||lockInfo.st_uid||lockInfo.st_nlink!=1||(lockInfo.st_mode&0777)!=0600||flock(OwnedLeaseLock,LOCK_EX|LOCK_NB))return finish(73);
 int reader=initializeStateReader();Report[@"stateReaderInitializationStatus"]=@(reader);if(reader)return finish(69);
 uint8_t primarySSID[36]={0};int primaryStatus=request(Primary,"en0",NO,UINT32_MAX,25,primarySSID,sizeof(primarySSID));uint32_t primaryLength=0;memcpy(&primaryLength,primarySSID,4);
 Report[@"primarySSIDReadStatusBefore"]=@(primaryStatus);if(!primaryStatus&&primaryLength>0&&primaryLength<=32)PrimarySSIDBefore=[NSData dataWithBytes:primarySSID+4 length:primaryLength];memset(primarySSID,0,sizeof(primarySSID));
 if(!PrimarySSIDBefore&&!recoverOnly)return finish(75);
#ifdef VM27_WIFI_OWNED_NATIVE_PROCESS_LIFETIME
 if(readNativeRetirement){
  Report[@"readOnly"]=@YES;Report[@"radioStateWrites"]=@0;Report[@"stationConversionRequested"]=@NO;
  VM27WiFiNativeReaderStateV1 state=readNativeRenewalState();NSDictionary *record=readFilterReceipt();
  BOOL absent=!state.modeStatus&&!state.mode&&absentEndpoint(state.identityStatus)&&absentEndpoint(state.infraStatus)&&absentEndpoint(state.ssidStatus);
  int outcome=absent?0:77;
  if(!absent&&record){
   struct timeval boot={0};size_t bootSize=sizeof(boot);
   NSData *expected=[[NSData alloc]initWithBase64EncodedString:record[@"ownedAuxiliaryMACBase64"]options:0];
   BOOL trusted=[record[@"build"]isEqual:@"20B101"]&&[record[@"ownedStationRoleActive"]isEqual:@YES]&&
    [record[@"ownedFirmwareInterfaceIndex"]intValue]==1&&expected.length==6&&
    !sysctlbyname("kern.boottime",&boot,&bootSize,NULL,0)&&[record[@"ifEventFilterBootSeconds"]longLongValue]==boot.tv_sec;
   if(trusted&&vm27_wifi_native_reader_renewal_v1(&state,expected.bytes)==VM27NativeReaderOwnedIdleV1)outcome=75;
  }
  Report[@"nativeRetirementEndpointAbsent"]=@(absent);Report[@"nativeRetirementIdentityStatus"]=@(state.identityStatus);
  Report[@"nativeRetirementInfraStatus"]=@(state.infraStatus);Report[@"nativeRetirementSSIDStatus"]=@(state.ssidStatus);
  closeControl(Auxiliary);closeControl(Primary);Auxiliary=NULL;Primary=NULL;
  return finish(outcome);
 }
#endif
 if(associate&&!ownedSession){
  uint8_t input[2048]={0};size_t used=0;while(used<sizeof(input)){ssize_t nread=read(0,input+used,1);if(nread<=0)break;if(input[used++]=='\n')break;}
  NSDictionary *configuration=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:input length:used]options:0 error:NULL];wipe(input,sizeof(input));
  ManagedDevelopmentBSSRestriction=ManagedStationBroker&&[configuration[@"restrictToPreviewBSS"]isEqual:@YES];
  NSArray *names=[configuration isKindOfClass:NSDictionary.class]?configuration[@"expectedSSIDs"]:nil;NSString *credential=[configuration isKindOfClass:NSDictionary.class]?configuration[@"password"]:nil;
  if(![names isKindOfClass:NSArray.class]||names.count!=2||(!ManagedStationBroker&&![credential isKindOfClass:NSString.class]))return finish(64);
  NSInteger primaryIndex=-1;for(unsigned i=0;i<2;i++){if(![names[i]isKindOfClass:NSString.class])return finish(64);NSData *bytes=[names[i]dataUsingEncoding:NSUTF8StringEncoding];if(!bytes.length||bytes.length>32)return finish(64);if([bytes isEqual:PrimarySSIDBefore])primaryIndex=i;}
  if(primaryIndex<0)return finish(75);TargetSSID=[names[1-primaryIndex]dataUsingEncoding:NSUTF8StringEncoding];TargetPassword=[[credential dataUsingEncoding:NSUTF8StringEncoding]mutableCopy];
  if((!ManagedStationBroker&&(TargetPassword.length<8||TargetPassword.length>63))||[TargetSSID isEqual:PrimarySSIDBefore])return finish(64);
  Report[@"primaryRequestedNetworkIndex"]=@(primaryIndex);Report[@"targetRequestedNetworkIndex"]=@(1-primaryIndex);Report[@"differentSSIDRequested"]=@YES;
  if(serve){NSString *encoded=configuration[@"tokenBase64"];if(![encoded isKindOfClass:NSString.class])return finish(64);brokerToken=[[NSData alloc]initWithBase64EncodedString:encoded options:0];if(brokerToken.length!=32)return finish(64);}
 }
 if(recoverOnly){
  if(!restoreOwnedIFEventFilter(nil)){Report[@"interfaceEventRecoveryVerified"]=@NO;return finish(75);}Report[@"interfaceEventRecoveryVerified"]=@YES;
  struct stat st;if(lstat(Receipt,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||st.st_size>4096)return finish(73);
  NSDictionary *stored=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL];
  if(![stored isKindOfClass:NSDictionary.class]||![stored[@"build"]isEqual:@"20B101"]||[stored[@"ownedFirmwareInterfaceIndex"]intValue]!=1)return finish(73);
  NSData *original=[[NSData alloc]initWithBase64EncodedString:stored[@"originalAuxiliaryMACBase64"]options:0];NSData *planned=[[NSData alloc]initWithBase64EncodedString:stored[@"ownedAuxiliaryMACBase64"]options:0];
  if(original.length!=6||planned.length!=6)return finish(73);
  BOOL match=NO;int readStatus=0;uint8_t current[6]={0};
  for(unsigned i=0;i<6&&!Stop;i++){
   readStatus=iovar(NO,"bsscfg:cur_etheraddr",1,NULL,0,current,6);
   if(!readStatus){match=!memcmp(current,original.bytes,6)||!memcmp(current,planned.bytes,6);break;}
   if(absentEndpoint(readStatus))break;usleep(250000);
  }
  NSData *expectedSSID=[[NSData alloc]initWithBase64EncodedString:stored[@"generatedSSIDBase64"]options:0];
  uint8_t cached[40]={0};uint32_t oneVersion=1;memcpy(cached,&oneVersion,4);
  int cachedStatus=request(Auxiliary,"ap1",NO,1,1,cached,sizeof(cached));uint32_t cachedLength=0;memcpy(&cachedLength,cached+4,4);
  BOOL nonceMatches=!cachedStatus&&cachedLength>0&&cachedLength<=32&&[expectedSSID isEqual:[NSData dataWithBytes:cached+8 length:cachedLength]];
  Report[@"recoveryCachedSSIDReadStatus"]=@(cachedStatus);Report[@"recoveryCachedSSIDMatchesOwnedNonce"]=@(nonceMatches);
  if(!nonceMatches){uint8_t bytes[36]={0};int ss=iovar(NO,"ssid",1,NULL,0,bytes,sizeof(bytes));uint32_t count=0;memcpy(&count,bytes,4);
   nonceMatches=!ss&&count>0&&count<=32&&[expectedSSID isEqual:[NSData dataWithBytes:bytes+4 length:count]];Report[@"recoveryBoundSSIDReadStatus"]=@(ss);Report[@"recoveryBoundSSIDMatchesOwnedNonce"]=@(nonceMatches);memset(bytes,0,sizeof(bytes));}
  match|=nonceMatches;memset(cached,0,sizeof(cached));
  Report[@"recoveryIdentityReadStatus"]=@(readStatus);Report[@"recoveryIdentityMatched"]=@(match);memset(current,0,sizeof(current));
  if(!match&&!absentEndpoint(readStatus))return finish(75);
  // No stop request is needed when three independent firmware reads already
  // show an absent auxiliary context and the native manager reports disabled.
  // Retire only our root-owned receipt; this branch changes no radio state.
  uint32_t beforeInfra=0,beforeEnabled=UINT32_MAX;int beforeEndpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&beforeInfra,4),beforeSSIDStatus=0;NSData *beforeSSID=ssid(&beforeSSIDStatus);(void)beforeSSID;
  int beforeMode=mode(&beforeEnabled);
  Report[@"recoveryEndpointStatusBefore"]=@(beforeEndpoint);Report[@"recoverySSIDStatusBefore"]=@(beforeSSIDStatus);Report[@"recoveryModeStatusBefore"]=@(beforeMode);Report[@"recoveryModeBefore"]=@(beforeEnabled);
  if(absentEndpoint(readStatus)&&absentEndpoint(beforeEndpoint)&&absentEndpoint(beforeSSIDStatus)&&!beforeMode&&!beforeEnabled){
   BOOL flags=recoverAuxiliaryBSDDataLease(stored);BOOL retired=flags&&!unlink(Receipt);Report[@"recoveryBSDUpFlagRestored"]=@(flags);Report[@"alreadyInactiveWithoutStop"]=@YES;Report[@"ownedAuxiliaryRecoveryVerified"]=@(retired);Report[@"recoveryReceiptRetained"]=@(!access(Receipt,F_OK));return finish(retired?0:73);
  }
  if(match&&!absentEndpoint(readStatus)&&[stored[@"ownedStationRoleActive"]boolValue]){
   memcpy(OwnedMAC,planned.bytes,6);MACRecorded=YES;OwnedStationRoleActive=YES;
   if(!retireOwnedStation()){Report[@"recoveryDirectSTAReleaseVerified"]=@NO;return finish(75);}
   if([Report[@"ownedStationQuiescedContextRetained"]boolValue]){
    BOOL flags=releaseRetainedStationBSDLease();
    Report[@"recoveryQuiescedContextRetained"]=@YES;Report[@"ownedAuxiliaryRecoveryVerified"]=@(flags);
    Report[@"recoveryReceiptRetained"]=@YES;return finish(flags?0:75);
   }
   BOOL flags=recoverAuxiliaryBSDDataLease(stored);BOOL retired=flags&&!unlink(Receipt);
   Report[@"recoveryDirectSTAReleaseVerified"]=@YES;Report[@"ownedAuxiliaryRecoveryVerified"]=@(retired);Report[@"recoveryReceiptRetained"]=@(!access(Receipt,F_OK));return finish(retired?0:75);
  }
  uint8_t empty[0x5dc]={0};uint32_t one=1;memcpy(empty,&one,4);
  int result=request(Primary,"en0",YES,25,1,empty,sizeof(empty));Report[@"nativeRecoveryStopStatus"]=@(result);
  uint32_t infra=0;int endpoint=request(Auxiliary,"ap1",NO,UINT32_MAX,19,&infra,4),ss=0;NSData *remaining=ssid(&ss);(void)remaining;
  uint32_t enabled=UINT32_MAX;int modeStatus=mode(&enabled);BOOL recovered=!result&&!modeStatus&&!enabled&&absentEndpoint(endpoint)&&absentEndpoint(ss);
  Report[@"recoveredAuxiliaryEndpointStatus"]=@(endpoint);Report[@"recoveredAuxiliarySSIDStatus"]=@(ss);Report[@"ownedAuxiliaryRecoveryVerified"]=@(recovered);
  if(recovered)recovered=recoverAuxiliaryBSDDataLease(stored);
  Report[@"ownedAuxiliaryRecoveryVerified"]=@(recovered);
  if(recovered)unlink(Receipt);Report[@"recoveryReceiptRetained"]=@(!access(Receipt,F_OK));return finish(recovered?0:75);
 }
 CFTypeRef initialNetwork=CurrentNetwork(PrimaryDevice);CFTypeRef initialChannel=initialNetwork?NetworkProperty(initialNetwork,CFSTR("CHANNEL")):NULL;
 if(initialChannel&&CFGetTypeID(initialChannel)==CFNumberGetTypeID())PrimaryChannel=[(__bridge NSNumber *)initialChannel unsignedIntValue];if(initialNetwork)CFRelease(initialNetwork);
 if(!PrimaryChannel||PrimaryChannel>196)return finish(75);
 if(ownedSession){if(!stationFirmwareProfileVerified())return finish(75);}
 else if(associate&&!selectStationCandidate())return finish(75);
 if(ManagedDevelopmentBSSRestriction){ManagedAllowedSSID=[TargetSSID copy];ManagedAllowedBSSID=[NSData dataWithBytes:TargetBSSID length:6];Report[@"managedDevelopmentSingleBSSRestriction"]=@YES;}
 if(ownedSession)PhysicalNativeInitialized=YES;
 if(ManagedStationBroker){
  Report[@"brokerBidirectionalFramesObserved"]=@(serveStationPackets(brokerToken));
 }else if(prepareOwnedStation()){
  if(associate&&!Stop){Report[@"concurrentDifferentWiFiAssociationVerified"]=@(associateStation());if(dhcp&&[Report[@"concurrentDifferentWiFiAssociationVerified"]boolValue])verifyAuxiliaryDHCP(OwnedMAC,Report);if(serve&&[Report[@"concurrentDifferentWiFiAssociationVerified"]boolValue])Report[@"brokerBidirectionalFramesObserved"]=@(serveStationPackets(brokerToken));}
 }
 if(validateLifetime&&[Report[@"concurrentDifferentWiFiAssociationVerified"]boolValue]){
  unsigned samples=0;BOOL valid=YES;
  for(unsigned i=0;i<60&&!Stop;i++){
   usleep(500000);uint8_t ssid[36]={0},bssid[6]={0};uint32_t length=0;
   int ss=request(Auxiliary,"ap1",NO,UINT32_MAX,25,ssid,sizeof(ssid));int bs=request(Auxiliary,"ap1",NO,UINT32_MAX,23,bssid,sizeof(bssid));memcpy(&length,ssid,4);recordPrimaryAssociation();
   BOOL match=!ss&&!bs&&length==TargetSSID.length&&length<=32&&!memcmp(ssid+4,TargetSSID.bytes,length)&&!memcmp(bssid,TargetBSSID,6)&&[Report[@"primaryAssociationPreserved"]boolValue];
   if(!match){Report[@"lifetimeLastSSIDReadStatus"]=@(ss);Report[@"lifetimeLastBSSIDReadStatus"]=@(bs);Report[@"lifetimeTargetSSIDMatches"]=@(!ss&&length==TargetSSID.length&&length<=32&&!memcmp(ssid+4,TargetSSID.bytes,length));Report[@"lifetimeTargetBSSIDMatches"]=@(!bs&&!memcmp(bssid,TargetBSSID,6));Report[@"lifetimePrimarySSIDMatches"]=Report[@"primaryAssociationPreserved"]?:@NO;valid=NO;break;}samples++;
  }
  Report[@"concurrentAssociationStableThirtySeconds"]=@(valid&&samples==60);Report[@"lifetimeHalfSecondSamples"]=@(samples);
 }
 if(ownedSession){OwnedStationSessionFD=-1;alarm(0);return finish(0);}
 cleanup();Report[@"recoveryReceiptRetained"]=@(!access(Receipt,F_OK));recordPrimaryAssociation();closeControl(Auxiliary);closeControl(Primary);Auxiliary=NULL;Primary=NULL;alarm(0);
 if(ownedSession)return finish(!Sent||Stopped?0:75);
 return finish([Report[@"stationConversionEndpointVerified"]boolValue]&&Stopped&&(!associate||[Report[ManagedStationBroker?@"managedGuestPMKAssociationVerified":@"concurrentDifferentWiFiAssociationVerified"]boolValue])&&(!dhcp||[Report[@"auxiliaryRealDHCPOfferVerified"]boolValue])?0:75);
}}
