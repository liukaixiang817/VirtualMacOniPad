// 20B101 native APSTA get/setSoftAP_PARAMS, audited at 0xac3dc/0xac7b0.
// Keep every current parameter except the power-save-enable byte at offset 23.
// The native controller routes request 347 through en0 to its APSTA object;
// ap1 rejects this request with 102. Only call after creating our own AP.
static BOOL ActiveAuxiliaryPower, AuxiliaryPowerRestorePending;
static uint8_t OriginalAuxiliaryPowerSave;
static BOOL setOwnedAuxiliaryPowerSave(uint8_t enabled, const char *phase) {
 uint8_t params[28]={0};uint32_t version=1;memcpy(params,&version,4);
 int status=request(Primary,"en0",NO,347,1,params,sizeof(params));
 NSString *prefix=@(phase);Report[[prefix stringByAppendingString:@"ReadStatus"]]=@(status);
 if(status||params[23]>1)return NO;
 params[23]=enabled;
 status=request(Primary,"en0",YES,347,1,params,sizeof(params));
 Report[[prefix stringByAppendingString:@"WriteStatus"]]=@(status);if(status)return NO;
 uint8_t observed[28]={0};memcpy(observed,&version,4);
 status=request(Primary,"en0",NO,347,1,observed,sizeof(observed));
 // Offset 22 is the live power state, so it may change after the setter.
 BOOL same=!status&&observed[23]==enabled;
 for(unsigned i=4;i<sizeof(params)&&same;i++)if(i!=22&&i!=23&&params[i]!=observed[i])same=NO;
 Report[[prefix stringByAppendingString:@"OnlyPowerSaveParameterChanged"]]=@(same);
 memset(params,0,sizeof(params));memset(observed,0,sizeof(observed));return same;
}
static BOOL acquireOwnedAuxiliaryPowerLease(void) {
 if(!ActiveAuxiliaryPower)return YES;
 uint8_t params[28]={0};uint32_t version=1;memcpy(params,&version,4);
 int status=request(Primary,"en0",NO,347,1,params,sizeof(params));
 Report[@"auxiliaryPowerParametersReadStatus"]=@(status);
 if(status||params[23]>1)return NO;
 OriginalAuxiliaryPowerSave=params[23];
 Report[@"auxiliaryPowerSaveEnabledBefore"]=@(OriginalAuxiliaryPowerSave);
 NSMutableDictionary *receipt=[[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL]mutableCopy];
 if(!receipt)return NO;receipt[@"originalOwnedAuxiliaryPowerSave"]=@(OriginalAuxiliaryPowerSave);
 NSData *data=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];
 int fd=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW);if(fd<0)return NO;
 BOOL saved=write(fd,data.bytes,data.length)==(ssize_t)data.length&&!fsync(fd);close(fd);if(!saved)return NO;
 AuxiliaryPowerRestorePending=YES;
 return setOwnedAuxiliaryPowerSave(0,"auxiliaryPowerLease");
}
static BOOL restoreOwnedAuxiliaryPowerLease(void) {
 if(!AuxiliaryPowerRestorePending)return YES;
 BOOL restored=setOwnedAuxiliaryPowerSave(OriginalAuxiliaryPowerSave,"auxiliaryPowerRestore");
 if(restored)AuxiliaryPowerRestorePending=NO;
 Report[@"auxiliaryPowerSaveOriginalRestored"]=@(restored);return restored;
}
