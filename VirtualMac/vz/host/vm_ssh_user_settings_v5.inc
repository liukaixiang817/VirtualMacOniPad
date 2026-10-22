static VM27SSHSettingsV3 VM27SSHCurrentV3={YES,22222,0,1};
static BOOL VM27SSHProvisioningV3;
static unsigned VM27SSHProvisionAttemptsV3;
static uint64_t VM27SSHProvisionEpochV3;
static NSString *VM27SSHProvisionDetailV3;
static NSString *VM27SSHActualVZPathV3(void) {
 return VZIndependent27SourceRouteSelected()?[VZBackendRuntimeRoot() stringByAppendingPathComponent:@"parent-flat/VZ27.dylib"]:
 VZRuntimePath(@"payload/Frameworks/Virtualization.framework/Virtualization");
}
static NSError *VM27SSHErrorV3(NSInteger code,NSString *message) {
 return [NSError errorWithDomain:@"VirtualMac.SSH" code:code userInfo:@{NSLocalizedDescriptionKey:message}];
}
static BOOL VM27SSHCreateCurrentV3(VM27SSHSettingsV3 settings,NSError **error) {
 if(error)*error=nil;
 if(!settings.enabled){gIndependent27SSHStarted=NO;gIndependent27SSHRegisteredV18=NO;return YES;}
 VM27GenuineVZSSHBridgeV1 *owner=nil;
 BOOL ok=VM27CreateGenuineVZSSHBridgeV3(gVirtualMachine,VM27SSHActualVZPathV3(),300000,
  settings.port,settings.scope,settings.families,&owner,error);
 gIndependent27SSHBridge=[owner retain];gIndependent27SSHLastSnapshotValid=NO;
 gIndependent27SSHRegisteredV18=ok&&owner!=nil;gIndependent27SSHStarted=gIndependent27SSHRegisteredV18;
 return gIndependent27SSHRegisteredV18;
}
extern BOOL VZGuestToolsCanProvisionSSHV4(void);
static void VM27SSHProvisionIfNeededV3(void) {
 // Readiness and the original exclusive QGA lease are independent of render polling.
 // An unavailable/busy agent does not consume a persistent installation attempt.
 if(!VZGuestToolsCanProvisionSSHV4())return;
 if(!VM27SSHCurrentV3.enabled || !gVirtualMachine || VM27SSHProvisioningV3 || VM27SSHChangingV3 ||
    VM27SSHProvisionAttemptsV3>=4 || gIndependent27OwnerClosePending ||
    ((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"))!=1)return;
 struct vm27_host_ssh_snapshot_v1 snapshot={0};
 if(gIndependent27SSHBridge && ![gIndependent27SSHBridge copySnapshot:&snapshot] && snapshot.ready)return;
 VM27SSHProvisioningV3=YES;++VM27SSHProvisionAttemptsV3;
 uint64_t epoch=VM27SSHProvisionEpochV3;id vm=[gVirtualMachine retain];
 VZGuestToolsEnsurePersistentSSHV3(^(BOOL ok,NSData *data) {
  if(gVirtualMachine==vm && epoch==VM27SSHProvisionEpochV3) {
   VM27SSHProvisioningV3=NO;[VM27SSHProvisionDetailV3 release];
   NSString *detail=ok?VZL(@"Guest SSH service is enabled."):[[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]autorelease];
   if(detail.length>300)detail=[detail substringToIndex:300];
   VM27SSHProvisionDetailV3=[(detail?:VZL(@"Waiting for the guest agent.")) copy];
   fprintf(stderr,"[VirtualMacSSHV3] persistentGuestService=%u attempt=%u credentialsChanged=0\n",ok,VM27SSHProvisionAttemptsV3);
  }
  [vm release];
 });
}
NSString *VZVMSSHStatusV3(NSString *bundlePath) {
 VZViewController *controller=(id)UIApplication.sharedApplication.keyWindow.rootViewController;
 if(!gVirtualMachine || ![controller.activeVMBundlePath.stringByStandardizingPath isEqualToString:bundlePath.stringByStandardizingPath])return VZL(@"Virtual Mac is off. Settings apply at its next start.");
 if(VM27SSHChangingV3)return VZL(@"Applying SSH settings…");
 if(!VM27SSHCurrentV3.enabled)return VZL(@"SSH forwarding is off.");
 struct vm27_host_ssh_snapshot_v1 snapshot={0};
 if(!gIndependent27SSHBridge || [gIndependent27SSHBridge copySnapshot:&snapshot] || snapshot.stopped || snapshot.error)
  return VZL(@"SSH listener is unavailable. Apply settings to retry.");
 return [NSString stringWithFormat:@"%@ %u · %@%@",VZL(@"Listening on port"),snapshot.tcp_port,
  snapshot.ready?VZL(@"Guest bridge connected"):VZL(@"Waiting for the guest agent."),
  (!snapshot.ready&&VM27SSHProvisionDetailV3.length)?[@"\n" stringByAppendingString:VM27SSHProvisionDetailV3]:@""];
}
void VZVMApplySSHSettingsV3(NSString *bundlePath,NSDictionary *options,void (^completion)(NSError *)) {
 if(!completion)return;
 if(!pthread_main_np()){dispatch_async(dispatch_get_main_queue(),^{completion(VM27SSHErrorV3(EPERM,VZL(@"SSH settings must be applied on the main queue.")));});return;}
 VM27SSHSettingsV3 requested;VZViewController *controller=(id)UIApplication.sharedApplication.keyWindow.rootViewController;
 NSInteger state=gVirtualMachine?((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state")):-1;
 if(!pthread_main_np() || !VM27SSHSettingsReadV3(options,&requested) || !gVirtualMachine ||
    (state!=1&&state!=2) || VM27SSHChangingV3 || gIndependent27OwnerClosePending ||
    ![controller.activeVMBundlePath.stringByStandardizingPath isEqualToString:bundlePath.stringByStandardizingPath]) {
  completion(VM27SSHErrorV3(EBUSY,VZL(@"SSH settings cannot be applied to this Virtual Mac right now.")));return;
 }
 VM27SSHChangingV3=YES;id vm=[gVirtualMachine retain];VM27SSHSettingsV3 previous=VM27SSHCurrentV3;
 VM27GenuineVZSSHBridgeV1 *prior=[gIndependent27SSHBridge retain];
 void (^finish)(NSError *)=^(NSError *error) {
  VM27SSHChangingV3=NO;
  if(VM27SSHDeferredStopV3) {
   VM27SSHDeferredStopV3=NO;NSError *stop=[VM27SSHDeferredErrorV3 autorelease];VM27SSHDeferredErrorV3=nil;
   [controller finishVMAndShowLibraryWithError:stop];
  }
  completion(error);[prior release];[vm release];
 };
 void (^replace)(NSError *)=^(NSError *closeError) {
  if(closeError || gIndependent27SSHBridge!=prior) {finish(closeError?:VM27SSHErrorV3(EIO,VZL(@"The SSH connection owner changed.")));return;}
  [gIndependent27SSHBridge release];gIndependent27SSHBridge=nil;gIndependent27SSHStarted=NO;gIndependent27SSHRegisteredV18=NO;
  NSInteger current=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
  if(gVirtualMachine!=vm || (current!=1&&current!=2) || VM27SSHDeferredStopV3){finish(VM27SSHErrorV3(ECANCELED,VZL(@"The Virtual Mac stopped while applying SSH settings.")));return;}
  NSError *error=nil;
  if(!VM27SSHCreateCurrentV3(requested,&error)) {
   if(!gIndependent27SSHBridge) {
    NSError *restore=nil;VM27SSHCreateCurrentV3(previous,&restore);
    if(restore)error=VM27SSHErrorV3(error.code,[NSString stringWithFormat:@"%@\n%@",error.localizedDescription,restore.localizedDescription]);
   }
   finish(error?:VM27SSHErrorV3(EIO,VZL(@"The SSH listener could not be created.")));return;
  }
  VM27SSHCurrentV3=requested;VM27SSHProvisionAttemptsV3=0;
  fprintf(stderr,"[VirtualMacSSHV3] applied enabled=%u port=%u scope=%u families=%u authenticationRequired=1\n",requested.enabled,requested.port,requested.scope,requested.families);
  finish(nil);VM27SSHProvisionIfNeededV3();
 };
 if(prior)[prior closeWithCompletion:replace];else replace(nil);
}
