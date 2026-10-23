/* All operations use the real VZ VM queue. Saved guest memory is never logged. */
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
extern const uint8_t VM27IndependentRuntimeManifestSHA256V1[32];
static BOOL VM27HibernateBusyV4,VM27HibernateSupportedV4;
static id VM27HibernateVMV4,VM27HibernateConfigurationV4;
static NSString *VM27HibernateBundleV4;
static NSDictionary *VM27HibernateOptionsV4;
static UIBackgroundTaskIdentifier VM27HibernateBackgroundTaskV5;
static BOOL VM27HibernateBackgroundTaskReadyV5;
static uint64_t VM27HibernateBackgroundEpochV5;
static void VM27HibernateEndBackgroundV5(void) {
    if(!VM27HibernateBackgroundTaskReadyV5 || VM27HibernateBackgroundTaskV5==UIBackgroundTaskInvalid)return;
    UIBackgroundTaskIdentifier task=VM27HibernateBackgroundTaskV5;
    VM27HibernateBackgroundTaskV5=UIBackgroundTaskInvalid;
    [UIApplication.sharedApplication endBackgroundTask:task];
}
static void VM27HibernateFinishOperationV5(void) {
    VM27HibernateBusyV4=NO;
    [(VZHUDView *)gHUDView refreshMenu];
    VM27HibernateEndBackgroundV5();
}
static NSDictionary *VM27HibernateComparableOptionsV5(NSDictionary *options) {
    NSMutableDictionary *value=[[options mutableCopy]autorelease];
    [value removeObjectForKey:@"HibernateOnBackgroundEnabled"];
    return value;
}
static BOOL VM27HibernateOperationPendingV4(void) {return VM27HibernateBusyV4;}

#include "vm27_hibernate_store_v2.h"
#include "vm27_hibernate_runtime_compat_v7.h"
static BOOL VM27HibernateBackendAllowedV4(NSString *bundle,NSError **error) {
 if(VZIndependent27SourceRouteSelected())return YES;
 NSError *readError=nil;NSDictionary *record=VM27HibernateReadV4(bundle,&readError);
 if(!record && !readError)return YES;
 if(error)*error=readError?:VM27HibernateErrorV4(EINVAL,VZL(@"Resume or discard the saved macOS 27 hibernation state before using macOS 13."));
 return NO;
}
static void VM27HibernateUnbindV4(void) {
    VM27HibernateVMV4=nil;VM27HibernateSupportedV4=NO;VM27HibernateFinishOperationV5();
    [VM27HibernateConfigurationV4 release];VM27HibernateConfigurationV4=nil;
    [VM27HibernateBundleV4 release];VM27HibernateBundleV4=nil;
    [VM27HibernateOptionsV4 release];VM27HibernateOptionsV4=nil;
}
static void VM27HibernateBindV4(id vm,id configuration,NSString *bundle) {
    if(!VM27HibernateBackgroundTaskReadyV5){VM27HibernateBackgroundTaskV5=UIBackgroundTaskInvalid;VM27HibernateBackgroundTaskReadyV5=YES;}
    VM27HibernateUnbindV4();
    VM27HibernateVMV4=vm;VM27HibernateConfigurationV4=[configuration retain];
    VM27HibernateBundleV4=[bundle copy];VM27HibernateOptionsV4=[VZVMOptionsForBundle(bundle)copy];
    VM27HibernateSupportedV4=VM27HibernateNativeAdmissionV2(vm,configuration);
}
static void VM27HibernateReportV4(NSError *error) {
    fprintf(stderr,"[VM27HibernateV4] error domain=%s code=%ld detail=%s\n",error.domain.UTF8String,(long)error.code,error.description.UTF8String);
    setStatus(error.localizedDescription);
    if(UIApplication.sharedApplication.applicationState==UIApplicationStateActive)
        VZPresentFailureReport(UIApplication.sharedApplication.keyWindow.rootViewController,VZL(@"Hibernate"),
            error.localizedDescription,error.debugDescription,VZFailureSupportOptionNone);
}
static void VM27HibernateSavePausedV4(id vm,NSString *bundle,NSString *stage,BOOL wasRunning) {
    if(vm!=gVirtualMachine || ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))!=2) {
        VM27HibernateFinishOperationV5();[vm release];return;
    }
    NSURL *url=fileURL([stage stringByAppendingPathComponent:@"State.vzvmsave"]);
    NSDictionary *savedOptions=VM27HibernateComparableOptionsV5(VM27HibernateOptionsV4);
    fprintf(stderr,"[VM27HibernateV4] stage=save-submit nativeState=2\n");
    ((void(*)(id,SEL,id,id))objc_msgSend)(vm,S("saveMachineStateToURL:completionHandler:"),url,^(NSError *saveError){
        dispatch_async(dispatch_get_main_queue(),^{
            NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
            fprintf(stderr,"[VM27HibernateV4] stage=save-complete nativeState=%ld error=%s\n",(long)state,saveError.description.UTF8String?:"none");
            NSString *statePath=url.path;
            if(saveError || vm!=gVirtualMachine || state!=2) {
                VM27HibernateFinishOperationV5();
                if(VM27HibernateOwnedV4(stage,YES)) {unlink(statePath.fileSystemRepresentation);rmdir(stage.fileSystemRepresentation);}
                if(wasRunning && vm==gVirtualMachine && state==2)VZIndependent27RequestVMStateV44(YES);
                VM27HibernateReportV4(saveError?:VM27HibernateErrorV4(EPROTO,VZL(@"The VM changed state while saving.")));[vm release];return;
            }
            int fd=open(statePath.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            struct stat saved={0};BOOL durable=fd>=0 && !fstat(fd,&saved) && S_ISREG(saved.st_mode) &&
                saved.st_uid==getuid() && saved.st_nlink==1 && saved.st_size>0 && !fchmod(fd,0600) && !fsync(fd);
            if(fd>=0)close(fd);
            durable=durable && VM27HibernateSyncDirectoryV5(stage);
            if(!durable) {
                VM27HibernateFinishOperationV5();
                if(wasRunning)VZIndependent27RequestVMStateV44(YES);
                VM27HibernateReportV4(VM27HibernateErrorV4(EIO,VZL(@"The hibernation file could not be committed.")));[vm release];return;
            }
            ((void(*)(id,SEL,id))objc_msgSend)(vm,S("stopWithCompletionHandler:"),^(NSError *stopError){
                dispatch_async(dispatch_get_main_queue(),^{
                    BOOL stopped=vm==gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))==0;
                    NSDictionary *disk=VM27HibernateDiskV4(bundle);NSData *identity=VM27HibernateIdentityV4(bundle);
                    NSDictionary *record=(!stopError && stopped && disk && identity)?@{@"Version":@1,
                        @"Generation":stage.lastPathComponent,@"Options":savedOptions,
                        @"RuntimeDigest":[NSData dataWithBytes:VM27IndependentRuntimeManifestSHA256V1 length:32],
                        @"MachineIdentity":identity,@"DiskIdentity":disk,@"SavedAt":NSDate.date,@"StateBytes":@(saved.st_size)}:nil;
                    NSString *root=stage.stringByDeletingLastPathComponent;
                    NSString *pending=[root stringByAppendingPathComponent:@"Commit.plist"];
                    BOOL committed=record && [record writeToFile:pending atomically:NO] && !chmod(pending.fileSystemRepresentation,0600);
                    int metadata=committed?open(pending.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC):-1;
                    committed=metadata>=0 && !fsync(metadata);if(metadata>=0)close(metadata);
                    if(committed)committed=!rename(pending.fileSystemRepresentation,[[root stringByAppendingPathComponent:@"Current.plist"]fileSystemRepresentation]);
                    if(committed)committed=VM27HibernateSyncDirectoryV5(root);
                    if(committed)[NSUserDefaults.standardUserDefaults setObject:bundle forKey:@"VM27LastHibernateBundleV5"];
                    VM27HibernateFinishOperationV5();
                    fprintf(stderr,"[VM27HibernateV4] stage=stop-and-commit stopped=%d committed=%d bytes=%lld error=%s\n",stopped,committed,(long long)saved.st_size,stopError.description.UTF8String?:"none");
                    if(!committed)VM27HibernateReportV4(stopError?:VM27HibernateErrorV4(EIO,VZL(@"The saved state was not committed. The partial file has been retained.")));
                    if(!stopped && wasRunning && vm==gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))==2)VZIndependent27RequestVMStateV44(YES);
                    if(stopped)finishVMThreadSafe(gVirtualMachineDelegate,nil);
                    [vm release];
                });
            });
        });
    });
}
static void VM27HibernateAwaitPauseV4(id vm,NSString *bundle,NSString *stage,BOOL wasRunning,unsigned budget) {
    if(vm!=gVirtualMachine){VM27HibernateFinishOperationV5();[vm release];return;}
    NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
    if(!gIndependent27VMStateTransitionPendingV44 && state==2) {VM27HibernateSavePausedV4(vm,bundle,stage,wasRunning);return;}
    if(!budget || (!gIndependent27VMStateTransitionPendingV44 && state!=1)) {
        VM27HibernateFinishOperationV5();
        VM27HibernateReportV4(VM27HibernateErrorV4(EBUSY,VZL(@"The VM could not pause for hibernation.")));[vm release];return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),dispatch_get_main_queue(),^{
        VM27HibernateAwaitPauseV4(vm,bundle,stage,wasRunning,budget-1);
    });
}
static BOOL VM27HibernateRequestV4(void) {
    if(!pthread_main_np() || !VM27HibernateSupportedV4 || VM27HibernateBusyV4 ||
        !gVirtualMachine || VM27HibernateVMV4!=gVirtualMachine || gIndependent27VMStateTransitionPendingV44 ||
        gIndependent27OwnerClosePending || gIndependent27InputClosePending)return NO;
    id vm=gVirtualMachine;NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
    if(state!=1 && state!=2)return NO;
    NSString *bundle=[[VM27HibernateBundleV4 copy]autorelease];NSError *error=nil;
    if(VM27HibernateReadV4(bundle,&error)||error){VM27HibernateReportV4(error?:VM27HibernateErrorV4(EEXIST,VZL(@"A hibernation state already exists.")));return NO;}
    NSDictionary *space=[NSFileManager.defaultManager attributesOfFileSystemForPath:bundle error:&error];
    uint64_t memory=((uint64_t(*)(id,SEL))objc_msgSend)(VM27HibernateConfigurationV4,S("memorySize"));
    if(!space || [space[NSFileSystemFreeSize]unsignedLongLongValue]<memory+(256ULL<<20)) {
        VM27HibernateReportV4(error?:VM27HibernateErrorV4(ENOSPC,VZL(@"Not enough free space to save the VM memory.")));return NO;
    }
    NSString *root=VM27HibernateRootV4(bundle);
    if(mkdir(root.fileSystemRepresentation,0700) && errno!=EEXIST)return NO;
    if(!VM27HibernateOwnedV4(root,YES))return NO;
    NSString *stage=[root stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    if(mkdir(stage.fileSystemRepresentation,0700))return NO;
    if(state==1 && !VZIndependent27RequestVMStateV44(NO)){rmdir(stage.fileSystemRepresentation);return NO;}
    VM27HibernateBusyV4=YES;[vm retain];[(VZHUDView *)gHUDView refreshMenu];
    setStatus(VZL(@"Saving virtual machine state…"));
    VM27HibernateAwaitPauseV4(vm,bundle,stage,state==1,300);
    return YES;
}
static BOOL VM27HibernateRestoreV4(id vm,NSString *bundle,void (^started)(NSError *)) {
    NSError *error=nil;NSDictionary *record=VM27HibernateReadV4(bundle,&error);
    if(!record && !error)return NO;
    NSData *runtime=[NSData dataWithBytes:VM27IndependentRuntimeManifestSHA256V1 length:32];
    if(!record || !VM27HibernateSupportedV4 || ![VM27HibernateComparableOptionsV5(record[@"Options"])isEqual:VM27HibernateComparableOptionsV5(VM27HibernateOptionsV4)] ||
       !VM27HibernateRuntimeMatchesV4(record[@"RuntimeDigest"],runtime) || ![record[@"MachineIdentity"]isEqual:VM27HibernateIdentityV4(bundle)] ||
       ![record[@"DiskIdentity"]isEqual:VM27HibernateDiskV4(bundle)]) {
        started(error?:VM27HibernateErrorV4(EINVAL,VZL(@"The saved VM configuration, disk or runtime has changed. The hibernation file was retained.")));return YES;
    }
    VM27HibernateBusyV4=YES;
    NSString *path=[[VM27HibernateRootV4(bundle)stringByAppendingPathComponent:record[@"Generation"]]stringByAppendingPathComponent:@"State.vzvmsave"];
    setStatus(VZL(@"Restoring virtual machine state…"));
    fprintf(stderr,"[VM27HibernateV4] stage=restore-submit savedBytes=%llu\n",[record[@"StateBytes"]unsignedLongLongValue]);
    ((void(*)(id,SEL,id,id))objc_msgSend)(vm,S("restoreMachineStateFromURL:completionHandler:"),fileURL(path),^(NSError *restoreError){
        dispatch_async(dispatch_get_main_queue(),^{
            NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
            fprintf(stderr,"[VM27HibernateV4] stage=restore-complete state=%ld error=%s\n",(long)state,restoreError.description.UTF8String?:"none");
            NSError *consumeError=nil;
            if(restoreError || vm!=gVirtualMachine || state!=2 || !VM27HibernateConsumeV4(bundle,record,&consumeError)) {
                VM27HibernateFinishOperationV5();started(restoreError?:consumeError?:VM27HibernateErrorV4(EPROTO,VZL(@"The VM could not restore its saved state.")));return;
            }
            if([[NSUserDefaults.standardUserDefaults stringForKey:@"VM27LastHibernateBundleV5"]isEqual:bundle])
                [NSUserDefaults.standardUserDefaults removeObjectForKey:@"VM27LastHibernateBundleV5"];
            ((void(*)(id,SEL,id))objc_msgSend)(vm,S("resumeWithCompletionHandler:"),^(NSError *resumeError){
                dispatch_async(dispatch_get_main_queue(),^{VM27HibernateFinishOperationV5();started(resumeError);});
            });
        });
    });
    return YES;
}

/* A completed save survives process death. A SIGKILL before completion cannot
 * run a final save; partial generations are never published as Current.plist. */
static void VM27HibernateTryBackgroundV5(uint64_t epoch,id owner,unsigned retries) {
    VM27LockObserveV1();
    if(epoch!=VM27HibernateBackgroundEpochV5 || owner!=gVirtualMachine ||
       UIApplication.sharedApplication.applicationState!=UIApplicationStateBackground ||
       VM27LockNotifyTokenV1<0 || VM27LockPolicyV1.locked ||
       !UIApplication.sharedApplication.protectedDataAvailable) {
        if(!VM27HibernateBusyV4)VM27HibernateEndBackgroundV5();
        fprintf(stderr,"[VM27HibernateBackgroundV5] skipped=1 locked=%u protectedData=%u sameOwner=%u\n",VM27LockPolicyV1.locked,UIApplication.sharedApplication.protectedDataAvailable,owner==gVirtualMachine);
        return;
    }
    if((gIndependent27VMStateTransitionPendingV44 || gIndependent27InputClosePending) && retries) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),dispatch_get_main_queue(),^{VM27HibernateTryBackgroundV5(epoch,owner,retries-1);});return;
    }
    BOOL accepted=VM27HibernateRequestV4();
    fprintf(stderr,"[VM27HibernateBackgroundV5] saveRequested=%u completedSaveRequiredBeforeKill=1\n",accepted);
    if(!accepted && !VM27HibernateBusyV4)VM27HibernateEndBackgroundV5();
}
static void VM27HibernateDidBackgroundV5(void) {
    if(!VZIndependent27SourceRouteSelected() || !VM27HibernateSupportedV4 ||
       !gVirtualMachine || VM27HibernateBusyV4 ||
       ![VM27HibernateOptionsV4[@"HibernateOnBackgroundEnabled"]boolValue])return;
    uint64_t epoch=++VM27HibernateBackgroundEpochV5;id owner=gVirtualMachine;
    if(VM27HibernateBackgroundTaskV5==UIBackgroundTaskInvalid)
        VM27HibernateBackgroundTaskV5=[UIApplication.sharedApplication beginBackgroundTaskWithName:@"Save Virtual Mac session" expirationHandler:^{
            fprintf(stderr,"[VM27HibernateBackgroundV5] backgroundTimeExpired=1 savePending=%u completedStateOnly=1\n",VM27HibernateBusyV4);
            VM27HibernateEndBackgroundV5();
        }];
    if(VM27HibernateBackgroundTaskV5==UIBackgroundTaskInvalid)return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,750*NSEC_PER_MSEC),dispatch_get_main_queue(),^{VM27HibernateTryBackgroundV5(epoch,owner,15);});
}
static void VM27HibernateBecameActiveV5(void) {
    ++VM27HibernateBackgroundEpochV5;
    if(!VM27HibernateBusyV4)VM27HibernateEndBackgroundV5();
}
static NSString *VM27HibernateAutoResumeBundleV5(void) {
    if(!VZIndependent27SourceRouteSelected())return nil;
    NSString *bundle=[NSUserDefaults.standardUserDefaults stringForKey:@"VM27LastHibernateBundleV5"];
    NSString *root=[VZVMLibraryPath().stringByStandardizingPath stringByAppendingString:@"/"];
    if(![bundle.stringByStandardizingPath hasPrefix:root] || !VZIsValidVMBundle(bundle))return nil;
    NSError *error=nil;return VM27HibernateReadV4(bundle,&error)?bundle:nil;
}
BOOL VM27HasSavedSessionV5(NSString *bundle) {
    NSString *path=[VM27HibernateRootV4(bundle)stringByAppendingPathComponent:@"Current.plist"];
    return VM27HibernateOwnedV4(path,NO);
}
BOOL VM27DiscardSavedSessionV5(NSString *bundle,NSError **error) {
    if(!pthread_main_np() || VM27HibernateBusyV4 ||
       (gVirtualMachine && [bundle isEqual:VM27HibernateBundleV4]))return NO;
    NSDictionary *record=VM27HibernateReadV4(bundle,error);
    if(!record || !VM27HibernateConsumeV4(bundle,record,error))return NO;
    if([[NSUserDefaults.standardUserDefaults stringForKey:@"VM27LastHibernateBundleV5"]isEqual:bundle])
        [NSUserDefaults.standardUserDefaults removeObjectForKey:@"VM27LastHibernateBundleV5"];
    return YES;
}
