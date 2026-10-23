/* All operations use the real VZ VM queue. Saved guest memory is never logged. */
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
extern const uint8_t VM27IndependentRuntimeManifestSHA256V1[32];
static BOOL VM27HibernateBusyV3,VM27HibernateSupportedV3;
static id VM27HibernateVMV3,VM27HibernateConfigurationV3;
static NSString *VM27HibernateBundleV3;
static NSDictionary *VM27HibernateOptionsV3;
static BOOL VM27HibernateOperationPendingV3(void) {return VM27HibernateBusyV3;}

static NSError *VM27HibernateErrorV3(NSInteger code,NSString *reason) {
    return [NSError errorWithDomain:@"VirtualMac.Hibernate" code:code
        userInfo:@{NSLocalizedDescriptionKey:reason}];
}
static NSString *VM27HibernateRootV3(NSString *bundle) {
    return [bundle stringByAppendingPathComponent:@".VM27HibernateV1"];
}
static BOOL VM27HibernateOwnedV3(NSString *path,BOOL directory) {
    struct stat st;
    return !lstat(path.fileSystemRepresentation,&st) && st.st_uid==getuid() &&
        (directory?S_ISDIR(st.st_mode):(S_ISREG(st.st_mode)&&st.st_nlink==1)) &&
        !(st.st_mode&0077);
}
static NSDictionary *VM27HibernateDiskV3(NSString *bundle) {
    NSString *path=[bundle stringByAppendingPathComponent:@"Disk.img"];
    struct stat st;
    if(lstat(path.fileSystemRepresentation,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1)return nil;
    return @{@"device":@((uint64_t)st.st_dev),@"inode":@((uint64_t)st.st_ino),@"bytes":@((uint64_t)st.st_size),
        @"mtimeSeconds":@(st.st_mtimespec.tv_sec),@"mtimeNanos":@(st.st_mtimespec.tv_nsec)};
}
static NSData *VM27HibernateIdentityV3(NSString *bundle) {
    NSMutableData *data=[NSMutableData data];
    for(NSString *name in @[@"HardwareModel",@"MachineIdentifier"]) {
        NSData *part=[NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:name]];
        if(!part.length || part.length>1024*1024)return nil;
        uint64_t length=part.length;[data appendBytes:&length length:sizeof(length)];[data appendData:part];
    }
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,hash);
    return [NSData dataWithBytes:hash length:sizeof(hash)];
}
static NSDictionary *VM27HibernateReadV3(NSString *bundle,NSError **error) {
    NSString *root=VM27HibernateRootV3(bundle),*path=[root stringByAppendingPathComponent:@"Current.plist"];
    struct stat st;
    if(lstat(path.fileSystemRepresentation,&st)) {
        if(errno!=ENOENT && error)*error=VM27HibernateErrorV3(errno,VZL(@"The hibernation record could not be read."));
        return nil;
    }
    if(!VM27HibernateOwnedV3(root,YES)||!VM27HibernateOwnedV3(path,NO)||st.st_size>1024*1024) {
        if(error)*error=VM27HibernateErrorV3(EACCES,VZL(@"The hibernation record has an invalid owner or file type."));return nil;
    }
    NSDictionary *record=[NSDictionary dictionaryWithContentsOfFile:path];
    NSString *generation=[record isKindOfClass:NSDictionary.class]?record[@"Generation"]:nil;
    NSUUID *uuid=[generation isKindOfClass:NSString.class]?[[[NSUUID alloc]initWithUUIDString:generation]autorelease]:nil;
    NSString *stage=uuid?[root stringByAppendingPathComponent:uuid.UUIDString]:nil;
    if(![record[@"Version"]isEqual:@1]||![generation isEqual:uuid.UUIDString]||
       !VM27HibernateOwnedV3(stage,YES)||!VM27HibernateOwnedV3([stage stringByAppendingPathComponent:@"State.vzvmsave"],NO)) {
        if(error)*error=VM27HibernateErrorV3(EINVAL,VZL(@"The saved hibernation state is incomplete."));return nil;
    }
    return record;
}
static BOOL VM27HibernateConsumeV3(NSString *bundle,NSDictionary *record,NSError **error) {
    NSDictionary *current=VM27HibernateReadV3(bundle,error);
    if(!current || ![current isEqual:record])return NO;
    NSString *root=VM27HibernateRootV3(bundle);
    NSString *stage=[root stringByAppendingPathComponent:record[@"Generation"]];
    if(unlink([[root stringByAppendingPathComponent:@"Current.plist"]fileSystemRepresentation])) {
        if(error)*error=VM27HibernateErrorV3(errno,VZL(@"The restored state could not be marked as consumed."));return NO;
    }
    /* A native restore may still map this inode. Unlink preserves its mappings. */
    unlink([[stage stringByAppendingPathComponent:@"State.vzvmsave"]fileSystemRepresentation]);
    rmdir(stage.fileSystemRepresentation);
    return YES;
}
static void VM27HibernateUnbindV3(void) {
    VM27HibernateVMV3=nil;VM27HibernateSupportedV3=NO;VM27HibernateBusyV3=NO;
    [VM27HibernateConfigurationV3 release];VM27HibernateConfigurationV3=nil;
    [VM27HibernateBundleV3 release];VM27HibernateBundleV3=nil;
    [VM27HibernateOptionsV3 release];VM27HibernateOptionsV3=nil;
}
static void VM27HibernateBindV3(id vm,id configuration,NSString *bundle) {
    VM27HibernateUnbindV3();
    VM27HibernateVMV3=vm;VM27HibernateConfigurationV3=[configuration retain];
    VM27HibernateBundleV3=[bundle copy];VM27HibernateOptionsV3=[VZVMOptionsForBundle(bundle)copy];
    VM27HibernateSupportedV3=VM27HibernateNativeAdmissionV2(vm,configuration);
}
static void VM27HibernateReportV3(NSError *error) {
    fprintf(stderr,"[VM27HibernateV3] error domain=%s code=%ld detail=%s\n",error.domain.UTF8String,(long)error.code,error.description.UTF8String);
    setStatus(error.localizedDescription);
    if(UIApplication.sharedApplication.applicationState==UIApplicationStateActive)
        VZPresentFailureReport(UIApplication.sharedApplication.keyWindow.rootViewController,VZL(@"Hibernate"),
            error.localizedDescription,error.debugDescription,VZFailureSupportOptionNone);
}
static void VM27HibernateSavePausedV3(id vm,NSString *bundle,NSString *stage,BOOL wasRunning) {
    if(vm!=gVirtualMachine || ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))!=2) {
        VM27HibernateBusyV3=NO;[vm release];return;
    }
    NSURL *url=fileURL([stage stringByAppendingPathComponent:@"State.vzvmsave"]);
    NSDictionary *savedOptions=[[VM27HibernateOptionsV3 copy]autorelease];
    fprintf(stderr,"[VM27HibernateV3] stage=save-submit nativeState=2\n");
    ((void(*)(id,SEL,id,id))objc_msgSend)(vm,S("saveMachineStateToURL:completionHandler:"),url,^(NSError *saveError){
        dispatch_async(dispatch_get_main_queue(),^{
            NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
            fprintf(stderr,"[VM27HibernateV3] stage=save-complete nativeState=%ld error=%s\n",(long)state,saveError.description.UTF8String?:"none");
            NSString *statePath=url.path;
            if(saveError || vm!=gVirtualMachine || state!=2) {
                VM27HibernateBusyV3=NO;
                if(VM27HibernateOwnedV3(stage,YES)) {unlink(statePath.fileSystemRepresentation);rmdir(stage.fileSystemRepresentation);}
                if(wasRunning && vm==gVirtualMachine && state==2)VZIndependent27RequestVMStateV44(YES);
                VM27HibernateReportV3(saveError?:VM27HibernateErrorV3(EPROTO,VZL(@"The VM changed state while saving.")));[vm release];return;
            }
            int fd=open(statePath.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            struct stat saved={0};BOOL durable=fd>=0 && !fstat(fd,&saved) && S_ISREG(saved.st_mode) &&
                saved.st_uid==getuid() && saved.st_nlink==1 && saved.st_size>0 && !fchmod(fd,0600) && !fsync(fd);
            if(fd>=0)close(fd);
            if(!durable) {
                VM27HibernateBusyV3=NO;
                if(wasRunning)VZIndependent27RequestVMStateV44(YES);
                VM27HibernateReportV3(VM27HibernateErrorV3(EIO,VZL(@"The hibernation file could not be committed.")));[vm release];return;
            }
            ((void(*)(id,SEL,id))objc_msgSend)(vm,S("stopWithCompletionHandler:"),^(NSError *stopError){
                dispatch_async(dispatch_get_main_queue(),^{
                    BOOL stopped=vm==gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))==0;
                    NSDictionary *disk=VM27HibernateDiskV3(bundle);NSData *identity=VM27HibernateIdentityV3(bundle);
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
                    VM27HibernateBusyV3=NO;
                    fprintf(stderr,"[VM27HibernateV3] stage=stop-and-commit stopped=%d committed=%d bytes=%lld error=%s\n",stopped,committed,(long long)saved.st_size,stopError.description.UTF8String?:"none");
                    if(!committed)VM27HibernateReportV3(stopError?:VM27HibernateErrorV3(EIO,VZL(@"The saved state was not committed. The partial file has been retained.")));
                    if(!stopped && wasRunning && vm==gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))==2)VZIndependent27RequestVMStateV44(YES);
                    if(stopped)finishVMThreadSafe(gVirtualMachineDelegate,nil);
                    [vm release];
                });
            });
        });
    });
}
static void VM27HibernateAwaitPauseV3(id vm,NSString *bundle,NSString *stage,BOOL wasRunning,unsigned budget) {
    if(vm!=gVirtualMachine){VM27HibernateBusyV3=NO;[vm release];return;}
    NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
    if(!gIndependent27VMStateTransitionPendingV44 && state==2) {VM27HibernateSavePausedV3(vm,bundle,stage,wasRunning);return;}
    if(!budget || (!gIndependent27VMStateTransitionPendingV44 && state!=1)) {
        VM27HibernateBusyV3=NO;
        VM27HibernateReportV3(VM27HibernateErrorV3(EBUSY,VZL(@"The VM could not pause for hibernation.")));[vm release];return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),dispatch_get_main_queue(),^{
        VM27HibernateAwaitPauseV3(vm,bundle,stage,wasRunning,budget-1);
    });
}
static BOOL VM27HibernateRequestV3(void) {
    if(!pthread_main_np() || !VM27HibernateSupportedV3 || VM27HibernateBusyV3 ||
        !gVirtualMachine || VM27HibernateVMV3!=gVirtualMachine || gIndependent27VMStateTransitionPendingV44 ||
        gIndependent27OwnerClosePending || gIndependent27InputClosePending)return NO;
    id vm=gVirtualMachine;NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
    if(state!=1 && state!=2)return NO;
    NSString *bundle=[[VM27HibernateBundleV3 copy]autorelease];NSError *error=nil;
    if(VM27HibernateReadV3(bundle,&error)||error){VM27HibernateReportV3(error?:VM27HibernateErrorV3(EEXIST,VZL(@"A hibernation state already exists.")));return NO;}
    NSDictionary *space=[NSFileManager.defaultManager attributesOfFileSystemForPath:bundle error:&error];
    uint64_t memory=((uint64_t(*)(id,SEL))objc_msgSend)(VM27HibernateConfigurationV3,S("memorySize"));
    if(!space || [space[NSFileSystemFreeSize]unsignedLongLongValue]<memory+(256ULL<<20)) {
        VM27HibernateReportV3(error?:VM27HibernateErrorV3(ENOSPC,VZL(@"Not enough free space to save the VM memory.")));return NO;
    }
    NSString *root=VM27HibernateRootV3(bundle);
    if(mkdir(root.fileSystemRepresentation,0700) && errno!=EEXIST)return NO;
    if(!VM27HibernateOwnedV3(root,YES))return NO;
    NSString *stage=[root stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    if(mkdir(stage.fileSystemRepresentation,0700))return NO;
    if(state==1 && !VZIndependent27RequestVMStateV44(NO)){rmdir(stage.fileSystemRepresentation);return NO;}
    VM27HibernateBusyV3=YES;[vm retain];[(VZHUDView *)gHUDView refreshMenu];
    setStatus(VZL(@"Saving virtual machine state…"));
    VM27HibernateAwaitPauseV3(vm,bundle,stage,state==1,300);
    return YES;
}
static BOOL VM27HibernateRestoreV3(id vm,NSString *bundle,void (^started)(NSError *)) {
    NSError *error=nil;NSDictionary *record=VM27HibernateReadV3(bundle,&error);
    if(!record && !error)return NO;
    NSData *runtime=[NSData dataWithBytes:VM27IndependentRuntimeManifestSHA256V1 length:32];
    if(!record || !VM27HibernateSupportedV3 || ![record[@"Options"]isEqual:VM27HibernateOptionsV3] ||
       ![record[@"RuntimeDigest"]isEqual:runtime] || ![record[@"MachineIdentity"]isEqual:VM27HibernateIdentityV3(bundle)] ||
       ![record[@"DiskIdentity"]isEqual:VM27HibernateDiskV3(bundle)]) {
        started(error?:VM27HibernateErrorV3(EINVAL,VZL(@"The saved VM configuration, disk or runtime has changed. The hibernation file was retained.")));return YES;
    }
    VM27HibernateBusyV3=YES;
    NSString *path=[[VM27HibernateRootV3(bundle)stringByAppendingPathComponent:record[@"Generation"]]stringByAppendingPathComponent:@"State.vzvmsave"];
    setStatus(VZL(@"Restoring virtual machine state…"));
    fprintf(stderr,"[VM27HibernateV3] stage=restore-submit savedBytes=%llu\n",[record[@"StateBytes"]unsignedLongLongValue]);
    ((void(*)(id,SEL,id,id))objc_msgSend)(vm,S("restoreMachineStateFromURL:completionHandler:"),fileURL(path),^(NSError *restoreError){
        dispatch_async(dispatch_get_main_queue(),^{
            NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
            fprintf(stderr,"[VM27HibernateV3] stage=restore-complete state=%ld error=%s\n",(long)state,restoreError.description.UTF8String?:"none");
            NSError *consumeError=nil;
            if(restoreError || vm!=gVirtualMachine || state!=2 || !VM27HibernateConsumeV3(bundle,record,&consumeError)) {
                VM27HibernateBusyV3=NO;started(restoreError?:consumeError?:VM27HibernateErrorV3(EPROTO,VZL(@"The VM could not restore its saved state.")));return;
            }
            ((void(*)(id,SEL,id))objc_msgSend)(vm,S("resumeWithCompletionHandler:"),^(NSError *resumeError){
                dispatch_async(dispatch_get_main_queue(),^{VM27HibernateBusyV3=NO;started(resumeError);});
            });
        });
    });
    return YES;
}
