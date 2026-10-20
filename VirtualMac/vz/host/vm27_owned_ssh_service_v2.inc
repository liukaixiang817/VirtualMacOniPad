/* New fixed guest job lifetime. The old bounded diagnostic remains separate.
 * This include follows the exact signed-resource reader and actual QGA APIs. */
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include "vm27_owned_ssh_service_scripts_v2.inc"

typedef NS_ENUM(unsigned,VM27SSHServiceStateV2) {
    VM27SSHServiceWaitingV2=1,VM27SSHServiceInstallingV2,
    VM27SSHServiceRunningV2,VM27SSHServiceStoppingV2,VM27SSHServiceUnresolvedV2
};
@interface VM27OwnedSSHServiceV2 : NSObject {
@public id _vm,_connection;
    NSData *_artifact;
    void (^_startCompletion)(BOOL,NSData *);
    VM27SSHServiceStateV2 _state;
    uint64_t _readyDeadline,_epoch,_generation;
    int _originalFD;
    dev_t _socketDevice;
    ino_t _socketInode;
    pid_t _hostPID;
    uint32_t _guestPID,_guestUID;
    NSString *_guestStart;
    BOOL _remoteMayExist;
}
@end
@implementation VM27OwnedSSHServiceV2
- (void)dealloc {
    [_vm release];[_connection release];[_artifact release];
    [_startCompletion release];[_guestStart release];[super dealloc];
}
@end
static VM27OwnedSSHServiceV2 *gGuestOwnedSSHServiceV2;
static NSHashTable *gGuestAttachedVMsV2;
static uint64_t VM27SSHMonotonicV2(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now) || now.tv_sec<0)return 0;
    return (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
}
static NSData *VM27SSHMessageV2(NSString *message) {
    return [message dataUsingEncoding:NSUTF8StringEncoding];
}
static void VM27SSHCompleteMainV2(void (^completion)(BOOL,NSData *),BOOL ok,NSData *output) {
    if(completion)dispatch_async(dispatch_get_main_queue(),^{completion(ok,output ?: [NSData data]);});
}
static BOOL VM27SSHRoleV2(void) {
    const char *version=getenv("VZ_PVG_BACKEND_VERSION");
    return version && !strcmp(version,"27") && getuid()==501 && geteuid()==501 &&
        [NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.mac.virtual.independent27"];
}
static const void *VM27SSHInspectIMPV2(IMP value) {
#if __has_feature(ptrauth_calls)
    return ptrauth_strip((const void *)value,ptrauth_key_function_pointer);
#else
    return (const void *)value;
#endif
}
static const char VM27SSHOriginalVZPathV2[]="/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/parent-flat/VZ27.dylib";
static BOOL VM27SSHOriginalIMPOnMainV2(id vm,const char *selectorName,IMP *out) {
    if(!pthread_main_np() || !vm || !out)return NO;
    Class original=objc_getClass("VZVirtualMachine");
    const char *image=original?class_getImageName(original):NULL;
    if(!image || strcmp(image,VM27SSHOriginalVZPathV2) || ![vm isKindOfClass:original])return NO;
    SEL queueSelector=sel_registerName("queue");
    IMP queueIMP=class_getMethodImplementation(original,queueSelector);
    Dl_info queueInfo={0};
    if(!queueIMP || !dladdr(VM27SSHInspectIMPV2(queueIMP),&queueInfo) || !queueInfo.dli_fname ||
       strcmp(queueInfo.dli_fname,VM27SSHOriginalVZPathV2) ||
       class_getMethodImplementation(object_getClass(vm),queueSelector)!=queueIMP ||
       ((dispatch_queue_t(*)(id,SEL))queueIMP)(vm,queueSelector)!=dispatch_get_main_queue())return NO;
    SEL selector=sel_registerName(selectorName);IMP actual=class_getMethodImplementation(original,selector);
    Dl_info info={0};
    if(!actual || !dladdr(VM27SSHInspectIMPV2(actual),&info) || !info.dli_fname ||
       strcmp(info.dli_fname,VM27SSHOriginalVZPathV2) ||
       class_getMethodImplementation(object_getClass(vm),selector)!=actual)return NO;
    *out=actual;return YES;
}
static BOOL VM27SSHAttachedV2(id vm) {
    return vm && [gGuestAttachedVMsV2 containsObject:vm];
}
static BOOL VM27OwnedSSHServiceAttachGateV2(id vm) {
    __block BOOL admitted=NO;
    QGASyncV3(^{
        if(!vm || (gGuestOwnedSSHServiceV2 && gGuestOwnedSSHServiceV2->_vm!=vm)) {
            VZGuestToolsLog(@"owned SSH retains the earlier actual VM; another Attach is refused");return;
        }
        if(!gGuestAttachedVMsV2)gGuestAttachedVMsV2=[[NSHashTable weakObjectsHashTable] retain];
        [gGuestAttachedVMsV2 removeAllObjects];[gGuestAttachedVMsV2 addObject:vm];admitted=YES;
    });return admitted;
}
static void VM27SSHStartFinishedV2(VM27OwnedSSHServiceV2 *owner,BOOL success,NSData *output) {
    if(!owner || owner!=gGuestOwnedSSHServiceV2)return;
    [owner retain];
    void (^completion)(BOOL,NSData *)=[owner->_startCompletion copy];
    [owner->_startCompletion release];owner->_startCompletion=nil;
    if(!success) {
        if(owner->_remoteMayExist) {
            owner->_state=VM27SSHServiceUnresolvedV2;
            VZGuestToolsLog(@"owned SSH service state unresolved; actual VM owner retained; guestSSHAuthenticated=0");
        } else {gGuestOwnedSSHServiceV2=nil;[owner release];}
    }
    VM27SSHCompleteMainV2(completion,success,output);[completion release];[owner release];
}
static void VM27OwnedSSHServiceResetNoticeV2(void) {
    VM27OwnedSSHServiceV2 *owner=gGuestOwnedSSHServiceV2;if(!owner)return;
    if(owner->_state==VM27SSHServiceWaitingV2) {
        VM27SSHStartFinishedV2(owner,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_WAIT_CANCELLED noGuestServiceLaunch=1 guestSSHAuthenticated=0\n"));
    } else {
        owner->_state=VM27SSHServiceUnresolvedV2;
        VZGuestToolsLog(@"owned SSH QGA connection reset/replaced; captured service and actual VM stay retained");
    }
}
static BOOL VM27OwnedSSHServiceActiveV2(void) {return gGuestOwnedSSHServiceV2!=nil;}
static void VM27OwnedSSHServiceConnectionChangedV2(void) {
    VM27OwnedSSHServiceV2 *owner=gGuestOwnedSSHServiceV2;
    if(owner && owner->_state!=VM27SSHServiceWaitingV2) {
        owner->_state=VM27SSHServiceUnresolvedV2;
        VZGuestToolsLog(@"owned SSH actual QGA connection replaced; captured service/VM owner retained");
    }
}
static BOOL VM27SSHCaptureV2(VM27OwnedSSHServiceV2 *owner,NSData *output) {
    NSString *text=[[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] autorelease];
    if(!text || output.length>65536)return NO;
    unsigned count=0;uint32_t pid=0,uid=0;char start[65]={0},label[97]={0};
    for(NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if(![line hasPrefix:@"VM27_OWNED_SSH_SERVICE_CAPTURE "])continue;
        unsigned parsedPID=0,parsedUID=0;int used=0;char hash[65]={0},name[97]={0};
        int fields=sscanf(line.UTF8String,"VM27_OWNED_SSH_SERVICE_CAPTURE pid=%u uid=%u ppid=1 startSHA256=%64[0-9a-f] label=%96[^ ] guestSSHAuthenticated=0%n",
            &parsedPID,&parsedUID,hash,name,&used);
        if(fields!=4 || used<=0 || (size_t)used!=strlen(line.UTF8String) ||
           parsedPID<=1 || parsedPID>INT_MAX || !parsedUID || strlen(hash)!=64 || strcmp(name,VM27_OWNED_SSH_LABEL_V2))return NO;
        ++count;pid=parsedPID;uid=parsedUID;memcpy(start,hash,sizeof(start));memcpy(label,name,sizeof(label));
    }
    if(count!=1 || !pid || !uid || strcmp(label,VM27_OWNED_SSH_LABEL_V2))return NO;
    owner->_guestPID=pid;owner->_guestUID=uid;
    owner->_guestStart=[[NSString stringWithUTF8String:start] copy];return YES;
}
static BOOL VM27SSHCurrentConnectionV2(VM27OwnedSSHServiceV2 *owner) {
    struct stat st;
    return owner && owner->_hostPID==getpid() && VM27SSHAttachedV2(owner->_vm) &&
        owner->_connection==gGuestSocketConnection && owner->_epoch==gGuestConnectionEpochV3 &&
        owner->_generation==gGuestProvisioningGeneration && owner->_originalFD==gGuestWriteDescriptor &&
        gGuestReadDescriptor==gGuestWriteDescriptor && owner->_originalFD>=0 &&
        !fstat(owner->_originalFD,&st) && S_ISSOCK(st.st_mode) &&
        st.st_dev==owner->_socketDevice && st.st_ino==owner->_socketInode;
}
static void VM27SSHInstallV2(VM27OwnedSSHServiceV2 *owner) {
    VM27OwnedQGAOperationV5 *operation=BeginQGAOperationV3(^(BOOL success,NSData *output){
        if(success && owner==gGuestOwnedSSHServiceV2 && VM27SSHCurrentConnectionV2(owner) && VM27SSHCaptureV2(owner,output)) {
            owner->_state=VM27SSHServiceRunningV2;
            VM27SSHStartFinishedV2(owner,YES,output);
        } else {
            VM27SSHStartFinishedV2(owner,NO,output.length?output:VM27SSHMessageV2(@"VM27_OWNED_SSH_START_UNPROVEN capturedServiceOwnerRetained=1 guestSSHAuthenticated=0\n"));
        }
    });
    if(!operation)return;
    owner->_state=VM27SSHServiceInstallingV2;
    owner->_connection=[gGuestSocketConnection retain];owner->_epoch=gGuestConnectionEpochV3;
    owner->_generation=gGuestProvisioningGeneration;owner->_originalFD=gGuestWriteDescriptor;
    owner->_socketDevice=operation->_lease.device;owner->_socketInode=operation->_lease.inode;
    NSString *prepare=[NSString stringWithUTF8String:VM27OwnedSSHPrepareV2];
    OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",prepare],^(BOOL prepared,NSData *output) {
        if(![operation isLive])return;
        if(!prepared) {[operation finish:NO output:output];return;}
        NSString *pending=@"/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f/helper.pending";
        OwnedQGAWriteFileV3(operation,pending,owner->_artifact,^(BOOL uploaded) {
            if(![operation isLive])return;
            if(!uploaded) {[operation finish:NO output:VM27SSHMessageV2(@"VM27_OWNED_SSH_HELPER_UPLOAD_FAILED\n")];return;}
            NSData *plist=[NSData dataWithBytes:VM27OwnedSSHJobPlistV2 length:sizeof(VM27OwnedSSHJobPlistV2)-1];
            uint8_t digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(plist.bytes,(CC_LONG)plist.length,digest);
            char actual[65];for(unsigned i=0;i<32;i++)snprintf(actual+2*i,3,"%02x",digest[i]);
            if(strcmp(actual,VM27_OWNED_SSH_JOB_SHA256_V2)) {[operation finish:NO output:VM27SSHMessageV2(@"VM27_OWNED_SSH_FIXED_PLIST_HASH_REJECTED\n")];return;}
            NSString *jobPending=@"/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f/job.pending";
            OwnedQGAWriteFileV3(operation,jobPending,plist,^(BOOL written) {
                if(![operation isLive])return;
                if(!written) {[operation finish:NO output:VM27SSHMessageV2(@"VM27_OWNED_SSH_PLIST_UPLOAD_FAILED\n")];return;}
                /* Once this real request is sent, guest launch may have occurred
                 * even if its reply is lost. Keep the service/VM on uncertainty. */
                owner->_remoteMayExist=YES;
                NSString *install=[NSString stringWithUTF8String:VM27OwnedSSHInstallStartV2];
                OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",install],^(BOOL started,NSData *result){
                    if([operation isLive])[operation finish:started output:result];
                });
            });
        });
    });
}
static void VM27SSHReadyTryV2(VM27OwnedSSHServiceV2 *owner) {
    if(owner!=gGuestOwnedSSHServiceV2 || owner->_state!=VM27SSHServiceWaitingV2)return;
    uint64_t now=VM27SSHMonotonicV2();
    if(!now || now>=owner->_readyDeadline || !VM27SSHAttachedV2(owner->_vm)) {
        VM27SSHStartFinishedV2(owner,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_QGA_READY_WAIT_FAILED noGuestServiceLaunch=1 guestSSHAuthenticated=0\n"));return;
    }
    if(gGuestProvisioningStarted && gGuestSocketConnection && gGuestReadDescriptor>=0 &&
       gGuestWriteDescriptor==gGuestReadDescriptor && !gGuestOwnedOperationV3 && !gGuestCallbacks.count) {
        VM27SSHInstallV2(owner);return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,200*NSEC_PER_MSEC),QGAQueueV3(),^{VM27SSHReadyTryV2(owner);});
}
static void VM27OwnedSSHServiceReadyV2(void) {
    VM27OwnedSSHServiceV2 *owner=gGuestOwnedSSHServiceV2;
    if(owner && owner->_state==VM27SSHServiceWaitingV2)
        dispatch_async(QGAQueueV3(),^{VM27SSHReadyTryV2(owner);});
}
void VZGuestToolsStartOwnedSSHServiceV2(id actualVM,void (^completion)(BOOL,NSData *)) {
    if(!completion)return;
    IMP nativeState=NULL;
    if(!VM27SSHOriginalIMPOnMainV2(actualVM,"state",&nativeState) ||
       ((NSInteger(*)(id,SEL))nativeState)(actualVM,sel_registerName("state"))!=1) {
        VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_START_REJECTED actualOriginalVMRunningOnMainQueueRequired=1 noGuestRequestSent=1\n"));return;
    }
    dispatch_async(QGAQueueV3(),^{
        uint64_t now=VM27SSHMonotonicV2();
        if(!VM27SSHRoleV2() || !actualVM || !VM27SSHAttachedV2(actualVM) || !now ||
           now>UINT64_MAX-UINT64_C(120000000000) || gGuestOwnedSSHServiceV2 || gGuestCleanupUnresolvedV5 ||
           gGuestActiveSSHAttemptGenerationV1!=UINT64_MAX) {
            VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_START_REJECTED actualAttachedVMOrExclusiveOwnerUnavailable=1 guestSSHAuthenticated=0\n"));return;
        }
        NSData *artifact=VM27ReadSignedGuestActiveSSHResourceV1();
        if(!artifact) {VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_RESOURCE_REJECTED noGuestRequestSent=1\n"));return;}
        VM27OwnedSSHServiceV2 *owner=[VM27OwnedSSHServiceV2 new];
        owner->_vm=[actualVM retain];owner->_artifact=[artifact retain];owner->_startCompletion=[completion copy];
        owner->_hostPID=getpid();owner->_state=VM27SSHServiceWaitingV2;owner->_readyDeadline=now+UINT64_C(120000000000);
        owner->_originalFD=-1;gGuestOwnedSSHServiceV2=owner;
        if(gGuestReadDescriptor>=0 && !gGuestProvisioningStarted)
            dispatch_async(QGAQueueV3(),^{VZGuestToolsProbeAgent(gGuestProvisioningGeneration,1);});
        VM27SSHReadyTryV2(owner);
    });
}
void VZGuestToolsStopOwnedSSHServiceV2(id actualVM,void (^completion)(BOOL,NSData *)) {
    if(!completion)return;
    dispatch_async(QGAQueueV3(),^{
        VM27OwnedSSHServiceV2 *owner=gGuestOwnedSSHServiceV2;
        if(!VM27SSHRoleV2() || !VM27SSHAttachedV2(actualVM) || (owner && owner->_vm!=actualVM)) {
            VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_STOP_REJECTED exactRetainedVMRequired=1\n"));return;
        }
        if(!owner) {
            VM27SSHCompleteMainV2(completion,YES,VM27SSHMessageV2(@"VM27_OWNED_SSH_STOP_NO_SERVICE_LEASE noGuestJobBootoutClaim=1\n"));return;
        }
        if(owner->_state==VM27SSHServiceWaitingV2) {
            VM27SSHStartFinishedV2(owner,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_WAIT_CANCELLED noGuestServiceLaunch=1\n"));
            VM27SSHCompleteMainV2(completion,YES,VM27SSHMessageV2(@"VM27_OWNED_SSH_STOP_NO_LAUNCH noGuestServiceLaunch=1\n"));return;
        }
        if(owner->_state!=VM27SSHServiceRunningV2 || !VM27SSHCurrentConnectionV2(owner) ||
           !owner->_guestPID || !owner->_guestUID || owner->_guestStart.length!=64 ||
           gGuestOwnedOperationV3 || gGuestCallbacks.count || gGuestCleanupUnresolvedV5) {
            owner->_state=VM27SSHServiceUnresolvedV2;
            VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_STOP_UNPROVEN capturedServiceAndActualVMRetained=1 noForeignSignalSent=1\n"));return;
        }
        owner->_state=VM27SSHServiceStoppingV2;
        NSString *stop=[NSString stringWithUTF8String:VM27OwnedSSHStopTemplateV2];
        stop=[stop stringByReplacingOccurrencesOfString:@"@PID@" withString:[NSString stringWithFormat:@"%u",owner->_guestPID]];
        stop=[stop stringByReplacingOccurrencesOfString:@"@UID@" withString:[NSString stringWithFormat:@"%u",owner->_guestUID]];
        stop=[stop stringByReplacingOccurrencesOfString:@"@START@" withString:owner->_guestStart];
        NSString *expected=[NSString stringWithFormat:@"VM27_OWNED_SSH_SERVICE_OFF pid=%u uid=%u startSHA256=%@ label=%s actualCapturedProcessOff=1 actualOwnJobOff=1\n",
            owner->_guestPID,owner->_guestUID,owner->_guestStart,VM27_OWNED_SSH_LABEL_V2];
        VM27OwnedQGAOperationV5 *operation=BeginQGAOperationV3(^(BOOL success,NSData *output){
            NSString *actual=[[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding] autorelease];
            if(success && owner==gGuestOwnedSSHServiceV2 && VM27SSHCurrentConnectionV2(owner) && [actual isEqualToString:expected]) {
                [owner retain];gGuestOwnedSSHServiceV2=nil;[owner release];
                VM27SSHCompleteMainV2(completion,YES,output);[owner release];
            } else {
                owner->_state=VM27SSHServiceUnresolvedV2;
                VM27SSHCompleteMainV2(completion,NO,output.length?output:VM27SSHMessageV2(@"VM27_OWNED_SSH_STOP_UNPROVEN capturedServiceAndActualVMRetained=1\n"));
            }
        });
        if(operation)OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",stop],^(BOOL stopped,NSData *result){if([operation isLive])[operation finish:stopped output:result];});
    });
}

void VZGuestToolsInvalidateOwnedSSHServiceAfterActualVMStopV2(id actualVM,void (^completion)(BOOL,NSData *)) {
    if(!completion)return;
    IMP nativeState=NULL;
    if(!VM27SSHRoleV2() || !VM27SSHOriginalIMPOnMainV2(actualVM,"state",&nativeState) ||
       ((NSInteger(*)(id,SEL))nativeState)(actualVM,sel_registerName("state"))!=0) {
        VM27SSHCompleteMainV2(completion,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_INVALIDATION_REJECTED actualOriginalNativeStoppedVMRequired=1 capturedServiceAndVMRetained=1\n"));return;
    }
    /* Main remains the actual VM.queue throughout this synchronous private
     * queue step, so a queued native restart cannot race the Stopped read. */
    __block BOOL ended=NO;
    QGASyncV3(^{
        VM27OwnedSSHServiceV2 *owner=gGuestOwnedSSHServiceV2;
        if(!VM27SSHAttachedV2(actualVM) || (owner && (owner->_vm!=actualVM || owner->_hostPID!=getpid())))return;
        if(!owner) {[gGuestAttachedVMsV2 removeObject:actualVM];ended=YES;return;}
        [owner retain];
        if(gGuestOwnedOperationV3)[gGuestOwnedOperationV3 cancel:@"original native VM is actually Stopped; guest runtime ended"];
        if(owner==gGuestOwnedSSHServiceV2 && owner->_startCompletion)
            VM27SSHStartFinishedV2(owner,NO,VM27SSHMessageV2(@"VM27_OWNED_SSH_START_CANCELLED guestRuntimeEnded=1 jobBootoutVerified=0\n"));
        if(owner==gGuestOwnedSSHServiceV2) {gGuestOwnedSSHServiceV2=nil;[owner release];}
        [gGuestAttachedVMsV2 removeObject:actualVM];ended=YES;[owner release];
    });
    VM27SSHCompleteMainV2(completion,ended,VM27SSHMessageV2(ended?
        @"VM27_OWNED_SSH_SERVICE_LEASE_INVALIDATED guestRuntimeEnded=1 actualNativeVMState=0 jobBootoutVerified=0 capturedPIDExitVerified=0 nativeQGACleanupNotFabricated=1\n":
        @"VM27_OWNED_SSH_INVALIDATION_REJECTED exactAttachedServiceVMRequired=1 capturedServiceAndVMRetained=1\n"));
}
