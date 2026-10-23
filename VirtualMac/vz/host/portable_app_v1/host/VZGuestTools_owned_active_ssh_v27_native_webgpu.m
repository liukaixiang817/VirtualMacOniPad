#import "VZGuestTools_owned_active_ssh_v7.h"
#include "vm27_owned_qga_connection_lease_v3.h"
#include "vm27_guest_active_ssh_artifact_v1.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>

#import <objc/message.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <unistd.h>

typedef void (^VZGuestAgentResponse)(NSDictionary *response);
typedef void (^VZGuestCommandCompletion)(BOOL success, NSData *output);

static NSMutableData *gGuestOutputBuffer;
static dispatch_source_t gGuestOutputSource;
static id gGuestSocketListener;
static id gGuestSocketDelegate;
static id gGuestSocketConnection;
static int gGuestReadDescriptor = -1;
static int gGuestWriteDescriptor = -1;
static uint64_t gGuestRequestIdentifier;
static NSMutableDictionary *gGuestCallbacks;
static BOOL gGuestProvisioningStarted;
static NSUInteger gGuestDiagnosticReads;
static BOOL gGuestToolsEnabled;
static BOOL gGuestOpenGLAccelerationEnabled;
static BOOL gGuestPencilSupportEnabled;
static BOOL gGuestRemovalPending;
static NSString *gGuestBundlePath;
static NSString *gGuestReadyToken;
static BOOL gGuestToolsAcknowledged;
static BOOL gGuestMenuRestartedForToken;
static uint64_t gGuestProvisioningGeneration;
static NSUInteger gGuestConnectionCount;

static void VZGuestToolsProbeAgent(uint64_t generation, NSUInteger attempt);
static BOOL VM27OwnedSSHServiceAttachGateV2(id vm);
static void VM27OwnedSSHServiceResetNoticeV2(void);
static void VM27OwnedSSHServiceReadyV2(void);
static void VM27OwnedSSHServiceConnectionChangedV2(void);
static BOOL VM27OwnedSSHServiceActiveV2(void);
#include "vm27_owned_qga_operation_v9partial.inc"

static void VZGuestToolsLog(NSString *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[[NSString alloc] initWithFormat:format
        arguments:arguments] autorelease];
    va_end(arguments);
    dprintf(STDERR_FILENO, "[GuestTools] %s\n", message.UTF8String ?: "");
}

static SEL S(const char *name)
{
    return sel_registerName(name);
}

static id New(const char *name)
{
    Class cls = objc_getClass(name);
    return cls ? ((id(*)(id, SEL))objc_msgSend)(cls, S("new")) : nil;
}

static void SetObject(id object, const char *selector, id value)
{
    if (object && [object respondsToSelector:S(selector)])
        ((void(*)(id, SEL, id))objc_msgSend)(object, S(selector), value);
}

static BOOL QGACloseCurrentSocketV3(NSString *reason)
{
    VM27OwnedQGAOperationV5 *owner=[gGuestOwnedOperationV3 retain];
    BOOL resolved=YES;
    if(owner) {
        [owner cancel:reason];resolved=owner->_cleanupResult==VM27QGAValidV3;[owner release];
    } else if(gGuestWriteDescriptor>=0) {
        VM27OwnedQGALeaseV3 lease;
        VM27QGAResultV3 made=VM27OwnedQGALeaseCreateV3(&lease,gGuestWriteDescriptor,gGuestConnectionEpochV3,gGuestProvisioningGeneration);
        if(made==VM27QGAValidV3)resolved=VM27OwnedQGALeaseCloseV3(&lease,true)==VM27QGAValidV3;
        else {if(lease.active)VM27OwnedQGALeaseCloseV3(&lease,false);resolved=NO;}
    }
    if(!resolved)gGuestCleanupUnresolvedV5=YES;
    if((!resolved || gGuestCleanupUnresolvedV5) && gGuestSocketConnection) {
        static NSMutableArray *retainedConnections;
        if(!retainedConnections)retainedConnections=[NSMutableArray new];
        [retainedConnections addObject:gGuestSocketConnection];
        VZGuestToolsLog(@"QGA native old socket cleanup unresolved; retained actual connection; owningNormalVMLifecycle=1");
    }
    gGuestReadDescriptor=-1;gGuestWriteDescriptor=-1;gGuestProvisioningStarted=NO;
    if(gGuestOutputSource)dispatch_source_cancel(gGuestOutputSource);
    return resolved && !gGuestCleanupUnresolvedV5;
}
static void VZGuestToolsReadOutput(uint64_t epoch,id connection,int originalFD,dispatch_source_t source)
{
    if(gGuestConnectionEpochV3!=epoch || gGuestSocketConnection!=connection ||
       gGuestReadDescriptor!=originalFD || gGuestOutputSource!=source || !OwnedQGAReadGateV3())return;
    VM27OwnedQGAOperationV5 *operation=gGuestOwnedOperationV3;
    VM27OwnedQGALeaseV3 idleLease={.ownedFD=-1,.originalFD=-1};
    if(!operation && VM27OwnedQGALeaseCreateV3(&idleLease,originalFD,epoch,gGuestProvisioningGeneration)!=VM27QGAValidV3) {
        if(idleLease.active)VM27OwnedQGALeaseCloseV3(&idleLease,false);
        QGACloseCurrentSocketV3(@"idle actual socket read lease unavailable");return;
    }
    int descriptor=operation?operation->_lease.ownedFD:idleLease.ownedFD;
    uint8_t bytes[4096];
    for(;;) {
        if(gGuestConnectionEpochV3!=epoch || gGuestSocketConnection!=connection || !OwnedQGAReadGateV3() ||
           (!operation && VM27OwnedQGALeaseCheckV3(&idleLease,originalFD,epoch,gGuestProvisioningGeneration)!=VM27QGAValidV3)) {
            if(idleLease.active)VM27OwnedQGALeaseCloseV3(&idleLease,false);return;
        }
        ssize_t count=recv(descriptor,bytes,sizeof(bytes),MSG_DONTWAIT);
        if(count>0) {
            if(!OwnedQGAReadGateV3() || (!operation && VM27OwnedQGALeaseCheckV3(&idleLease,originalFD,epoch,gGuestProvisioningGeneration)!=VM27QGAValidV3)) {
                if(idleLease.active)VM27OwnedQGALeaseCloseV3(&idleLease,false);return;
            }
            if(gGuestOutputBuffer.length>2097152-(NSUInteger)count){if(idleLease.active)VM27OwnedQGALeaseCloseV3(&idleLease,false);QGACloseCurrentSocketV3(@"actual response exceeds finite buffer");return;}
            [gGuestOutputBuffer appendBytes:bytes length:(NSUInteger)count];continue;
        }
        if(count<0 && errno==EINTR)continue;
        if(count==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)){if(idleLease.active)VM27OwnedQGALeaseCloseV3(&idleLease,false);QGACloseCurrentSocketV3(@"actual QGA EOF/native read failure");return;}
        break;
    }
    if(idleLease.active && VM27OwnedQGALeaseCloseV3(&idleLease,false)!=VM27QGAValidV3){QGACloseCurrentSocketV3(@"idle read lease cleanup unresolved");return;}
    for(;;) {
        if(gGuestConnectionEpochV3!=epoch || gGuestSocketConnection!=connection || !OwnedQGAReadGateV3())return;
        const uint8_t *raw=gGuestOutputBuffer.bytes;NSUInteger length=gGuestOutputBuffer.length;
        const uint8_t *newline=length?memchr(raw,'\n',length):NULL;if(!newline)break;
        NSUInteger amount=(NSUInteger)(newline-raw);NSData *line=[gGuestOutputBuffer subdataWithRange:NSMakeRange(0,amount)];
        [gGuestOutputBuffer replaceBytesInRange:NSMakeRange(0,amount+1) withBytes:NULL length:0];if(!line.length)continue;
        NSError *error=nil;id response=[NSJSONSerialization JSONObjectWithData:line options:0 error:&error];
        if(![response isKindOfClass:NSDictionary.class]) {QGACloseCurrentSocketV3(@"actual malformed QGA response");return;}
        id identifier=response[@"id"];
        if(identifier && ![identifier isKindOfClass:NSNumber.class]) {QGACloseCurrentSocketV3(@"actual response identifier malformed");return;}
        // AppleQEMUGuestAgent replies are untagged and ordered on one real port.
        // A retained exclusive operation admits only one request at a time.
        if(!identifier && gGuestCallbacks.count)identifier=[[gGuestCallbacks.allKeys sortedArrayUsingSelector:@selector(compare:)] firstObject];
        VZGuestAgentResponse callback=[[gGuestCallbacks objectForKey:identifier] copy];
        if(identifier)[gGuestCallbacks removeObjectForKey:identifier];
        if(callback){callback(response);[callback release];}
        else if(gGuestOwnedOperationV3){QGACloseCurrentSocketV3(@"actual response has no owned request identifier");return;}
        else if(response[@"error"])VZGuestToolsLog(@"unsolicited actual QGA error: %@",response[@"error"]);
    }
}

static BOOL VZGuestToolsSend(NSString *command,NSDictionary *arguments,VZGuestAgentResponse callback)
{
    __block BOOL sent=NO;
    QGASyncV3(^{
        VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){
            (void)output;if(!success && callback)callback(@{@"error":@{@"class":@"VM27OwnedQGACancelled",@"desc":@"actual QGA operation unavailable or cancelled"}});
        });
        if(!owner)return;
        sent=OwnedQGASendV3(owner,command,arguments,^(NSDictionary *response){
            if(![owner isLive])return;[owner finish:YES output:[NSData data]];if(callback)callback(response);
        });
    });return sent;
}

void VZGuestToolsReset(void)
{
    QGASyncV3(^{
    VM27OwnedSSHServiceResetNoticeV2();
    QGACloseCurrentSocketV3(@"explicit existing GuestTools reset");
    if(gGuestConnectionEpochV3!=UINT64_MAX)++gGuestConnectionEpochV3;else gGuestConnectionEpochV3=UINT64_MAX;
    if(gGuestProvisioningGeneration!=UINT64_MAX)++gGuestProvisioningGeneration;
    if (gGuestOutputSource) {
        dispatch_source_cancel(gGuestOutputSource);
        dispatch_release(gGuestOutputSource);
        gGuestOutputSource = NULL;
    }
    [gGuestSocketConnection release];
    gGuestSocketConnection = nil;
    /* Reset owns only the old connection. Keep the actual registered listener
     * and its delegate available for this VM to reconnect; next Attach replaces
     * these references, while the caller still owns normal VM stop/release. */
    gGuestReadDescriptor = -1;
    gGuestWriteDescriptor = -1;
    [gGuestOutputBuffer release];
    gGuestOutputBuffer = nil;
    [gGuestCallbacks release];
    gGuestCallbacks = nil;
    gGuestRequestIdentifier = 0;
    gGuestProvisioningStarted = NO;
    gGuestDiagnosticReads = 0;
    gGuestConnectionCount = 0;
    [gGuestBundlePath release];
    gGuestBundlePath = nil;
    [gGuestReadyToken release];
    gGuestReadyToken = nil;
    gGuestToolsAcknowledged = NO;
    gGuestMenuRestartedForToken = NO;
    });
}

BOOL VZGuestToolsConfigureDevice(id configuration)
{
    VZGuestToolsReset();
    id device = New("VZVirtioSocketDeviceConfiguration");
    if (!device) {
        VZGuestToolsLog(@"virtio socket configuration unavailable");
        return NO;
    }
    SetObject(configuration, "setSocketDevices:", @[device]);
    VZGuestToolsLog(@"configured Apple guest agent socket device");
    [device release];
    return YES;
}

static BOOL VZGuestToolsAcceptConnection(id connection)
{
    if(!connection || ![connection respondsToSelector:S("fileDescriptor")])return NO;
    __block BOOL admitted=NO;
    QGASyncV3(^{
        int descriptor=((int(*)(id,SEL))objc_msgSend)(connection,S("fileDescriptor"));
        if(descriptor<0 || gGuestCleanupUnresolvedV5 || gGuestConnectionEpochV3==UINT64_MAX || gGuestProvisioningGeneration==UINT64_MAX) {
            VZGuestToolsLog(@"actual QGA connection/identity cannot be admitted");return;
        }
        VM27OwnedSSHServiceConnectionChangedV2();
        BOOL closed=QGACloseCurrentSocketV3(@"actual SDK QGA connection replaced");
        /* Cancel may itself advance both counters. Never wrap an exhausted
         * identity or admit while old native cleanup remains unresolved. */
        if(!closed || gGuestConnectionEpochV3==UINT64_MAX || gGuestProvisioningGeneration==UINT64_MAX) {
            VZGuestToolsLog(@"actual QGA replacement refused after old cleanup; retained normal VM ownership");return;
        }
        ++gGuestConnectionEpochV3;++gGuestProvisioningGeneration;BOOL reconnected=gGuestConnectionCount++>0;
        if(gGuestOutputSource){dispatch_source_cancel(gGuestOutputSource);dispatch_release(gGuestOutputSource);gGuestOutputSource=NULL;}
        [gGuestSocketConnection release];gGuestSocketConnection=[connection retain];
        gGuestReadDescriptor=descriptor;gGuestWriteDescriptor=descriptor;
        [gGuestOutputBuffer release];gGuestOutputBuffer=[NSMutableData new];
        [gGuestCallbacks release];gGuestCallbacks=[NSMutableDictionary new];gGuestRequestIdentifier=0;
        gGuestProvisioningStarted=NO;gGuestDiagnosticReads=0;gGuestToolsAcknowledged=NO;gGuestMenuRestartedForToken=NO;
        if(reconnected && (gGuestToolsEnabled || gGuestRemovalPending)) {
            [gGuestReadyToken release];gGuestReadyToken=[NSUUID.UUID.UUIDString copy];
        }
        dispatch_source_t source=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)descriptor,0,QGAQueueV3());
        if(!source){QGACloseCurrentSocketV3(@"actual read source creation failed");return;}
        gGuestOutputSource=source;uint64_t epoch=gGuestConnectionEpochV3;
        dispatch_source_set_event_handler(source,^{VZGuestToolsReadOutput(epoch,connection,descriptor,source);});
        dispatch_resume(source);admitted=YES;
        VZGuestToolsLog(@"Apple guest agent %@ accepted; actual QGA epoch=%llu",reconnected?@"reconnection":@"connection",(unsigned long long)epoch);
        uint64_t generation=gGuestProvisioningGeneration;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),QGAQueueV3(),^{VZGuestToolsProbeAgent(generation,1);});
    });return admitted;
}

@interface VZGuestSocketListenerDelegate : NSObject
@end

@implementation VZGuestSocketListenerDelegate
- (BOOL)listener:(id)listener shouldAcceptNewConnection:(id)connection
 fromSocketDevice:(id)socketDevice
{
    (void)listener;
    (void)socketDevice;
    __block BOOL accepted=NO;
    QGASyncV3(^{if(self==gGuestSocketDelegate)accepted=VZGuestToolsAcceptConnection(connection);});
    return accepted;
}
@end

static void VZGuestToolsAttachOnCurrentThread(id virtualMachine)
{
    VZGuestToolsLog(@"resolving guest socket runtime devices");
    NSArray *devices = [virtualMachine respondsToSelector:S("socketDevices")]
        ? ((id(*)(id, SEL))objc_msgSend)(virtualMachine, S("socketDevices"))
        : ([virtualMachine respondsToSelector:S("_socketDevices")]
            ? ((id(*)(id, SEL))objc_msgSend)(virtualMachine,
                                             S("_socketDevices")) : nil);
    id device = devices.firstObject;
    VZGuestToolsLog(@"guest socket runtime device=%@", device);
    id listener = New("VZVirtioSocketListener");
    VZGuestToolsLog(@"created guest socket listener=%@", listener);
    if (!device || !listener) {
        VZGuestToolsLog(@"Apple guest agent socket listener unavailable");
        [listener release];
        return;
    }
    id delegate=[VZGuestSocketListenerDelegate new];
    QGASyncV3(^{[gGuestSocketDelegate release];gGuestSocketDelegate=[delegate retain];});
    SetObject(listener, "setDelegate:", delegate);
    [delegate release];
    VZGuestToolsLog(@"configured guest socket listener delegate");
    ((void(*)(id, SEL, id, uint32_t))objc_msgSend)(
        device, S("setSocketListener:forPort:"), listener, 505050);
    VZGuestToolsLog(@"registered guest socket listener port 505050");
    QGASyncV3(^{[gGuestSocketListener release];gGuestSocketListener=[listener retain];});
    [listener release];
    VZGuestToolsLog(@"listening for Apple guest agent on Virtio port 505050");
}

static void VZGuestToolsAttachOnMain(void *opaque)
{
    VZGuestToolsAttachOnCurrentThread((id)opaque);
}

void VZGuestToolsAttachToVirtualMachine(id virtualMachine)
{
    if(!VM27OwnedSSHServiceAttachGateV2(virtualMachine))return;
    // VZVirtioSocketDevice's listener registration is main-thread-affine.
    // iPadOS 14 constructs the otherwise synchronous VZ configuration on a
    // worker queue to avoid its scene-update watchdog; calling
    // setSocketListener:forPort: from that queue makes CoreFoundation terminate
    // the UIKit host with SIGTRAP. Marshal only this small registration step.
    // iPadOS 15/16 already arrive on main and retain their existing path.
    if (!pthread_main_np()) {
        dispatch_sync_f(dispatch_get_main_queue(), virtualMachine,
                        VZGuestToolsAttachOnMain);
        return;
    }
    VZGuestToolsAttachOnCurrentThread(virtualMachine);
}



static void VZGuestToolsRun(NSString *path,NSArray *arguments,VZGuestCommandCompletion completion)
{
    QGASyncV3(^{
        VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(completion);if(!owner)return;
        OwnedQGARunV3(owner,path,arguments ?: @[],^(BOOL success,NSData *output){if([owner isLive])[owner finish:success output:output];});
    });
}

void VZGuestToolsEnableRemoteLogin(void (^completion)(BOOL, NSData *))
{
    QGASyncV3(^{
    const char *version = getenv("VZ_PVG_BACKEND_VERSION");
    if (!version || strcmp(version, "27") || gGuestWriteDescriptor < 0) {
        completion(NO, [NSData data]);
        return;
    }
    NSString *script = @"set -eu; "
        "/bin/launchctl enable system/com.openssh.sshd; "
        "if ! /bin/launchctl print system/com.openssh.sshd >/dev/null 2>&1; then "
        "/bin/launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist; fi; "
        "/usr/sbin/systemsetup -getremotelogin || true; "
        "/usr/bin/id lkx; /bin/launchctl print system/com.openssh.sshd";
    VZGuestToolsRun(@"/bin/sh", @[@"-c", script], completion);
    });
}

static void VZGuestToolsWriteFile(NSString *path,NSData *data,void (^completion)(BOOL success))
{
    QGASyncV3(^{
        VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){(void)output;if(completion)completion(success);});if(!owner)return;
        OwnedQGAWriteFileV3(owner,path,data,^(BOOL success){if([owner isLive])[owner finish:success output:[NSData data]];});
    });
}

static void VZGuestToolsProvisionDesktop(NSUInteger attempt);

static NSData *VZGuestToolsConfigurationData(NSString *build)
{
    const char *backend = getenv("VZ_PVG_BACKEND_VERSION");
    NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:
        [gGuestBundlePath stringByAppendingPathComponent:@"VirtualMac.plist"]];
    NSNumber *level = options[@"NativeGraphicsFeatureLevel27"];
    BOOL nativeWebGPU = backend && !strcmp(backend, "27") &&
        (!level || ([level isKindOfClass:NSNumber.class] && level.integerValue == 3));
    NSDictionary *configuration = @{
        @"NativeWebGPUEnabled": @(nativeWebGPU),
        @"Build": build ?: @"",
        @"ReadyToken": gGuestReadyToken ?: @"",
        @"OpenGLAllowed": @(gGuestOpenGLAccelerationEnabled),
        @"OpenGLAcceleration": @(gGuestOpenGLAccelerationEnabled),
        @"ApplePencilPressureTiltEnabled": @(gGuestPencilSupportEnabled),
    };
    NSError *error = nil;
    NSData *data = [NSPropertyListSerialization
        dataWithPropertyList:configuration
        format:NSPropertyListXMLFormat_v1_0 options:0 error:&error];
    if (!data)
        VZGuestToolsLog(@"could not encode guest policy: %@", error);
    return data;
}

static void VZGuestToolsActivate(BOOL payloadChanged, uint64_t generation,
                                 void (^completion)(BOOL success))
{
    BOOL forceRestart = payloadChanged || !gGuestMenuRestartedForToken;
    // A running menu publishes readiness once, after constructing its UI.
    // Keep that genuine acknowledgement during non-restarting retries;
    // removing it here can race a slow launch and prevent all later ACKs.
    NSString *readyResetCommand = forceRestart
        ? @"/bin/rm -f /tmp/VirtualMacGuestTools.ready; " : @"";
    NSString *registeredJobCommand = forceRestart
        ? @"/bin/launchctl kickstart -k \"$job\" 2>/dev/null || true"
        : @"/bin/launchctl kickstart \"$job\" 2>/dev/null || true";
    NSString *script = [NSString stringWithFormat:
        @"uid=$(/usr/bin/stat -f %%u /dev/console); "
         "case $uid in ''|0) "
             "echo VIRTUAL_MAC_WAITING_FOR_DESKTOP; exit 75;; esac; "
         "test -f /var/db/.AppleSetupDone || { "
             "echo VIRTUAL_MAC_WAITING_FOR_DESKTOP; exit 75; }; "
         "%@"
         "/usr/bin/xattr -cr /Library/VirtualMac "
             "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist; "
         "job=\"gui/$uid/com.mac.virtual.guest-tools\"; "
         "if /bin/launchctl print \"$job\" >/dev/null 2>&1; then "
             "%@; "
         "else "
             "/bin/launchctl bootstrap \"gui/$uid\" "
                 "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist "
                 "2>&1; "
             "bootstrap_status=$?; "
             "if test $bootstrap_status -ne 0; then "
                 "exit $bootstrap_status; "
             "fi; "
         "fi; "
         "/bin/launchctl print \"$job\" "
             "2>&1 | /usr/bin/tail -n 24; "
         "echo VIRTUAL_MAC_ACTIVATED",
         readyResetCommand, registeredJobCommand];
    VZGuestToolsRun(@"/bin/sh", @[@"-c", script],
        ^(BOOL success, NSData *output) {
            if (generation != __atomic_load_n(&gGuestProvisioningGeneration,
                                              __ATOMIC_ACQUIRE)) return;
            NSString *text = [[[NSString alloc] initWithData:output
                encoding:NSUTF8StringEncoding] autorelease];
            text = [text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            text = [text stringByReplacingOccurrencesOfString:
                @"VIRTUAL_MAC_ACTIVATED" withString:@""];
            text = [text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            VZGuestToolsLog(@"guest menu activation %@: %@",
                            success ? @"succeeded" : @"failed", text ?: @"");
            if (success) gGuestMenuRestartedForToken = YES;
            completion(success);
        });
}

/* Runs only after the real sw_vers operation has finished and before the
 * existing desktop callback. This process-lifetime diagnostic never retries. */
static BOOL gGuestBootDiagnosticAttemptedV8;
static void VZGuestToolsReadBootDiagnosticV8(void (^completion)(void))
{
    if(gGuestBootDiagnosticAttemptedV8){completion();return;}
    gGuestBootDiagnosticAttemptedV8=YES;
    NSString *script=@"export LC_ALL=C\n"
        "{\n"
        "printf 'VM27_READONLY_GUEST_BOOT_V12\\nCONSOLE_UID\\n'\n"
        "echo 'CONSOLE_STAT_BEGIN'\n"
        "/usr/bin/stat -f %u /dev/console\n"
        "vm27_stat_rc=$?\n"
        "printf 'CONSOLE_STAT_RETURN actualExit=%s\\n' \"$vm27_stat_rc\"\n"
        "if test -f /var/db/.AppleSetupDone; then echo APPLE_SETUP_DONE=1; else echo APPLE_SETUP_DONE=0; fi\n"
        "echo 'RELEVANT_DESKTOP_PROCESSES pid ppid uid stat wchan comm'\n"
        "echo 'GUI_PS_CAPTURE_BEGIN'\n"
        "vm27_ps=$(/bin/ps -axo pid=,ppid=,uid=,stat=,wchan=,comm=)\n"
        "vm27_ps_rc=$?\n"
        "printf 'GUI_PS_CAPTURE_RETURN actualExit=%s\\n' \"$vm27_ps_rc\"\n"
        "printf '%s\\n' \"$vm27_ps\" | /usr/bin/awk '\n"
        " NF>=6 && $1~/^[0-9]+$/ && $2~/^[0-9]+$/ && $3~/^[0-9]+$/ {\n"
        "  rows[++n]=$0; parents[n]=$2; users[n]=$3; names[n]=$6;\n"
        "  if($3==0 && $6~/(^|\\/)AppleQEMUGuestAgent$/)agents[$1]=1;\n"
        " }\n"
        " END {\n"
        "  for(i=1;i<=n && printed<32;i++)\n"
        "   if(names[i]~/(^|\\/)(WindowServer|loginwindow|SecurityAgent|Finder|Dock|AppleQEMUGuestAgent)$/ || (users[i]==0 && agents[parents[i]])) {print rows[i];printed++}\n"
        "  printf \"VM27_GUI_PROCESS_ROWS scanned=%d printed=%d outputLimit=32 snapshotNonAtomic=1\\n\",n,printed;\n"
        " }'\n"
        "} 2>&1 | LC_ALL=C /usr/bin/awk 'BEGIN { vm27_left=8192 } { vm27_line=$0 ORS; if(length(vm27_line)>vm27_left)vm27_line=substr(vm27_line,1,vm27_left); printf \"%s\",vm27_line; fflush(); vm27_left-=length(vm27_line); if(vm27_left<=0)exit }'\n";
    VZGuestToolsRun(@"/bin/sh",@[@"-c",script],^(BOOL success,NSData *output){
        NSUInteger count=MIN(output.length,(NSUInteger)8192);const int saved=errno;
        VZGuestToolsLog(@"readonly guest boot diagnostic completed=%u capturedBytes=%lu retainedBytes=%lu lifetimeAttempts=1 existingOperationBoundSeconds=45 noSSHOrGuestFileWrites=1",
            success?1u:0u,(unsigned long)output.length,(unsigned long)count);
        if(count)(void)write(STDERR_FILENO,output.bytes,count);
        (void)write(STDERR_FILENO,"\n",1);errno=saved;
        completion();
    });
}

static void VZGuestToolsDiscoverGuestVersion(void (^completion)(void))
{
    VZGuestToolsRun(@"/usr/bin/sw_vers", @[@"-productVersion"],
        ^(BOOL success, NSData *output) {
            NSString *version = [[[NSString alloc] initWithData:output
                encoding:NSUTF8StringEncoding] autorelease];
            version = [version stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            NSInteger majorVersion = success
                ? [[[version componentsSeparatedByString:@"."] firstObject]
                    integerValue] : 0;
            if (majorVersion > 0) {
                if (majorVersion < 14) {
                    // Scope compatibility to this observed boot. Do not alter
                    // the saved preference: the same VM can be upgraded to a
                    // newer macOS release before its next start.
                    gGuestOpenGLAccelerationEnabled = NO;
                    VZGuestToolsLog(@"OpenGL disabled for macOS %@; Sonoma "
                                    @"or later is required", version);
                }
            } else {
                VZGuestToolsLog(@"could not determine guest macOS version");
            }
            /* A failed sw_vers does not admit the lifetime boot diagnostic.
             * Preserve the original desktop/provision callback on failure. */
            if(success)VZGuestToolsReadBootDiagnosticV8(completion);
            else completion();
        });
}

static void VZGuestToolsMarkRemovalComplete(void)
{
    if (!gGuestBundlePath.length) return;
    NSString *path = [gGuestBundlePath
        stringByAppendingPathComponent:@"VirtualMac.plist"];
    NSMutableDictionary *configuration = [NSMutableDictionary
        dictionaryWithContentsOfFile:path];
    if (![configuration isKindOfClass:NSMutableDictionary.class]) return;
    configuration[@"GuestToolsRemovalPending"] = @NO;
    [configuration writeToFile:path atomically:YES];
}

static void VZGuestToolsUninstall(void)
{
    NSString *script =
        @"uid=$(/usr/bin/stat -f %u /dev/console); "
         "case $uid in ''|0) exit 0;; esac; "
         "user=$(/usr/bin/id -nu \"$uid\"); "
         "/bin/launchctl bootout \"gui/$uid/com.mac.virtual.guest-tools\" "
             "2>/dev/null || true; "
         "/bin/launchctl bootout system/com.mac.virtual.opengl-compat "
             "2>/dev/null || true; "
         "/bin/launchctl unsetenv DYLD_INSERT_LIBRARIES "
             "2>/dev/null || true; "
         "/bin/launchctl asuser \"$uid\" /bin/launchctl unsetenv "
             "DYLD_INSERT_LIBRARIES; "
         "/usr/bin/sudo -u \"$user\" -H /usr/bin/defaults delete "
             "com.mac.virtual.guest-tools 2>/dev/null || true; "
         "/usr/bin/sudo -u \"$user\" -H /usr/bin/defaults delete "
             "com.apple.loginwindow TALLogoutSavesState "
             "2>/dev/null || true; "
         "/usr/bin/sudo -u \"$user\" -H /usr/bin/defaults delete "
             "com.apple.loginwindow LoginwindowLaunchesRelaunchApps "
             "2>/dev/null || true; "
         "/bin/rm -rf /Library/VirtualMac "
             "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist "
             "/Library/LaunchAgents/com.mac.virtual.opengl-compat.plist "
             "/Library/LaunchDaemons/com.mac.virtual.opengl-compat.plist";
    VZGuestToolsRun(@"/bin/sh", @[@"-c", script],
        ^(BOOL success, NSData *output) {
            (void)output;
            VZGuestToolsLog(@"guest payload removal %@",
                            success ? @"succeeded" : @"failed");
            if (success) VZGuestToolsMarkRemovalComplete();
        });
}

static void VZGuestToolsAuditSecurityState(void)
{
    NSString *script =
        @"uid=$(/usr/bin/stat -f %u /dev/console); "
         "/usr/bin/csrutil status; "
         "/usr/sbin/nvram boot-args 2>/dev/null || true; "
         "/bin/launchctl asuser \"$uid\" /bin/launchctl getenv "
             "DYLD_INSERT_LIBRARIES 2>/dev/null || true; "
         "/usr/bin/pgrep -fl 'Virtual Mac Guest Tools' 2>/dev/null || true; "
         "/bin/cat /tmp/VirtualMacGuestTools.stderr.log "
             "/tmp/VirtualMacGuestTools.stdout.log 2>/dev/null || true; "
         "/bin/launchctl print \"gui/$uid/com.mac.virtual.guest-tools\" "
             "2>&1 | /usr/bin/tail -n 20 || true";
    VZGuestToolsRun(@"/bin/sh", @[@"-c", script],
        ^(BOOL success, NSData *output) {
            NSString *text = [[[NSString alloc] initWithData:output
                encoding:NSUTF8StringEncoding] autorelease];
            text = [text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            VZGuestToolsLog(@"guest security state (%@): %@",
                success ? @"queried" : @"query failed", text ?: @"");
        });
}

static void VZGuestToolsInstallPayload(uint64_t generation,
                                       void (^completion)(BOOL success))
{
    NSString *directory = [NSBundle.mainBundle.resourcePath
        stringByAppendingPathComponent:@"GuestTools"];
    NSData *archive = [NSData dataWithContentsOfFile:[directory
        stringByAppendingPathComponent:@"VirtualMacGuestTools.tar.gz"]];
    if (!archive.length) {
        VZGuestToolsLog(@"packaged guest payload is incomplete");
        completion(NO);
        return;
    }
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(archive.bytes, (CC_LONG)archive.length, digest);
    NSMutableString *payloadDigest = [NSMutableString string];
    for (NSUInteger index = 0; index < 8; ++index)
        [payloadDigest appendFormat:@"%02x", digest[index]];
    NSString *build = [NSString stringWithFormat:@"%@-%@",
        [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"]
            ?: @"0", payloadDigest];
    NSData *configuration = VZGuestToolsConfigurationData(build);
    if (!configuration.length) {
        completion(NO);
        return;
    }
    VZGuestToolsWriteFile(@"/tmp/VirtualMacGuestToolsConfiguration.plist",
        configuration, ^(BOOL wroteConfiguration) {
        if (!wroteConfiguration || generation != __atomic_load_n(
                &gGuestProvisioningGeneration, __ATOMIC_ACQUIRE)) {
            VZGuestToolsLog(@"guest policy write failed");
            completion(NO);
            return;
        }
        NSString *check = [NSString stringWithFormat:
            @"test \"$(cat /Library/VirtualMac/.build 2>/dev/null)\" = '%@'",
            build];
        VZGuestToolsRun(@"/bin/sh", @[@"-c", check],
            ^(BOOL current, NSData *output) {
            (void)output;
            if (generation != __atomic_load_n(&gGuestProvisioningGeneration,
                                              __ATOMIC_ACQUIRE)) return;
            if (current) {
                NSString *update =
                    @"set -e; /bin/mkdir -p /Library/VirtualMac; "
                     "/usr/sbin/chown root:wheel "
                         "/tmp/VirtualMacGuestToolsConfiguration.plist; "
                     "/bin/chmod 644 "
                         "/tmp/VirtualMacGuestToolsConfiguration.plist; "
                     "/bin/mv -f /tmp/VirtualMacGuestToolsConfiguration.plist "
                         "/Library/VirtualMac/HostConfiguration.plist";
                VZGuestToolsRun(@"/bin/sh", @[@"-c", update],
                    ^(BOOL updated, NSData *updateOutput) {
                    (void)updateOutput;
                    if (!updated) {
                        completion(NO);
                        return;
                    }
                    VZGuestToolsLog(@"guest payload is current (build %@)", build);
                    VZGuestToolsActivate(NO, generation, completion);
                });
                return;
            }
            VZGuestToolsWriteFile(@"/tmp/VirtualMacGuestTools.tar.gz", archive,
                ^(BOOL wroteArchive) {
                if (!wroteArchive) {
                    VZGuestToolsLog(@"guest payload archive write failed");
                    completion(NO);
                    return;
                }
                NSString *finish = [NSString stringWithFormat:
                    @"set -e; "
                     "uid=$(/usr/bin/stat -f %%u /dev/console); "
                     "case $uid in ''|0) exit 75;; esac; "
                     "test -f /var/db/.AppleSetupDone; "
                     "/bin/launchctl bootout "
                        "\"gui/$uid/com.mac.virtual.guest-tools\" "
                        "2>/dev/null || true; "
                     "/bin/launchctl bootout "
                        "\"gui/$uid/com.mac.virtual.opengl-compat\" "
                        "2>/dev/null || true; "
                     "/bin/launchctl bootout system/com.mac.virtual.opengl-compat "
                        "2>/dev/null || true; "
                     "/bin/launchctl unsetenv DYLD_INSERT_LIBRARIES "
                        "2>/dev/null || true; "
                     "login_hook=$(/usr/bin/defaults read "
                        "/Library/Preferences/com.apple.loginwindow LoginHook "
                        "2>/dev/null || true); "
                     "if test \"$login_hook\" = "
                        "'/Library/VirtualMac/Virtual Mac OpenGL Acceleration'; "
                     "then /usr/bin/defaults delete "
                        "/Library/Preferences/com.apple.loginwindow LoginHook "
                        "2>/dev/null || true; fi; "
                     "/bin/rm -rf /tmp/VirtualMacGuestToolsPayload; "
                     "/bin/mkdir -p /tmp/VirtualMacGuestToolsPayload; "
                     "/usr/bin/tar --no-same-owner -xmzf "
                        "/tmp/VirtualMacGuestTools.tar.gz "
                        "-C /tmp/VirtualMacGuestToolsPayload; "
                     "/bin/mkdir -p /Library/VirtualMac /Library/LaunchAgents; "
                     "/bin/rm -rf '/Library/VirtualMac/Virtual Mac Guest Tools.app'; "
                     "/bin/cp -R '/tmp/VirtualMacGuestToolsPayload/Library/VirtualMac/Virtual Mac Guest Tools.app' "
                        "/Library/VirtualMac/; "
                     "/bin/cp -f /tmp/VirtualMacGuestToolsPayload/Library/VirtualMac/OpenGLPVGCompat.dylib "
                        "/Library/VirtualMac/OpenGLPVGCompat.dylib; "
                     "/usr/sbin/chown root:wheel "
                        "/tmp/VirtualMacGuestToolsConfiguration.plist; "
                     "/bin/chmod 644 "
                        "/tmp/VirtualMacGuestToolsConfiguration.plist; "
                     "/bin/mv -f /tmp/VirtualMacGuestToolsConfiguration.plist "
                        "/Library/VirtualMac/HostConfiguration.plist; "
                     "/usr/sbin/chown -R root:wheel /Library/VirtualMac; "
                     "/bin/chmod 755 /Library/VirtualMac/OpenGLPVGCompat.dylib "
                        "'/Library/VirtualMac/Virtual Mac Guest Tools.app/Contents/MacOS/Virtual Mac Guest Tools'; "
                     "/usr/bin/xattr -cr /Library/VirtualMac; "
                     "/usr/bin/codesign --verify --strict "
                        "'/Library/VirtualMac/Virtual Mac Guest Tools.app'; "
                     "/usr/bin/codesign --verify --strict "
                        "/Library/VirtualMac/OpenGLPVGCompat.dylib; "
                     "/bin/cp -f /tmp/VirtualMacGuestToolsPayload/Library/LaunchAgents/com.mac.virtual.guest-tools.plist "
                        "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist.new; "
                     "/usr/sbin/chown root:wheel "
                        "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist.new; "
                     "/bin/chmod 644 "
                        "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist.new; "
                     "/bin/mv -f "
                        "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist.new "
                        "/Library/LaunchAgents/com.mac.virtual.guest-tools.plist; "
                     "printf '%%s' '%@' > /Library/VirtualMac/.build; "
                     "/bin/rm -rf /tmp/VirtualMacGuestToolsPayload "
                        "/tmp/VirtualMacGuestTools.tar.gz; "
                     "echo VIRTUAL_MAC_PAYLOAD_INSTALLED", build];
                VZGuestToolsRun(@"/bin/sh", @[@"-c", finish],
                    ^(BOOL installed, NSData *finishOutput) {
                    NSString *text = [[[NSString alloc]
                        initWithData:finishOutput
                        encoding:NSUTF8StringEncoding] autorelease];
                    text = [text stringByTrimmingCharactersInSet:
                        NSCharacterSet.whitespaceAndNewlineCharacterSet];
                    if (!installed) {
                        VZGuestToolsLog(@"payload setup failed: %@",
                                        text ?: @"unknown error");
                        completion(NO);
                        return;
                    }
                    VZGuestToolsLog(@"installed guest payload build %@", build);
                    VZGuestToolsActivate(YES, generation, completion);
                });
            });
        });
    });
}

static void VZGuestToolsProvisionDesktop(NSUInteger attempt)
{
    // This independent package intentionally omits the optional legacy menu
    // archive. Do not keep spawning an impossible repair every ten seconds;
    // native clock, owned SSH and the separate clipboard GUI agent continue.
    NSString *payload=[NSBundle.mainBundle.resourcePath stringByAppendingPathComponent:@"GuestTools/VirtualMacGuestTools.tar.gz"];
    if(gGuestToolsEnabled && !gGuestRemovalPending && ![[NSFileManager.defaultManager attributesOfItemAtPath:payload error:nil][NSFileSize] unsignedLongLongValue]) {
        VZGuestToolsLog(@"optional menu payload absent; automatic repair unavailable; clock SSH clipboard remain enabled");
        return;
    }
    uint64_t generation = __atomic_load_n(
        &gGuestProvisioningGeneration, __ATOMIC_ACQUIRE);
    if (gGuestToolsAcknowledged || !gGuestReadyToken.length) return;
    NSString *probe =
        @"uid=$(/usr/bin/stat -f %u /dev/console); "
         "case $uid in ''|0) exit 75;; esac; "
         "test -f /var/db/.AppleSetupDone || exit 75; "
         "/bin/cat /tmp/VirtualMacGuestTools.ready 2>/dev/null || true";
    VZGuestToolsRun(@"/bin/sh", @[@"-c", probe],
        ^(BOOL success, NSData *output) {
            NSString *text = [[[NSString alloc] initWithData:output
                encoding:NSUTF8StringEncoding] autorelease];
            text = [text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            if (generation != __atomic_load_n(&gGuestProvisioningGeneration,
                                              __ATOMIC_ACQUIRE)) return;
            if (success && !gGuestToolsEnabled) {
                if (gGuestRemovalPending) VZGuestToolsUninstall();
                return;
            }
            if (success && [text isEqualToString:gGuestReadyToken]) {
                gGuestToolsAcknowledged = YES;
                VZGuestToolsLog(@"guest menu extra acknowledged token %@",
                                gGuestReadyToken);
                VZGuestToolsAuditSecurityState();
                return;
            }
            if (!success) {
                if (attempt == 0)
                    VZGuestToolsLog(@"waiting for a macOS desktop user session");
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    10 * NSEC_PER_SEC),
                    QGAQueueV3(), ^{
                        if (generation == __atomic_load_n(
                                &gGuestProvisioningGeneration,
                                __ATOMIC_ACQUIRE))
                            VZGuestToolsProvisionDesktop(attempt + 1);
                    });
                return;
            }
            if (attempt == 0 || attempt % 6 == 0)
                VZGuestToolsLog(@"guest menu extra not acknowledged; %@ attempt %lu",
                    attempt ? @"repair" : @"installing", (unsigned long)attempt + 1);
            VZGuestToolsInstallPayload(generation, ^(BOOL installed) {
                if (!installed && (attempt == 0 || attempt % 6 == 0))
                    VZGuestToolsLog(@"guest payload repair will be retried");
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    10 * NSEC_PER_SEC),
                    QGAQueueV3(), ^{
                        if (generation == __atomic_load_n(
                                &gGuestProvisioningGeneration,
                                __ATOMIC_ACQUIRE) && !gGuestToolsAcknowledged)
                            VZGuestToolsProvisionDesktop(attempt + 1);
                    });
            });
        });
}

/* Standard QGA time synchronization runs once at real guest-info readiness,
 * before desktop provisioning/SSH work can occupy the same owned stream. A
 * missing/disabled command is never inferred to exist. There are no guest file
 * writes or external shell commands; native QGA success/error remains visible. */
static BOOL VM27GuestCommandEnabledV16(id info,NSString *wanted) {
 if(![info isKindOfClass:NSDictionary.class])return NO;
 id commands=info[@"supported_commands"];
 if(![commands isKindOfClass:NSArray.class])return NO;
 for(id row in commands)if([row isKindOfClass:NSDictionary.class] &&
  [row[@"name"] isKindOfClass:NSString.class] && [row[@"name"] isEqualToString:wanted] &&
  [row[@"enabled"] isKindOfClass:NSNumber.class] && [row[@"enabled"] boolValue])return YES;
 return NO;
}
#include "vm27_guest_clock_relative_v18.inc"

static void VZGuestToolsProbeAgent(uint64_t generation, NSUInteger attempt)
{
    if(gGuestOwnedOperationV3) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),QGAQueueV3(),^{VZGuestToolsProbeAgent(generation,attempt);});return;
    }
    if (generation != __atomic_load_n(&gGuestProvisioningGeneration,
                                      __ATOMIC_ACQUIRE) ||
        gGuestProvisioningStarted || gGuestReadDescriptor < 0)
        return;
    if (attempt == 1 || attempt % 60 == 0)
        VZGuestToolsLog(@"probing Apple guest agent (attempt %lu)",
                        (unsigned long)attempt);
    // Before the first successful response every outstanding command is this
    // same readiness probe. AppleQEMUGuestAgent can silently discard requests
    // sent while it is starting, so retry, but retain at most one callback.
    // This bounds memory use during a long Setup Assistant or a guest whose
    // agent never becomes available.
    @synchronized (gGuestCallbacks) {
        [gGuestCallbacks removeAllObjects];
    }
    VZGuestToolsSend(@"guest-info", nil, ^(NSDictionary *response) {
        if (generation != __atomic_load_n(&gGuestProvisioningGeneration,
                                          __ATOMIC_ACQUIRE)) return;
        if (response[@"return"] && !gGuestProvisioningStarted) {
            gGuestProvisioningStarted = YES;
            VZGuestToolsLog(@"Apple guest agent ready");
            VM27GuestSyncHostClockV18(response[@"return"],generation,^{
                VM27OwnedSSHServiceReadyV2();
                VZGuestToolsDiscoverGuestVersion(^{
                    VZGuestToolsProvisionDesktop(0);
                });
            });
        }
    });
    // Do not make durability depend on receiving a reply to an earlier probe.
    // QGA can appear late during Setup Assistant or after a slow first login.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
        QGAQueueV3(), ^{
            VZGuestToolsProbeAgent(generation, attempt + 1);
        });
}

void VZGuestToolsStartProvisioning(NSString *bundlePath,
                                   BOOL guestToolsEnabled,
                                   BOOL openGLAccelerationEnabled,
                                   BOOL pencilSupportEnabled,
                                   BOOL removalPending)
{
    QGASyncV3(^{
    gGuestToolsEnabled = guestToolsEnabled;
    gGuestOpenGLAccelerationEnabled = openGLAccelerationEnabled;
    gGuestPencilSupportEnabled = pencilSupportEnabled;
    gGuestRemovalPending = removalPending;
    gGuestToolsAcknowledged = NO;
    gGuestMenuRestartedForToken = NO;
    [gGuestReadyToken release];
    gGuestReadyToken = (guestToolsEnabled || removalPending)
        ? [NSUUID.UUID.UUIDString copy] : nil;
    [gGuestBundlePath release];
    gGuestBundlePath = [bundlePath copy];
    if (!guestToolsEnabled && !removalPending) return;
    uint64_t generation = __atomic_load_n(&gGuestProvisioningGeneration,
                                          __ATOMIC_ACQUIRE);
    if (gGuestReadDescriptor >= 0)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
            QGAQueueV3(), ^{
                VZGuestToolsProbeAgent(generation, 1);
            });
    });
}

BOOL VZGuestToolsConfigureBootArguments(id auxiliaryStorage,
                                        BOOL guestAgentEnabled,
                                        BOOL openGLAccelerationEnabled,
                                        NSError **error)
{
    SEL getter = S("_valueForNVRAMVariableNamed:error:");
    SEL setter = S("_setValue:forNVRAMVariableNamed:error:");
    if (!auxiliaryStorage || ![auxiliaryStorage respondsToSelector:setter]) {
        if (error)
            *error = [NSError errorWithDomain:@"VirtualMacGuestTools"
                code:1 userInfo:@{NSLocalizedDescriptionKey:
                @"The Virtual Mac NVRAM interface is unavailable."}];
        return NO;
    }
    NSError *readError = nil;
    id existing = [auxiliaryStorage respondsToSelector:getter]
        ? ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
            auxiliaryStorage, getter, @"boot-args", &readError)
        : nil;
    NSString *arguments = nil;
    if ([existing isKindOfClass:NSData.class])
        arguments = [[[NSString alloc] initWithData:existing
            encoding:NSUTF8StringEncoding] autorelease];
    else if ([existing isKindOfClass:NSString.class])
        arguments = existing;
    arguments = [arguments stringByTrimmingCharactersInSet:
        NSCharacterSet.whitespaceAndNewlineCharacterSet] ?: @"";
    NSMutableArray *tokens = [NSMutableArray array];
    for (NSString *token in [arguments componentsSeparatedByCharactersInSet:
        NSCharacterSet.whitespaceAndNewlineCharacterSet]) {
        if (token.length && ![token isEqualToString:@"-arm64e_preview_abi"])
            [tokens addObject:token];
    }
    if (openGLAccelerationEnabled)
        [tokens addObject:@"-arm64e_preview_abi"];
    NSString *updated = [tokens componentsJoinedByString:@" "];
    BOOL result = YES;
    if (![updated isEqualToString:arguments]) {
        result = ((BOOL(*)(id, SEL, id, id, NSError **))objc_msgSend)(
            auxiliaryStorage, setter, updated, @"boot-args", error);
    }
    if (!result) return NO;

    // VZ advertises this port identifier in the product device-tree node.
    // AppleQEMUGuestAgent reads the corresponding NVRAM variable from /options
    // before connecting to host CID 2 through AppleVirtIOAgentDevice. VMs
    // originally restored without guest-agent support do not have that
    // variable, so adding the socket device alone leaves the daemon exiting
    // with status 1. The value is VZ's stable agent port identifier, not a
    // guest-version or build-specific address.
    if (!guestAgentEnabled) {
        SEL remover = S("_removeNVRAMVariableNamed:error:");
        if ([auxiliaryStorage respondsToSelector:remover]) {
            @try {
                ((BOOL(*)(id, SEL, id, NSError **))objc_msgSend)(
                    auxiliaryStorage, remover, @"apple-guest-agent-port",
                    NULL);
            } @catch (__unused NSException *exception) {}
        }
        return YES;
    }
    // AppleQEMUGuestAgent parses the /options value as an ASCII decimal port.
    // (Its fallback copy in the product node is a binary uint32.) The private
    // setter therefore receives the textual NVRAM representation.
    @try {
        result = ((BOOL(*)(id, SEL, id, id, NSError **))objc_msgSend)(
            auxiliaryStorage, setter, @"505050", @"apple-guest-agent-port",
            error);
    } @catch (NSException *exception) {
        result = NO;
        if (error)
            *error = [NSError errorWithDomain:@"VirtualMacGuestTools" code:2
                userInfo:@{NSLocalizedDescriptionKey:
                    exception.reason ?: @"The guest agent port could not be staged."}];
    }
    if (result) {
        VZGuestToolsLog(@"staged NVRAM boot arguments %@", updated);
        VZGuestToolsLog(@"staged Apple guest agent port 505050");
    }
    return result;
}


/* Fixed signed helper. The dialogue owns one actual socket epoch until its
 * completion or cancellation; first diagnostic service is still 300 seconds. */
static uint64_t gGuestActiveSSHAttemptGenerationV1=UINT64_MAX;

static NSData *VM27ReadSignedGuestActiveSSHResourceV1(void) {
    NSString *base=[NSBundle.mainBundle resourcePath];
    NSString *path=[base stringByAppendingPathComponent:@VM27_GUEST_ACTIVE_SSH_RESOURCE_V1];
    if (!base || !path) return nil;
    char base_real[PATH_MAX],actual[PATH_MAX],want[PATH_MAX];
    if (!realpath(base.fileSystemRepresentation,base_real) ||
        !realpath(path.fileSystemRepresentation,actual)) return nil;
    int n=snprintf(want,sizeof(want),"%s/%s",base_real,VM27_GUEST_ACTIVE_SSH_RESOURCE_V1);
    if (n<0 || (size_t)n>=sizeof(want) || strcmp(actual,want)) return nil;
    struct stat before,at,after,final;
    if (lstat(actual,&before) || !S_ISREG(before.st_mode) || before.st_nlink!=1 ||
        before.st_uid!=501 || before.st_gid!=501 || (before.st_mode&0777)!=0600 ||
        before.st_size!=VM27_GUEST_ACTIVE_SSH_BYTES_V1) return nil;
    int fd=open(actual,O_RDONLY|O_NOFOLLOW);if(fd<0)return nil;
    uint8_t bytes[VM27_GUEST_ACTIVE_SSH_BYTES_V1];size_t used=0;BOOL ok=YES;
    if(fstat(fd,&at) || at.st_dev!=before.st_dev || at.st_ino!=before.st_ino)ok=NO;
    while(ok && used<sizeof(bytes)) {
        ssize_t amount=read(fd,bytes+used,sizeof(bytes)-used);
        if(amount<0 && errno==EINTR)continue;
        if(amount<=0){ok=NO;break;}used+=(size_t)amount;
    }
    uint8_t tail;if(ok && read(fd,&tail,1)!=0)ok=NO;
    if(fstat(fd,&after) || lstat(actual,&final))ok=NO;
    close(fd);
    if(!ok || at.st_dev!=after.st_dev || at.st_ino!=after.st_ino ||
        at.st_size!=after.st_size || at.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec ||
        at.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec ||
        at.st_ctimespec.tv_sec!=after.st_ctimespec.tv_sec || at.st_ctimespec.tv_nsec!=after.st_ctimespec.tv_nsec ||
        final.st_dev!=after.st_dev || final.st_ino!=after.st_ino || final.st_size!=after.st_size ||
        final.st_uid!=501 || final.st_gid!=501 || (final.st_mode&0777)!=0600 || final.st_nlink!=1 ||
        !S_ISREG(final.st_mode)) return nil;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(bytes,(CC_LONG)sizeof(bytes),digest);
    char text[65];for(unsigned i=0;i<32;i++)snprintf(text+2*i,3,"%02x",digest[i]);
    if(strcmp(text,VM27_GUEST_ACTIVE_SSH_SHA256_V1))return nil;
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}
void VZGuestToolsInstallOwnedActiveSSHHelperV1(void (^completion)(BOOL,NSData *)) {
    if(!completion)return;
    dispatch_async(QGAQueueV3(),^{
        void (^finished)(BOOL,NSData *)=^(BOOL success,NSData *output){
            dispatch_async(dispatch_get_main_queue(),^{completion(success,output ?: [NSData data]);});
        };
        const char *version=getenv("VZ_PVG_BACKEND_VERSION");
        NSString *bundleIdentifier=[NSBundle.mainBundle bundleIdentifier];
        if(!version || strcmp(version,"27") || getuid()!=501 || geteuid()!=501 ||
           ![bundleIdentifier isEqualToString:@"com.mac.virtual.independent27"]) {
            finished(NO,[@"VM27_GUEST_HELPER_REJECTED actual independent App role required; guestSSHAuthenticated=0\n" dataUsingEncoding:NSUTF8StringEncoding]);return;
        }
        uint64_t generation=gGuestProvisioningGeneration;
        if(VM27OwnedSSHServiceActiveV2() || !gGuestProvisioningStarted || gGuestReadDescriptor<0 || gGuestWriteDescriptor<0 ||
           gGuestCallbacks.count || gGuestOwnedOperationV3 || gGuestActiveSSHAttemptGenerationV1==generation) {
            finished(NO,[@"VM27_GUEST_HELPER_REJECTED actual ready idleQGA/once-per-generation required; guestSSHAuthenticated=0\n" dataUsingEncoding:NSUTF8StringEncoding]);return;
        }
        NSData *artifact=VM27ReadSignedGuestActiveSSHResourceV1();
        if(!artifact) {finished(NO,[@"VM27_GUEST_HELPER_REJECTED exact signed resource unavailable; guestSSHAuthenticated=0\n" dataUsingEncoding:NSUTF8StringEncoding]);return;}
        VM27OwnedQGAOperationV5 *operation=BeginQGAOperationV3(finished);if(!operation)return;
        gGuestActiveSSHAttemptGenerationV1=generation;
    NSString *prepare=@"set -eu\n[ \"$(/usr/bin/id -u)\" = 0 ] && [ \"$(/usr/bin/id -ru)\" = 0 ]\n[ -d /private/tmp ] && [ ! -L /private/tmp ]\n[ \"$(cd -P /private/tmp && /bin/pwd -P)\" = /private/tmp ]\n[ ! -e /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ]\numask 077\n/bin/mkdir -m 700 /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f\n[ -d /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ]\n[ \"$(cd -P /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f && /bin/pwd -P)\" = /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ]\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f)\" = 0:0:700 ]\n(set -C; : > /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending)\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending)\" = 0:0:600:1:0 ]\nprintf 'VM27_GUEST_HELPER_NAMESPACE_CREATED root=/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f uploaded=0 started=0\\n'\n";
    OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",prepare],^(BOOL prepared,NSData *output) {
        if(![operation isLive]) {[operation finish:NO output:output];return;}
        if(!prepared) {[operation finish:NO output:output];return;}
        OwnedQGAWriteFileV3(operation,@VM27_GUEST_ACTIVE_SSH_PENDING_V1,artifact,^(BOOL uploaded) {
            if(![operation isLive]) {[operation finish:NO output:[NSData data]];return;}
            if(!uploaded) {[operation finish:NO output:[@"VM27_GUEST_HELPER_QGA_UPLOAD_FAILED guestSSHAuthenticated=0\n" dataUsingEncoding:NSUTF8StringEncoding]];return;}
            NSString *finish=@"set -eu\n[ \"$(/usr/bin/id -u)\" = 0 ] && [ \"$(/usr/bin/id -ru)\" = 0 ]\n[ -d /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ]\n[ \"$(cd -P /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f && /bin/pwd -P)\" = /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f ]\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f)\" = 0:0:700 ]\n[ -f /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending ]\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending)\" = 0:0:600:1:52448 ]\n[ \"$(/usr/bin/shasum -a 256 /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending | /usr/bin/cut -d ' ' -f1)\" = 33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c ]\n\n/usr/bin/codesign --verify --strict /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending\n[ ! -e /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ]\n/bin/chmod 700 /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending\n/bin/mv -n /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh\n[ ! -e /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.pending ]\n[ -f /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ]\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l:%z' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh)\" = 0:0:700:1:52448 ]\n[ \"$(/usr/bin/shasum -a 256 /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh | /usr/bin/cut -d ' ' -f1)\" = 33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c ]\n\n/bin/launchctl enable system/com.openssh.sshd\nif ! /bin/launchctl print system/com.openssh.sshd >/dev/null 2>&1; then\n /bin/launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist\nfi\n/bin/launchctl print system/com.openssh.sshd >/dev/null\n/usr/bin/id lkx\n/usr/bin/nohup /bin/sh -c 'set -eu\n[ \"$(/usr/bin/id -u)\" = 0 ] && [ \"$(/usr/bin/id -ru)\" = 0 ]\n[ -f /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ] && [ ! -L /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh ]\n[ \"$(/usr/bin/stat -f '\"'\"'%u:%g:%Lp:%l:%z'\"'\"' /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh)\" = 0:0:700:1:52448 ]\n[ \"$(/usr/bin/shasum -a 256 /private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh | /usr/bin/cut -d '\"'\"' '\"'\"' -f1)\" = 33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c ]\n\nown_pid=0\nown_start='\"'\"''\"'\"'\nown_path=/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh\nown_parent=$$\nown_started=0\nexact_owned() {\n [ \"$own_pid\" -gt 1 ] && [ -n \"$own_start\" ] || return 1\n [ \"$(/bin/ps -ww -p \"$own_pid\" -o uid= | /usr/bin/tr -d '\"'\"' '\"'\"')\" = 0 ] || return 1\n [ \"$(/bin/ps -ww -p \"$own_pid\" -o ppid= | /usr/bin/tr -d '\"'\"' '\"'\"')\" = \"$own_parent\" ] || return 1\n [ \"$(/bin/ps -ww -p \"$own_pid\" -o comm=)\" = \"$own_path\" ] || return 1\n [ \"$(/bin/ps -ww -p \"$own_pid\" -o lstart= | /usr/bin/shasum -a 256 | /usr/bin/cut -d '\"'\"' '\"'\"' -f1)\" = \"$own_start\" ]\n}\nfinish_owned() {\n own_status=$?\n trap - EXIT TERM INT HUP\n if [ \"$own_started\" = 1 ] && exact_owned; then\n  exact_owned && /bin/kill -TERM \"$own_pid\"\n  own_grace=0\n  while [ \"$own_grace\" -lt 3 ] && exact_owned; do /bin/sleep 1; own_grace=$((own_grace+1)); done\n  if exact_owned; then exact_owned && /bin/kill -KILL \"$own_pid\"; fi\n fi\n if [ \"$own_started\" = 1 ]; then\n  own_final_state=$(/bin/ps -ww -p \"$own_pid\" -o stat= | /usr/bin/tr -d '\"'\"' '\"'\"')\n  case \"$own_final_state\" in Z*)\n   [ \"$(/bin/ps -ww -p \"$own_pid\" -o ppid= | /usr/bin/tr -d '\"'\"' '\"'\"')\" = \"$own_parent\" ] &&\n   [ \"$(/bin/ps -ww -p \"$own_pid\" -o lstart= | /usr/bin/shasum -a 256 | /usr/bin/cut -d '\"'\"' '\"'\"' -f1)\" = \"$own_start\" ] && wait \"$own_pid\" || true;; esac\n  if /bin/ps -ww -p \"$own_pid\" -o pid= | /usr/bin/tr -d '\"'\"' '\"'\"' | /usr/bin/grep -q .; then\n   printf '\"'\"'VM27_GUEST_HELPER_CAPTURE_OR_CLEANUP_UNRESOLVED pid=%s expectedPPID=%s expectedStartSHA256=%s path=%s owningNormalVMLifecycle=1 guestSSHAuthenticated=0\\n'\"'\"' \"$own_pid\" \"$own_parent\" \"$own_start\" \"$own_path\"\n   exit 78\n  fi\n  wait \"$own_pid\" || true\n fi\n printf '\"'\"'VM27_GUEST_HELPER_WATCHER_DONE status=%s actualOwnedChildOff=1 guestSSHAuthenticated=0\\n'\"'\"' \"$own_status\"\n exit \"$own_status\"\n}\ntrap finish_owned EXIT\ntrap '\"'\"'exit 143'\"'\"' TERM INT HUP\n/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/vm27-guest-vsock-ssh --serve-v1 >/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/helper.log 2>&1 < /dev/null &\nown_pid=$!\nown_started=1\nown_start=$(/bin/ps -ww -p \"$own_pid\" -o lstart= | /usr/bin/shasum -a 256 | /usr/bin/cut -d '\"'\"' '\"'\"' -f1)\nown_capture=0\nwhile [ \"$own_capture\" -lt 2 ] && ! exact_owned; do /bin/sleep 1; own_capture=$((own_capture+1)); done\nexact_owned\nprintf '\"'\"'VM27_GUEST_HELPER_ID pid=%s ppid=%s uid=0 startSHA256=%s path=%s\\n'\"'\"' \"$own_pid\" \"$own_parent\" \"$own_start\" \"$own_path\" >/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/lease.txt\nown_second=0\nwhile [ \"$own_second\" -lt 300 ]; do\n if ! exact_owned; then\n  if /bin/ps -ww -p \"$own_pid\" -o pid= | /usr/bin/tr -d '\"'\"' '\"'\"' | /usr/bin/grep -q .; then exit 78; fi\n  wait \"$own_pid\"; own_started=0; exit 0\n fi\n /bin/sleep 1; own_second=$((own_second+1))\ndone\nprintf '\"'\"'VM27_GUEST_HELPER_WALL_LIMIT seconds=300\\n'\"'\"'\nexit 124\n' >/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f/watcher.log 2>&1 < /dev/null &\nown_watcher=$!\n[ \"$own_watcher\" -gt 1 ]\nprintf 'VM27_GUEST_HELPER_LAUNCH_REQUESTED watcherPID=%s root=/private/tmp/VM27OwnedActiveSSH-v1-33547b92f6f7bf5f helperSHA256=33547b92f6f7bf5f60ad47084963f41090c0a736fc85d78a7221fb66cd5b869c wallSeconds=300 guestSSHAuthenticated=0\\n' \"$own_watcher\"\n";
            OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",finish],^(BOOL launched,NSData *result) {
                if(![operation isLive]) {[operation finish:NO output:result];return;}
                NSString *text=[[[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding]autorelease];
                BOOL actualRequested=launched && [text containsString:@"VM27_GUEST_HELPER_LAUNCH_REQUESTED watcherPID="];
                VZGuestToolsLog(@"owned helper launch requested=%d; HELLO and SSH authentication still unverified",actualRequested);
                [operation finish:actualRequested output:result];
            });
        });
    });
    });
}

#include "vm27_owned_ssh_service_v3.inc"
#include "vm27_clipboard_provision_v6.inc"


#import "VZGuestTools_owned_active_ssh_v10.h"
/* A fixed root-agent read-only command. Existing ready/provision operations,
 * command ownership, epoch/generation checks and 45-second deadline are whole.
 * Its bounded transcript is evidence; a successful shell exit does not assert
 * that each printed subsystem is healthy or that a desktop is visible. */
BOOL VZGuestToolsReadDesktopDiagnosticV10(void (^completion)(BOOL success, NSData *output))
{
    NSString *script=@"{\n#!/bin/sh\n# Fixed read-only login-session diagnostic, executed by the actual root guest agent.\n# No arguments, guest files, configuration/service changes, or foreign signals.\n# Each selected process is sampled once for a native 1-second interval. Process\n# discovery, rechecks, symbolication and log reading have no whole-script wall\n# deadline here. Identity observations are non-atomic; uncertainty skips sample.\nset -u\nset -f\nLC_ALL=C\nexport LC_ALL\n\nif test \"$#\" -ne 0; then\n    printf 'VM27_LOGIN_SESSION_DIAGNOSTIC_REJECTED argumentsNotAllowed=1\\n'\n    exit 64\nfi\nif test \"$(/usr/bin/id -u)\" != 0; then\n    printf 'VM27_LOGIN_SESSION_DIAGNOSTIC_REJECTED actualRootRequired=1\\n'\n    exit 77\nfi\nprintf 'VM27_LOGIN_SESSION_DIAGNOSTIC_V1 readOnly=1 guestFilesWritten=0 foreignSignalsSent=0 wholeScriptWallDeadline=none\\n'\nprintf 'IDENTITY_DISCOVERY_BEGIN fields=pid,uid,lstart,comm\\n'\nvm27_process_rows=$(/bin/ps -axo pid=,uid=,lstart=,comm=)\nvm27_discovery_rc=$?\nprintf 'IDENTITY_DISCOVERY_RETURN actualExit=%s snapshotNonAtomic=1\\n' \"$vm27_discovery_rc\"\n\n# Normalize only eight fields: PID, UID, five C-locale lstart fields, full path.\n# Fixed allowlisted paths contain no whitespace. Never execute process data.\nvm27_identity_row() {\n    /bin/ps -p \"$1\" -o pid=,uid=,lstart=,comm= |\n    /usr/bin/awk -v pid=\"$1\" -v uid=\"$2\" -v path=\"$3\" '\n      NF==8 && $1==pid && $2==uid && $8==path {\n        n++; row=sprintf(\"%s %s %s %s %s %s %s %s\",$1,$2,$3,$4,$5,$6,$7,$8)\n      }\n      END {if(n==1)print row}'\n}\n\nvm27_sample_fixed_target() {\n    vm27_target_name=$1\n    vm27_target_uid=$2\n    vm27_target_path=$3\n    printf 'TARGET_DISCOVERY_BEGIN target=%s requiredUID=%s requiredPath=%s\\n' \"$vm27_target_name\" \"$vm27_target_uid\" \"$vm27_target_path\"\n    if test \"$vm27_discovery_rc\" -ne 0; then\n        printf 'TARGET_SKIPPED target=%s reason=initialPSFailed sampleAttempts=0\\n' \"$vm27_target_name\"\n        return\n    fi\n    vm27_selected=$(printf '%s\\n' \"$vm27_process_rows\" |\n      /usr/bin/awk -v uid=\"$vm27_target_uid\" -v path=\"$vm27_target_path\" '\n        NF==8 && $1~/^[0-9]+$/ && $1>1 && $2==uid && $8==path {\n          n++; row=sprintf(\"%s %s %s %s %s %s %s %s\",$1,$2,$3,$4,$5,$6,$7,$8)\n        }\n        END {if(n==1)print row;else printf \"UNKNOWN matches=%d\\n\",n}')\n    case \"$vm27_selected\" in\n      UNKNOWN*) printf 'TARGET_SKIPPED target=%s reason=notUnique identity=%s sampleAttempts=0\\n' \"$vm27_target_name\" \"$vm27_selected\";return ;;\n    esac\n    set -- $vm27_selected\n    if test \"$#\" -ne 8; then\n        printf 'TARGET_SKIPPED target=%s reason=malformedInitialIdentity sampleAttempts=0\\n' \"$vm27_target_name\"\n        return\n    fi\n    vm27_target_pid=$1\n    printf 'TARGET_RECHECK_BEGIN target=%s pid=%s\\n' \"$vm27_target_name\" \"$vm27_target_pid\"\n    vm27_before=$(vm27_identity_row \"$vm27_target_pid\" \"$vm27_target_uid\" \"$vm27_target_path\")\n    if test -z \"$vm27_before\" || test \"$vm27_before\" != \"$vm27_selected\"; then\n        printf 'TARGET_SKIPPED target=%s pid=%s reason=identityChangedBeforeSampling sampleAttempts=0\\n' \"$vm27_target_name\" \"$vm27_target_pid\"\n        return\n    fi\n    printf 'TARGET_IDENTITY_BEFORE target=%s row=%s observedStable=1 atomicIdentityLease=0\\n' \"$vm27_target_name\" \"$vm27_before\"\n    printf 'SAMPLE_BEGIN target=%s pid=%s nativeDurationSeconds=1 intervalMilliseconds=10 sampleAttempts=1 retainedPayloadCapBytes=6144 binaryImagesExcluded=1\\n' \"$vm27_target_name\" \"$vm27_target_pid\"\n    {\n        /usr/bin/sample \"$vm27_target_pid\" 1 10 -file /dev/stdout 2>&1\n        vm27_native_sample_rc=$?\n        printf 'VM27_SAMPLE_TOOL_RETURN actualExit=%s\\n' \"$vm27_native_sample_rc\"\n    } | /usr/bin/awk '\n      BEGIN {cap=6144; used=0; seen=0; images=0; truncated=0}\n      /^VM27_SAMPLE_TOOL_RETURN actualExit=[0-9]+$/ {printf \"\\n%s\\n\",$0; fflush(); toolReturn=1; next}\n      /^Binary Images:/ {images=1; next}\n      !images {\n        line=$0 \"\\n\"; seen+=length(line); left=cap-used;\n        if(left>0) {chunk=substr(line,1,left); printf \"%s\",chunk; used+=length(chunk); fflush()}\n        if(seen>cap)truncated=1\n      }\n      END {\n        printf \"\\nSAMPLE_STREAM_RETURN retainedPayloadBytes=%d payloadTruncated=%d binaryImagesSectionSeen=%d actualToolReturnSeen=%d\\n\",used,truncated,images,toolReturn;\n        fflush()\n      }'\n    vm27_stream_rc=$?\n    printf 'SAMPLE_FILTER_RETURN target=%s filterExit=%s sampleExitReportedOnlyByToolReturnMarker=1\\n' \"$vm27_target_name\" \"$vm27_stream_rc\"\n    vm27_after=$(vm27_identity_row \"$vm27_target_pid\" \"$vm27_target_uid\" \"$vm27_target_path\")\n    if test -n \"$vm27_after\" && test \"$vm27_after\" = \"$vm27_before\"; then\n        printf 'TARGET_IDENTITY_AFTER target=%s pid=%s observedSameBeforeAfter=1 snapshotNonAtomic=1\\n' \"$vm27_target_name\" \"$vm27_target_pid\"\n    else\n        printf 'TARGET_IDENTITY_AFTER target=%s pid=%s observedSameBeforeAfter=0 sampleIdentityUnproven=1\\n' \"$vm27_target_name\" \"$vm27_target_pid\"\n    fi\n}\n\nvm27_sample_fixed_target loginwindow 0 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow\nvm27_sample_fixed_target SecurityAgent 92 /System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent\n\nprintf 'LOGIN_SESSION_LOG_BEGIN relativeWindow=2m processes=loginwindow,SecurityAgent retainedPayloadCapBytes=1536 debugOrInfoExpansion=0\\n'\n{\n    /usr/bin/log show --style compact --last 2m --predicate '(process == \"loginwindow\") OR (process == \"SecurityAgent\")' 2>&1\n    vm27_native_log_rc=$?\n    printf 'VM27_LOG_TOOL_RETURN actualExit=%s\\n' \"$vm27_native_log_rc\"\n} | /usr/bin/awk '\n  BEGIN {cap=1536; used=0; seen=0; truncated=0}\n  /^VM27_LOG_TOOL_RETURN actualExit=[0-9]+$/ {printf \"\\n%s\\n\",$0; fflush(); toolReturn=1; next}\n  {\n    line=$0 \"\\n\"; seen+=length(line); left=cap-used;\n    if(left>0) {chunk=substr(line,1,left); printf \"%s\",chunk; used+=length(chunk); fflush()}\n    if(seen>cap)truncated=1\n  }\n  END {\n    printf \"\\nLOGIN_SESSION_LOG_STREAM_RETURN retainedPayloadBytes=%d payloadTruncated=%d actualToolReturnSeen=%d\\n\",used,truncated,toolReturn;\n    fflush()\n  }'\nprintf 'LOGIN_SESSION_LOG_FILTER_RETURN filterExit=%s logExitReportedOnlyByToolReturnMarker=1\\n' \"$?\"\nprintf 'VM27_LOGIN_SESSION_DIAGNOSTIC_RETURN readOnly=1 nativeSampleAttemptsPerTargetAtMost=1 wholeScriptWallDeadline=none\\n'\n\n} 2>&1 | LC_ALL=C /usr/bin/awk 'BEGIN {left=16384} {line=$0 ORS; if(length(line)>left)line=substr(line,1,left); if(length(line)){printf \"%s\",line; fflush(); left-=length(line)}}'\n";
    __block BOOL accepted=NO;
    QGASyncV3(^{
        if(gGuestOwnedOperationV3 || gGuestCleanupUnresolvedV5 ||
           gGuestWriteDescriptor<0 || gGuestReadDescriptor!=gGuestWriteDescriptor ||
           !gGuestSocketConnection || !gGuestCallbacks) return;
        accepted=YES;
        /* Already on the same serial owner queue: no guest wait or takeover. */
        VZGuestToolsRun(@"/bin/sh", @[@"-c", script], ^(BOOL success, NSData *output) {
            NSUInteger count=MIN(output.length,(NSUInteger)16384);
            NSData *bounded=count ? [output subdataWithRange:NSMakeRange(0,count)] : [NSData data];
            if(completion)completion(success,bounded);
        });
    });
    return accepted;
}

#include "vm27_persistent_ssh_script_v4.inc"
void VZGuestToolsEnsurePersistentSSHV3(void (^completion)(BOOL,NSData *)) {
 if(!completion)return;
 dispatch_async(QGAQueueV3(),^{
  void (^finished)(BOOL,NSData *)=^(BOOL ok,NSData *data) {
   dispatch_async(dispatch_get_main_queue(),^{completion(ok,data?:[NSData data]);});
  };
  if(getuid()!=501 || geteuid()!=501 || gGuestWriteDescriptor<0 || gGuestCleanupUnresolvedV5) {
   finished(NO,[@"Guest agent is not connected." dataUsingEncoding:NSUTF8StringEncoding]);return;
  }
  NSData *artifact=VM27ReadSignedGuestActiveSSHResourceV1();
  if(!artifact){finished(NO,[@"The signed SSH guest helper is unavailable." dataUsingEncoding:NSUTF8StringEncoding]);return;}
  VM27OwnedQGAOperationV5 *operation=BeginQGAOperationV3(finished);if(!operation)return;
  NSString *token=[[NSUUID.UUID.UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
  NSString *stage=[@"/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f/.install-" stringByAppendingString:token];
  NSString *pending=[stage stringByAppendingPathComponent:@"helper.pending"];
  NSString *prepare=[NSString stringWithFormat:
   @"set -eu\n[ \"$(/usr/bin/id -u)\" = 0 ] && [ \"$(/usr/bin/id -ru)\" = 0 ]\n"
   "ROOT='/Library/Application Support/VM27OwnedSSH-v2-33547b92f6f7bf5f'\n"
   "for p in /Library '/Library/Application Support';do [ -d \"$p\" ] && [ ! -L \"$p\" ];[ \"$(cd -P \"$p\" && /bin/pwd -P)\" = \"$p\" ];[ \"$(/usr/bin/stat -f '%%u' \"$p\")\" = 0 ];done\n"
   "if [ ! -e \"$ROOT\" ] && [ ! -L \"$ROOT\" ];then /bin/mkdir -m 755 \"$ROOT\";/usr/sbin/chown root:wheel \"$ROOT\";fi\n"
   "[ -d \"$ROOT\" ] && [ ! -L \"$ROOT\" ]\n[ \"$(cd -P \"$ROOT\" && /bin/pwd -P)\" = \"$ROOT\" ]\n[ \"$(/usr/bin/stat -f '%%u:%%g:%%Lp' \"$ROOT\")\" = 0:0:755 ]\n"
   "if [ -f \"$ROOT/vm27-guest-vsock-ssh\" ] && [ ! -L \"$ROOT/vm27-guest-vsock-ssh\" ];then printf 'VM27_HELPER_PRESENT\\n';exit 0;fi\n"
   "[ ! -e \"$ROOT/vm27-guest-vsock-ssh\" ] && [ ! -L \"$ROOT/vm27-guest-vsock-ssh\" ]\n"
   "STAGE='%@'\n[ ! -e \"$STAGE\" ] && [ ! -L \"$STAGE\" ]\numask 077\n/bin/mkdir -m 700 \"$STAGE\"\n(set -C;: > \"$STAGE/helper.pending\")\n"
   "[ \"$(/usr/bin/stat -f '%%u:%%g:%%Lp:%%l:%%z' \"$STAGE/helper.pending\")\" = 0:0:600:1:0 ]\nprintf 'VM27_HELPER_UPLOAD_REQUIRED\\n'\n",stage];
  OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",prepare],^(BOOL prepared,NSData *output) {
   if(![operation isLive]||!prepared){[operation finish:NO output:output];return;}
   NSString *reply=[[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]autorelease];
   BOOL present=[reply isEqualToString:@"VM27_HELPER_PRESENT\n"];
   if(!present && ![reply isEqualToString:@"VM27_HELPER_UPLOAD_REQUIRED\n"]){[operation finish:NO output:output];return;}
   void (^install)(void)=^{
    NSString *script=[[NSString stringWithUTF8String:VM27PersistentSSHScriptV4] stringByReplacingOccurrencesOfString:@"@PENDING@" withString:pending];
    OwnedQGARunV3(operation,@"/bin/sh",@[@"-c",script],^(BOOL ok,NSData *result) {
     NSString *text=[[[NSString alloc]initWithData:result encoding:NSUTF8StringEncoding]autorelease];
     BOOL marker=text && [text rangeOfString:@"VM27_GUEST_PERSISTENT_SSH_READY"].location!=NSNotFound;
     [operation finish:ok&&marker output:result];
    });
   };
   if(present)install();
   else OwnedQGAWriteFileV3(operation,pending,artifact,^(BOOL uploaded){
    if(![operation isLive]||!uploaded){[operation finish:NO output:[@"The signed SSH helper upload did not complete." dataUsingEncoding:NSUTF8StringEncoding]];return;}install();
   });
  });
 });
}

BOOL VZGuestToolsCanProvisionSSHV4(void) {
 __block BOOL ready=NO;
 QGASyncV3(^{
  ready=getuid()==501 && geteuid()==501 && gGuestProvisioningStarted &&
   gGuestSocketConnection!=nil && gGuestWriteDescriptor>=0 &&
   !gGuestCleanupUnresolvedV5 && !gGuestOwnedOperationV3;
 });
 return ready;
}
