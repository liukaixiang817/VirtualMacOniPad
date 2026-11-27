// New-guest radio lifecycle. Runs through the Apple guest agent and launchd;
// it does not require SSH, a fixed account, or the optional Guest Tools App.
#import <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/kext/KextManager.h>
#include <libproc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include "VM27RadioFirstBootPolicyV1.h"
#include "VM27RadioGuestProfileV1.h"

static NSString *const Root = @"/Library/VirtualMac/SharedRadio";
static NSString *const BluetoothRoot = @"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";

static NSDictionary *readPlist(NSString *path) {
    struct stat st;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 ||
        (st.st_mode & 0022) || st.st_size < 1 || st.st_size > 262144) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t n = read(fd, (uint8_t *)data.mutableBytes + offset, data.length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return nil; }
        offset += (NSUInteger)n;
    }
    close(fd);
    id value = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}
static BOOL savePlist(NSDictionary *value, NSString *path) {
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    return data && [data writeToFile:path options:NSDataWritingAtomic error:NULL] &&
        chmod(path.fileSystemRepresentation,0600) == 0;
}
static BOOL radioArgumentsReady(NSString *arguments) {
    if(![arguments isKindOfClass:NSString.class]||arguments.length>8192)return NO;
    NSSet *tokens=[NSSet setWithArray:[arguments componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]];
    for(NSString *required in @[@"amfi_get_out_of_my_way=1",@"bt-transport-override=10",@"-arm64e_preview_abi",@"mtknative=1"])
        if(![tokens containsObject:required])return NO;
    return YES;
}
static BOOL configuredArgumentsReady(void) {
    NSTask *task=[NSTask new];NSPipe *output=[NSPipe pipe];
    task.executableURL=[NSURL fileURLWithPath:@"/usr/sbin/nvram"];task.arguments=@[@"boot-args"];
    task.standardInput=NSFileHandle.fileHandleWithNullDevice;task.standardOutput=output;task.standardError=NSFileHandle.fileHandleWithNullDevice;
    if(![task launchAndReturnError:NULL])return NO;
    double deadline=NSProcessInfo.processInfo.systemUptime+5;
    while(task.running&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(10000);
    if(task.running){[task terminate];usleep(100000);if(task.running)kill(task.processIdentifier,SIGKILL);}
    [task waitUntilExit];NSData *data=[output.fileHandleForReading readDataToEndOfFile];
    if(task.terminationStatus||data.length>8192)return NO;
    NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    return [text hasPrefix:@"boot-args\t"]&&radioArgumentsReady([text substringFromIndex:10]);
}

static int run(NSString *program, NSArray<NSString *> *arguments) {
    NSTask *task = [NSTask new];
    task.executableURL = [NSURL fileURLWithPath:program]; task.arguments = arguments;
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
    task.standardError = NSFileHandle.fileHandleWithNullDevice;
    if (![task launchAndReturnError:NULL]) return EIO;
    double timeout = [program hasSuffix:@"RadioOwnerAuthorizationV1"] ? 420 :
                     [program isEqual:@VM27_RADIO_PREPARE_PATH] ? 120 : 20;
    double deadline = NSProcessInfo.processInfo.systemUptime + timeout;
    while (task.running && NSProcessInfo.processInfo.systemUptime < deadline) usleep(100000);
    BOOL expired = task.running;
    if (expired) { [task terminate]; usleep(100000); if (task.running) kill(task.processIdentifier, SIGKILL); }
    [task waitUntilExit];
    return expired ? ETIMEDOUT : task.terminationStatus;
}

static BOOL serviceLoaded(NSString *label) {
    return run(@"/bin/launchctl", @[@"print", [@"system/" stringByAppendingString:label]]) == 0;
}

static BOOL startJob(NSString *label) {
    if (serviceLoaded(label)) return YES;
    NSString *path = [[@"/Library/LaunchDaemons" stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"];
    NSDictionary *job = readPlist(path);
    return [job[@"Label"] isEqual:label] && run(@"/bin/launchctl", @[@"bootstrap", @"system", path]) == 0;
}
static BOOL startBluetoothJob(NSString *label) {
    NSString *name = [label stringByAppendingPathExtension:@"plist"];
    NSDictionary *job = readPlist([BluetoothRoot stringByAppendingPathComponent:name]);
    if (![job[@"Label"] isEqual:label]) return NO;
    NSString *path = [@"/Library/LaunchDaemons" stringByAppendingPathComponent:name];
    struct stat st;
    if (!lstat(path.fileSystemRepresentation, &st)) {
        if (![readPlist(path) isEqual:job]) return NO;
    } else {
        if (errno != ENOENT) return NO;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:job format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        if (![data writeToFile:path options:NSDataWritingWithoutOverwriting error:NULL] || chmod(path.fileSystemRepresentation,0644)) return NO;
    }
    return startJob(label);
}

static BOOL registryClass(const char *name, CFMutableDictionaryRef *properties) {
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
    if (!service) return NO;
    BOOL found = !properties || IORegistryEntryCreateCFProperties(service, properties, kCFAllocatorDefault, 0) == KERN_SUCCESS;
    IOObjectRelease(service); return found;
}

static NSDictionary *constructorStatus(void) {
    NSString *path = [BluetoothRoot stringByAppendingPathComponent:@VM27_RADIO_BLUETOOTH_CONSTRUCTOR];
    struct stat st;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    char bytes[4096]; ssize_t size = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && !st.st_uid && st.st_nlink == 1 &&
        !(st.st_mode & 0077) && st.st_size > 0 && (uint64_t)st.st_size < sizeof(bytes)) size = read(fd, bytes, (size_t)st.st_size);
    close(fd);
    id value = size > 0 ? [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:(NSUInteger)size] options:0 error:NULL] : nil;
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

int main(int argc, char **argv) { @autoreleasepool {
    BOOL statusOnly = argc == 2 && !strcmp(argv[1], "--status");
    BOOL coldShutdown=NO,requestColdRestart=NO;
#if defined(VM27_RADIO_GUEST_BUILD_26B131)
    coldShutdown=argc==3&&!strcmp(argv[1],"--cold-shutdown");
    requestColdRestart=argc==2&&!strcmp(argv[1],"--request-cold-restart");
#endif
    if (((argc != 2 || (!statusOnly && !requestColdRestart && strcmp(argv[1], "--check-once"))) && !coldShutdown) || geteuid()) return EPERM;
    char build[32] = {0}, boot[64] = {0}, args[8192] = {0}; size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) || strcmp(build, VM27_RADIO_GUEST_BUILD)) return ENOTSUP;
    size = sizeof(boot); if (sysctlbyname("kern.bootsessionuuid", boot, &size, NULL, 0)) return EIO;
    size = sizeof(args); if (sysctlbyname("kern.bootargs", args, &size, NULL, 0)) return EIO;
    struct stat st;
    if (lstat(Root.fileSystemRepresentation, &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0077)) return EPERM;
    int lock = open([[Root stringByAppendingPathComponent:@"FirstBoot.lock"] fileSystemRepresentation],
                    (statusOnly ? O_RDONLY : O_RDWR | O_CREAT) | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0) return errno;
    if (fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 ||
        (st.st_mode & 0777) != 0600 || (!statusOnly && flock(lock, LOCK_EX | LOCK_NB))) { close(lock); return EBUSY; }
    NSDictionary *installed = readPlist([Root stringByAppendingPathComponent:@"Provisioning.plist"]);
    if (![installed[@"GuestBuild"] isEqual:@VM27_RADIO_GUEST_BUILD] || ![installed[@"CombinedInstallation"] isEqual:@YES]) { close(lock); return EPERM; }
    NSString *package = installed[@"PackagePath"];
    if (![package isKindOfClass:NSString.class] || ![package hasPrefix:[Root stringByAppendingString:@"/Packages/"]]) { close(lock); return EPERM; }
    NSDictionary *manifest = readPlist([package stringByAppendingPathComponent:@"Package.plist"]);
    NSString *expectedDriver = manifest[@"CombinedInstallation"][@"DriverVersion"];
    if (![expectedDriver isKindOfClass:NSString.class] || ![expectedDriver length]) { close(lock); return EPERM; }
    NSDictionary *driverInfo = readPlist(@"/Library/Extensions/VM27SharedRadioNativeV1.kext/Contents/Info.plist");
    BOOL driverInstalled = [driverInfo[@"CFBundleVersion"] isEqual:expectedDriver];
    CFMutableDictionaryRef cfProperties = NULL;
    BOOL driverLoaded = registryClass("VM27SharedRadioBackendV1", &cfProperties);
    NSDictionary *properties = CFBridgingRelease(cfProperties);
    (void)properties;
    NSDictionary *loaded = CFBridgingRelease(KextManagerCopyLoadedKextInfo(
        (__bridge CFArrayRef)@[@"com.virtualmac.SharedRadioNativeV1"],
        (__bridge CFArrayRef)@[@"CFBundleVersion"]));
    BOOL currentDriver = driverLoaded &&
        [loaded[@"com.virtualmac.SharedRadioNativeV1"][@"CFBundleVersion"] isEqual:expectedDriver];
    // The IEEE80211 interface is a separate acceptance condition from kext
    // presence: mtknative=0 deliberately loads only the inert backend.
    BOOL wifiInterface = currentDriver && registryClass("VM27SharedWiFiInterfaceV1", NULL);
    BOOL argumentsReady = radioArgumentsReady(@(args));
    BOOL nvramReady = argumentsReady || configuredArgumentsReady();
    int (*csrConfig)(uint32_t *) = dlsym(RTLD_DEFAULT, "csr_get_active_config"); uint32_t csr = 0;
    BOOL policyReadable = csrConfig && !csrConfig(&csr);
    VM27RadioFirstBootPolicyV1 policy = VM27RadioEvaluateFirstBootPolicyV1(policyReadable,csr,argumentsReady);
    BOOL bootReady = policy.radioActivationAllowed;
    NSString *receiptPath = [Root stringByAppendingPathComponent:@"Activation.plist"];
    NSDictionary *prior = readPlist(receiptPath);
#if defined(VM27_RADIO_GUEST_BUILD_26B131)
    BOOL currentColdRequest=[prior[@"BootUUID"] isEqual:@(boot)] &&
        [prior[@"PackageManifestSHA256"] isEqual:installed[@"PackageManifestSHA256"]] &&
        [prior[@"ColdRestartRequired"] isEqual:@YES] &&
        [prior[@"ColdRestartRequestID"] isKindOfClass:NSString.class] &&
        [[NSUUID alloc]initWithUUIDString:prior[@"ColdRestartRequestID"]];
    if(coldShutdown) {
        if(!currentColdRequest || ![prior[@"ColdRestartRequestID"] isEqual:@(argv[2])]){close(lock);return EPERM;}
        close(lock);return run(@"/sbin/shutdown",@[@"-h",@"now"]);
    }
    if(requestColdRestart) {
        // Explicit root maintenance request, also used to validate the same
        // normal shutdown/host teardown path after updating the radio tools.
        if(!driverInstalled || !bootReady){close(lock);return EPERM;}
        NSMutableDictionary *request=[prior mutableCopy]?:[NSMutableDictionary new];
        request[@"Schema"]=@1;request[@"GuestBuild"]=@VM27_RADIO_GUEST_BUILD;
        request[@"BootUUID"]=@(boot);request[@"PackageManifestSHA256"]=installed[@"PackageManifestSHA256"];
        request[@"State"]=@"native-activation-reboot-required";request[@"ColdRestartRequired"]=@YES;
        request[@"ColdRestartRequestID"]=NSUUID.UUID.UUIDString;
        if(!savePlist(request,receiptPath)){close(lock);return EIO;}
        prior=request;currentColdRequest=YES;
    }
    if(currentColdRequest) {
        NSData *output=[NSJSONSerialization dataWithJSONObject:prior options:NSJSONWritingSortedKeys error:NULL];
        if(output){fwrite(output.bytes,1,output.length,stdout);putchar('\n');}
        close(lock);return 0;
    }
#endif
    NSString *progressPath = [Root stringByAppendingPathComponent:@"ActivationProgress.plist"];
    NSDictionary *savedProgress = readPlist(progressPath);
    if (!savedProgress && (!lstat(progressPath.fileSystemRepresentation,&st) || errno != ENOENT)) { close(lock); return EPERM; }
    NSMutableDictionary *progress = [savedProgress[@"PackageManifestSHA256"] isEqual:installed[@"PackageManifestSHA256"]] ?
        [savedProgress mutableCopy] : [@{@"Schema":@1,@"PackageManifestSHA256":installed[@"PackageManifestSHA256"]} mutableCopy];
    BOOL policyRestartRecorded = [progress[@"PolicyRestartBootUUID"] isKindOfClass:NSString.class];
    BOOL driverRestartRecorded = [progress[@"DriverRestartBootUUID"] isKindOfClass:NSString.class];
    BOOL handoffRestartRecorded = [progress[@"ConsoleHandoffRestartBootUUID"] isKindOfClass:NSString.class];
    if(!statusOnly && policy.ownerPolicyNeeded && !handoffRestartRecorded &&
       !policyRestartRecorded && !driverRestartRecorded) {
        BOOL changed=NO;
        if(run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1",@[@"--setup-assistant-active"])==0 &&
           ![progress[@"SetupAssistantObservedBootUUID"] isEqual:@(boot)]) {
            progress[@"SetupAssistantObservedBootUUID"]=@(boot);changed=YES;
        }
        if(run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1",@[@"--owner-session-visible"])==0 &&
           ![progress[@"OwnerVisibleObservedBootUUID"] isEqual:@(boot)]) {
            progress[@"OwnerVisibleObservedBootUUID"]=@(boot);changed=YES;
        }
        if(changed&&!savePlist(progress,progressPath)){close(lock);return EIO;}
    }
    BOOL tried = [prior[@"LoadAttemptBootUUID"] isEqual:@(boot)] &&
        [prior[@"LoadAttemptPackage"] isEqual:installed[@"PackageManifestSHA256"]];
    NSMutableDictionary *report = [@{@"Schema":@1, @"GuestBuild":@VM27_RADIO_GUEST_BUILD, @"BootUUID":@(boot),
        @"PackageManifestSHA256":installed[@"PackageManifestSHA256"],
        @"DriverInstalled":@(driverInstalled), @"DriverLoaded":@(currentDriver),
        @"NativeWiFiInterfaceCreated":@(wifiInterface), @"BluetoothBootConfigured":@(bootReady),
        @"CSRReadbackAvailable":@(policyReadable), @"CSRConfig":@(csr),
        @"CSRRequiredMask":@(VM27_RADIO_CSR_REQUIRED_V1), @"GuestPolicyConfigured":@(policy.policyReady),
        @"BootArgumentsConfigured":@(argumentsReady),
        @"BootArgumentsWrittenToNVRAM":@(nvramReady),
        @"WiFiConnectionVerified":@NO, @"BluetoothPairingVerified":@NO,
        @"FirstPairingRequested":@NO, @"SecurityPolicyChanged":@NO} mutableCopy];
    for (NSString *key in @[@"LoadAttemptBootUUID", @"LoadAttemptPackage", @"NativeLoadExit",
                            @"OwnerPolicyAttemptBootUUID", @"OwnerPolicyExit", @"DriverApprovalExit", @"BootImagesPrepared", @"BootImagesPreparationExit"])
        if (prior[key]) report[key] = prior[key];
    if(currentDriver&&report[@"NativeLoadExit"]){report[@"LastNativeLoadExit"]=report[@"NativeLoadExit"];[report removeObjectForKey:@"NativeLoadExit"];}
    BOOL restart = NO;
    BOOL setupResumeReady = YES;
#if VM27_RADIO_GUEST_MAJOR == 15
    if (!statusOnly && !currentDriver) {
        BOOL canFinish = run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1", @[@"--ready-for-owner-ui"]) == 0 ||
            run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1", @[@"--ready-for-restart"]) == 0;
        int settle = canFinish ? run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1", @[@"--settle-completed-setup-resume"]) : EAGAIN;
        report[@"CompletedSetupResumeExit"] = @(settle);
        setupResumeReady = settle == 0;
    }
#endif
    if(!statusOnly&&setupResumeReady&&policy.ownerPolicyNeeded&&!policyRestartRecorded&&!driverRestartRecorded&&!handoffRestartRecorded&&
       run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1",@[@"--ready-for-restart"])==0&&
       run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1",@[@"--ready-for-owner-ui"])==EAGAIN) {
        // Fresh restore can finish account setup in a background owner
        // session while Setup User still owns the screen. Finish that handoff
        // once before showing an owner alert. Full Security may legitimately
        // filter boot arguments until the following owner-policy stage.
        progress[@"ConsoleHandoffRestartBootUUID"]=@(boot);
        if(!savePlist(progress,progressPath)){close(lock);return EIO;}
        report[@"RestartStage"]=@"finish-setup-console-handoff";restart=YES;
    }
    if (!statusOnly && setupResumeReady && !restart && VM27RadioStageMayRunV1(policy.ownerPolicyNeeded,policyRestartRecorded) && ![prior[@"OwnerPolicyAttemptBootUUID"] isEqual:@(boot)]) {
        int auth = run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1", @[@"--policy"]);
        // No console owner yet: retry after Setup Assistant/login completes.
        // Cancelled/rejected authentication gets at most one prompt per boot.
        if (auth != EAGAIN) report[@"OwnerPolicyAttemptBootUUID"] = @(boot);
        report[@"OwnerPolicyExit"] = @(auth); restart = auth == 0;
        if (restart) { progress[@"PolicyRestartBootUUID"] = @(boot); if (!savePlist(progress,progressPath)) { close(lock); return EIO; } }
    }
    if (!statusOnly && setupResumeReady && driverInstalled && bootReady && VM27RadioStageMayRunV1(!currentDriver,driverRestartRecorded) && !tried) {
        int prepared = run(@VM27_RADIO_PREPARE_PATH, @[]);
        report[@"BootImagesPrepared"] = @(prepared == 0);
        report[@"BootImagesPreparationExit"] = @(prepared);
        if (!prepared) {
            report[@"LoadAttemptBootUUID"] = @(boot);
            report[@"LoadAttemptPackage"] = installed[@"PackageManifestSHA256"];
            // The first normal request must register native pending approval.
            // --no-authorization is valid only after our exact-driver approval
            // succeeds; using it here skips registration and fails staging.
            int load = run(@"/usr/bin/kmutil", @[@"load", @"-p", @"/Library/Extensions/VM27SharedRadioNativeV1.kext"]);
            report[@"NativeLoadExit"] = @(load);
            if (load == 28) {
                // Already approved and staged for KcgenOS. Do not request
                // another owner credential for an empty pending list.
                restart = YES;
            } else if (load == 27) {
                int approved = run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1", @[@"--approve-driver"]);
                report[@"DriverApprovalExit"] = @(approved);
                if(approved==EAGAIN){[report removeObjectForKey:@"LoadAttemptBootUUID"];[report removeObjectForKey:@"LoadAttemptPackage"];}
                if (!approved) {
                    load = run(@"/usr/bin/kmutil", @[@"load", @"--no-authorization", @"-p", @"/Library/Extensions/VM27SharedRadioNativeV1.kext"]);
                    report[@"NativeLoadExit"] = @(load); restart = load == 28 || load == 0;
                }
            } else if (!load) restart = YES;
            if (restart) { progress[@"DriverRestartBootUUID"] = @(boot); if (!savePlist(progress,progressPath)) { close(lock); return EIO; } }
        }
    }
    BOOL daemon = [properties[@"HostRadioClientOnline"] boolValue];
    if (!statusOnly && !serviceLoaded(@"com.virtualmac.shared-radio-native-v1"))
        startJob(@"com.virtualmac.shared-radio-native-v1");
    BOOL btStarted = statusOnly && serviceLoaded(@"com.virtualmac.exclusive-bluetooth-relay-v1") &&
        serviceLoaded(@"com.virtualmac.exclusive-bluetooth-autoload-v1") && serviceLoaded(@"com.virtualmac.exclusive-bluetooth-hogp-v1");
    if (bootReady && !statusOnly && !restart) {
        // No first pairing here. Prepare generates this VM's private token and
        // an empty native-HID configuration; the guest initiates new pairing.
        BOOL prepared = run([BluetoothRoot stringByAppendingPathComponent:@"exclusive-guest-provision-v1"], @[@"--prepare", @(boot)]) == 0;
        if (prepared) {
            btStarted = startBluetoothJob(@"com.virtualmac.exclusive-bluetooth-relay-v1") &&
                        startBluetoothJob(@"com.virtualmac.exclusive-bluetooth-autoload-v1") &&
                        startBluetoothJob(@"com.virtualmac.exclusive-bluetooth-hogp-v1");
        }
    }
    NSDictionary *constructor = constructorStatus();
    pid_t pid = [constructor[@"bluetoothdPID"] intValue]; char executable[PROC_PIDPATHINFO_MAXSIZE] = {0};
    BOOL btLive = pid > 1 && [constructor[@"bootUUID"] isEqual:@(boot)] &&
        [constructor[@"installerResult"] isEqual:@0] &&
        proc_pidpath(pid, executable, sizeof(executable)) > 0 && !strcmp(executable, "/usr/sbin/bluetoothd");
    report[@"RadioDaemonRunning"] = @(daemon); report[@"BluetoothJobsStarted"] = @(btStarted);
    report[@"BluetoothNativeTransportLoaded"] = @(btLive);
    report[@"State"] = restart ? @"native-activation-reboot-required" : !policyReadable ? @"policy-readback-unavailable" :
        !policy.policyReady ? (policyRestartRecorded ? @"guest-policy-requires-attention" : @"guest-policy-required") : !argumentsReady ? @"boot-arguments-require-attention" :
        !currentDriver ? (driverRestartRecorded ? @"native-driver-requires-attention" : @"native-driver-activation-required") :
        !wifiInterface ? @"native-wifi-interface-disabled" :
        !(btLive && daemon) ? @"starting-radio-services" : @"native-radio-components-ready";
    if (!statusOnly) {
#if defined(VM27_RADIO_GUEST_BUILD_26B131)
        if(restart){report[@"ColdRestartRequired"]=@YES;report[@"ColdRestartRequestID"]=NSUUID.UUID.UUIDString;}
#endif
        if (!savePlist(report,receiptPath)) { close(lock); return EIO; }
    }
    NSData *output = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL];
    if (output) { fwrite(output.bytes, 1, output.length, stdout); putchar('\n'); }
#if !defined(VM27_RADIO_GUEST_BUILD_26B131)
    if (restart && !statusOnly) { fflush(stdout); run(@"/sbin/shutdown", @[@"-r", @"now"]); }
#endif
    close(lock); return 0;
} }
