// Stage a build-specific radio package through the existing Apple guest agent.
// This never treats installed files as proof of association, pairing, or boot policy.
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
#include "VM27RadioGuestProfileV1.h"
extern char **environ;

static NSData *ReadFile(NSString *path, uid_t owner, NSUInteger limit) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return nil;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != owner ||
        st.st_nlink != 1 || (st.st_mode & 0022) || st.st_size < 0 ||
        (uint64_t)st.st_size > limit) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    NSUInteger at = 0;
    while (at < data.length) {
        ssize_t n = read(fd, (uint8_t *)data.mutableBytes + at, data.length - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return nil; }
        at += (NSUInteger)n;
    }
    close(fd); return data;
}
static NSString *SHA(NSData *data) {
    if (!data) return nil;
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, bytes);
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (unsigned i = 0; i < sizeof(bytes); ++i) [text appendFormat:@"%02x", bytes[i]];
    return text;
}
static BOOL HashString(id value) {
    return [value isKindOfClass:NSString.class] && [value length] == 64 &&
        [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location == NSNotFound;
}
static BOOL RelativePath(id path) {
    if (![path isKindOfClass:NSString.class] || ![path length] || [path length] > 512 ||
        [path isAbsolutePath] || ![[path stringByStandardizingPath] isEqual:path]) return NO;
    for (NSString *part in [path pathComponents])
        if ([part isEqual:@".."] || [part isEqual:@"."]) return NO;
    return YES;
}
static BOOL SafeDirectory(NSString *path, uid_t owner) {
    struct stat st;
    return !lstat(path.fileSystemRepresentation, &st) && S_ISDIR(st.st_mode) &&
        st.st_uid == owner && !(st.st_mode & 0022);
}
static NSDictionary *Validate(NSString *root, uid_t owner, NSString *expected) {
    char canonical[PATH_MAX];
    if (!HashString(expected) || !realpath(root.fileSystemRepresentation, canonical) ||
        ![root isEqual:@(canonical)] || !SafeDirectory(root, owner)) return nil;
    NSData *data = ReadFile([root stringByAppendingPathComponent:@"Package.plist"], owner, 262144);
    if (![SHA(data) isEqual:expected]) return nil;
    NSDictionary *manifest = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    if (![manifest isKindOfClass:NSDictionary.class] || ![manifest[@"Schema"] isEqual:@1] ||
        ![manifest[@"GuestBuild"] isKindOfClass:NSString.class] ||
        ![manifest[@"Files"] isKindOfClass:NSDictionary.class] ||
        ![manifest[@"Files"] count] || [manifest[@"Files"] count] > 256) return nil;
    NSDictionary *files = manifest[@"Files"];
    NSMutableSet *allowed = [NSMutableSet setWithObject:@"Package.plist"];
    for (id relative in files) {
        NSDictionary *entry = files[relative];
        if (!RelativePath(relative) || ![entry isKindOfClass:NSDictionary.class] ||
            !HashString(entry[@"SHA256"]) ||
            !([entry[@"Mode"] isEqual:@0600] || [entry[@"Mode"] isEqual:@0700])) return nil;
        NSString *parent = [relative stringByDeletingLastPathComponent];
        while (parent.length) {
            if (!SafeDirectory([root stringByAppendingPathComponent:parent], owner)) return nil;
            [allowed addObject:parent]; parent = [parent stringByDeletingLastPathComponent];
        }
        NSString *path = [root stringByAppendingPathComponent:relative];
        if (![SHA(ReadFile(path, owner, 16 * 1024 * 1024)) isEqual:entry[@"SHA256"]]) return nil;
        [allowed addObject:relative];
    }
    NSDirectoryEnumerator *enumerator = [NSFileManager.defaultManager enumeratorAtPath:root];
    for (NSString *relative in enumerator) if (![allowed containsObject:relative]) return nil;
    return manifest;
}
static BOOL WritePlist(NSDictionary *object, NSString *path) {
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    return data && [data writeToFile:path options:NSDataWritingAtomic error:NULL] &&
        chmod(path.fileSystemRepresentation, 0600) == 0;
}
static BOOL EnsureDirectory(NSString *path, mode_t mode) {
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st)) {
        if (errno != ENOENT || mkdir(path.fileSystemRepresentation, mode)) return NO;
    }
    return SafeDirectory(path, 0);
}
static BOOL CopyNewOrIdentical(NSString *source, NSString *destination, mode_t mode) {
    NSData *data = ReadFile(source, 0, 16 * 1024 * 1024);
    if (!data) return NO;
    struct stat st;
    if (!lstat(destination.fileSystemRepresentation, &st)) {
        // Installation retries cannot replace an unrelated helper or a newer
        // development version. A package migration has to be explicit.
        return [ReadFile(destination, 0, 16 * 1024 * 1024) isEqual:data] &&
            (st.st_mode & 07777) == mode;
    }
    if (errno != ENOENT) return NO;
    int fd = open(destination.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return NO;
    NSUInteger offset = 0; BOOL good = YES;
    while (offset < data.length) {
        ssize_t n = write(fd, (const uint8_t *)data.bytes + offset, data.length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { good = NO; break; }
        offset += (NSUInteger)n;
    }
    if (fchmod(fd, mode) || fsync(fd)) good = NO;
    close(fd);
    if (!good) unlink(destination.fileSystemRepresentation);
    return good;
}
static BOOL CopyDriver(NSString *package, NSDictionary *manifest) {
    NSString *prefix = @"VM27SharedRadioNativeV1.kext/";
    NSString *target = @"/Library/Extensions/VM27SharedRadioNativeV1.kext";
    if (!EnsureDirectory(@"/Library/Extensions", 0755) || !EnsureDirectory(target, 0755)) return NO;
    NSMutableSet *expected = [NSMutableSet set];
    for (NSString *relative in [manifest[@"Files"] allKeys]) {
        if (![relative hasPrefix:prefix]) continue;
        NSString *subpath = [relative substringFromIndex:prefix.length];
        [expected addObject:subpath];
        NSString *parent = [subpath stringByDeletingLastPathComponent];
        NSMutableArray *parents = [NSMutableArray array];
        while (parent.length) { [parents insertObject:parent atIndex:0]; [expected addObject:parent]; parent = [parent stringByDeletingLastPathComponent]; }
        for (NSString *directory in parents)
            if (!EnsureDirectory([target stringByAppendingPathComponent:directory], 0755)) return NO;
        mode_t mode = [subpath hasPrefix:@"Contents/MacOS/"] ? 0755 : 0644;
        if (!CopyNewOrIdentical([package stringByAppendingPathComponent:relative], [target stringByAppendingPathComponent:subpath], mode)) return NO;
    }
    if (!expected.count) return NO;
    for (NSString *relative in [NSFileManager.defaultManager enumeratorAtPath:target])
        if (![expected containsObject:relative]) return NO;
    return YES;
}
static BOOL WriteNewOrIdenticalJob(NSDictionary *job, NSString *label) {
    NSString *path = [[@"/Library/LaunchDaemons" stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"];
    struct stat st;
    if (!lstat(path.fileSystemRepresentation, &st)) {
        NSData *data = ReadFile(path, 0, 65536);
        id prior = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL] : nil;
        return [prior isEqual:job] && (st.st_mode & 07777) == 0644;
    }
    return errno == ENOENT && WritePlist(job, path) && chmod(path.fileSystemRepresentation, 0644) == 0;
}
static BOOL InstallCombined(NSString *package, NSDictionary *manifest) {
    NSDictionary *combined = manifest[@"CombinedInstallation"];
    if (![combined isKindOfClass:NSDictionary.class] || ![combined[@"Schema"] isEqual:@1] ||
        ![combined[@"GuestBuild"] isEqual:@VM27_RADIO_GUEST_BUILD] ||
        ![combined[@"GuestPolicyChangesAutomatic"] isEqual:@NO]) return NO;
    NSString *helpers = @"/Library/PrivilegedHelperTools";
    NSString *bt = [helpers stringByAppendingPathComponent:@"VirtualMacSharedBluetoothClassicV1"];
    NSString *modules = @"/Library/Application Support/BTServer/VirtualMacSharedRadioDevelopment-v1";
    for (NSString *path in @[helpers, bt, @"/Library/Application Support", @"/Library/Application Support/BTServer", modules,
                            @"/Library/LaunchDaemons"])
        if (!EnsureDirectory(path, [path isEqual:bt] || [path isEqual:modules] ? 0700 : 0755)) return NO;
    if (!CopyDriver(package, manifest) ||
        !CopyNewOrIdentical([package stringByAppendingPathComponent:@"shared-radio-native-daemon"],
                           [helpers stringByAppendingPathComponent:@"com.virtualmac.SharedRadioNativeDaemonV1"], 0755) ||
        !CopyNewOrIdentical([package stringByAppendingPathComponent:@"radio-first-boot-v1"],
                           [helpers stringByAppendingPathComponent:@"com.virtualmac.RadioFirstBootV1"], 0755)) return NO;
    for(NSArray *entry in @[@[@VM27_RADIO_PREPARE_COMPONENT,@VM27_RADIO_PREPARE_HELPER],
                            @[@"radio-owner-authorization-v1",@"com.virtualmac.RadioOwnerAuthorizationV1"],
                            @[@"radio-approve-driver-v1",@"com.virtualmac.RadioApproveDriverV1"]])
        if(!CopyNewOrIdentical([package stringByAppendingPathComponent:entry[0]],
                              [helpers stringByAppendingPathComponent:entry[1]],0755))return NO;
    for(NSString *path in @[@"/Library/Preferences",@"/Library/Preferences/FeatureFlags",@"/Library/Preferences/FeatureFlags/Domain"])
        if(!EnsureDirectory(path,0755))return NO;
    NSString *features=@"/Library/Preferences/FeatureFlags/Domain/BluetoothFeatures.plist";
    struct stat featureStat;NSMutableDictionary *flags=[NSMutableDictionary dictionary];
    if(!lstat(features.fileSystemRepresentation,&featureStat)){
        NSData *data=ReadFile(features,0,65536);
        id value=data?[NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainers format:NULL error:NULL]:nil;
        if(![value isKindOfClass:NSDictionary.class])return NO;[flags addEntriesFromDictionary:value];
    }else if(errno!=ENOENT)return NO;
    id existing=flags[@"EnableBTVCLeConnection"];
    if(existing&&![existing isKindOfClass:NSDictionary.class])return NO;
    NSMutableDictionary *le=existing?[existing mutableCopy]:[NSMutableDictionary dictionary];le[@"Enabled"]=@YES;
    flags[@"EnableBTVCLeConnection"]=le;
    if(!WritePlist(flags,features)||chmod(features.fileSystemRepresentation,0644))return NO;
    NSString *source = [package stringByAppendingPathComponent:@"Bluetooth"];
    for (NSString *name in @[@"exclusive-early-autoload-v2", @"exclusive-guest-relay-v1",
                             @"exclusive-guest-provision-v1", @"exclusive-hogp-service-v1"])
        if (!CopyNewOrIdentical([source stringByAppendingPathComponent:name], [bt stringByAppendingPathComponent:name], 0700)) return NO;
    NSString *module = @VM27_RADIO_BLUETOOTH_MODULE;
    if (!CopyNewOrIdentical([source stringByAppendingPathComponent:module], [modules stringByAppendingPathComponent:module], 0600)) return NO;
    for (NSString *label in @[@"com.virtualmac.exclusive-bluetooth-autoload-v1", @"com.virtualmac.exclusive-bluetooth-relay-v1",
                              @"com.virtualmac.exclusive-bluetooth-hogp-v1"]) {
        NSData *data = ReadFile([[source stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"], 0, 65536);
        NSDictionary *job = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL] : nil;
        // Keep these templates private until the coordinator has read back
        // the authorized boot policy. A cancelled first setup must not make
        // restricted Bluetooth jobs fail repeatedly on the next cold boot.
        if (![job[@"Label"] isEqual:label] ||
            !CopyNewOrIdentical([[source stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"],
                                [[bt stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"],0600)) return NO;
    }
    NSDictionary *relay = @{@"Label":@"com.virtualmac.shared-radio-native-v1",
        @"ProgramArguments":@[[helpers stringByAppendingPathComponent:@"com.virtualmac.SharedRadioNativeDaemonV1"], @"--run"],
        @"RunAtLoad":@YES, @"KeepAlive":@YES, @"ProcessType":@"Background", @"ThrottleInterval":@5, @"Umask":@077,
        @"StandardOutPath":@"/var/log/virtualmac-shared-radio-native-v1.log",
        @"StandardErrorPath":@"/var/log/virtualmac-shared-radio-native-v1.log"};
    NSDictionary *activation = @{@"Label":@"com.virtualmac.radio-first-boot-v1",
        @"ProgramArguments":@[[helpers stringByAppendingPathComponent:@"com.virtualmac.RadioFirstBootV1"], @"--check-once"],
        @"RunAtLoad":@YES, @"StartInterval":@15, @"ProcessType":@"Background", @"Umask":@077,
        @"StandardOutPath":@"/var/log/virtualmac-radio-first-boot-v1.log",
        @"StandardErrorPath":@"/var/log/virtualmac-radio-first-boot-v1.log"};
    return WriteNewOrIdenticalJob(relay, relay[@"Label"]) && WriteNewOrIdenticalJob(activation, activation[@"Label"]);
}
static BOOL Bootstrap(NSString *label) {
    NSTask *task = [NSTask new]; task.executableURL = [NSURL fileURLWithPath:@"/bin/launchctl"];
    task.arguments = @[@"bootstrap", @"system", [[@"/Library/LaunchDaemons" stringByAppendingPathComponent:label] stringByAppendingPathExtension:@"plist"]];
    task.standardInput = NSFileHandle.fileHandleWithNullDevice; task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
    task.standardError = NSFileHandle.fileHandleWithNullDevice;
    if (![task launchAndReturnError:NULL]) return NO;
    double deadline = NSProcessInfo.processInfo.systemUptime + 10;
    while (task.running && NSProcessInfo.processInfo.systemUptime < deadline) usleep(100000);
    if (task.running) { [task terminate]; usleep(100000); if (task.running) kill(task.processIdentifier, SIGKILL); }
    [task waitUntilExit];
    // A repeated --stage sees the existing job. Verify that exact label, rather
    // than treating every nonzero bootstrap result as installation success.
    if (!task.terminationStatus) return YES;
    NSTask *check = [NSTask new]; check.executableURL = [NSURL fileURLWithPath:@"/bin/launchctl"];
    check.arguments = @[@"print", [@"system/" stringByAppendingString:label]];
    check.standardOutput = NSFileHandle.fileHandleWithNullDevice; check.standardError = NSFileHandle.fileHandleWithNullDevice;
    if (![check launchAndReturnError:NULL]) return NO;
    deadline = NSProcessInfo.processInfo.systemUptime + 5;
    while (check.running && NSProcessInfo.processInfo.systemUptime < deadline) usleep(100000);
    if (check.running) { [check terminate]; usleep(100000); if (check.running) kill(check.processIdentifier, SIGKILL); }
    [check waitUntilExit]; return check.terminationStatus == 0;
}
static BOOL EnableRelay(NSString *package, NSString **state) {
    NSString *folder=@"/Library/LaunchDaemons";
    NSString *path=[folder stringByAppendingPathComponent:@"com.virtualmac.shared-radio-native-v1.plist"];
    if (!SafeDirectory(folder,0)) return NO;
    struct stat st;
    if (!lstat(path.fileSystemRepresentation,&st)) {
        NSData *data=ReadFile(path,0,65536);
        NSDictionary *prior=data?[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL]:nil;
        if (![prior isKindOfClass:NSDictionary.class] || ![prior[@"Label"] isEqual:@"com.virtualmac.shared-radio-native-v1"]) return NO;
        // Preserve an earlier development installation. A separate migration
        // must verify its running process before replacing its executable.
        *state=@"existing-relay-preserved"; return YES;
    }
    if (errno!=ENOENT) return NO;
    NSDictionary *job=@{@"Label":@"com.virtualmac.shared-radio-native-v1",
        @"ProgramArguments":@[[package stringByAppendingPathComponent:@"shared-radio-native-daemon"],@"--run"],
        @"RunAtLoad":@YES,@"KeepAlive":@YES,@"ProcessType":@"Background",
        @"ThrottleInterval":@5,@"Umask":@077,
        @"StandardOutPath":@"/var/log/virtualmac-shared-radio-native-v1.log",
        @"StandardErrorPath":@"/var/log/virtualmac-shared-radio-native-v1.log"};
    if (!WritePlist(job,path) || chmod(path.fileSystemRepresentation,0644)) return NO;
    char *arguments[]={"/bin/launchctl","bootstrap","system",(char *)path.fileSystemRepresentation,NULL};
    pid_t child=0;
    if (posix_spawn(&child,arguments[0],NULL,NULL,arguments,environ)) return NO;
    int status=0;double deadline=NSProcessInfo.processInfo.systemUptime+15;
    while (YES) {
        pid_t result=waitpid(child,&status,WNOHANG);
        if (result==child) break;
        if (result<0) { if(errno==EINTR)continue; return NO; }
        if (NSProcessInfo.processInfo.systemUptime>=deadline) {
            kill(child,SIGKILL);waitpid(child,&status,0);return NO;
        }
        usleep(100000);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) return NO;
    *state=@"relay-launch-job-installed";return YES;
}
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 4 || (strcmp(argv[1], "--validate") && strcmp(argv[1], "--stage"))) return 64;
    BOOL stage = !strcmp(argv[1], "--stage");
    if (stage && geteuid()) return 77;
    NSString *source = @(argv[2]), *expected = @(argv[3]);
    NSDictionary *manifest = Validate(source, geteuid(), expected);
    if (!manifest) { fprintf(stderr, "VM27_RADIO_INVALID_PACKAGE\n"); return 65; }
    if (!stage) { puts("VM27_RADIO_PACKAGE_VALID"); return 0; }
    char build[64] = {0}; size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) ||
        ![manifest[@"GuestBuild"] isEqual:@(build)]) {
        fprintf(stderr, "VM27_RADIO_UNSUPPORTED_GUEST_BUILD\n"); return 78;
    }
    char kernel[1024]={0};size=sizeof(kernel);
    if (sysctlbyname("kern.version",kernel,&size,NULL,0) ||
        ![manifest[@"GuestKernelVersion"] isEqual:@(kernel)]) {
        fprintf(stderr,"VM27_RADIO_UNSUPPORTED_GUEST_KERNEL\n");return 78;
    }
#if !defined(__arm64__)
    return 78;
#endif
    // All parents are checked individually: no package can redirect a root write.
    NSString *root = @"/Library/VirtualMac/SharedRadio";
    for (NSString *path in @[@"/Library", @"/Library/VirtualMac", root,
                             [root stringByAppendingPathComponent:@"Packages"]]) {
        struct stat st;
        BOOL created = NO;
        // Guest Tools is an Aqua application under this shared parent.
        // Keep radio packages and credentials private in their own children.
        mode_t mode = [path isEqual:@"/Library"] || [path isEqual:@"/Library/VirtualMac"] ? 0755 : 0700;
        if (lstat(path.fileSystemRepresentation, &st)) {
            if (errno != ENOENT || mkdir(path.fileSystemRepresentation, mode)) return 73;
            created = YES;
        }
        if (!SafeDirectory(path, 0)) return 77;
        // The root guest agent may inherit umask 077. Correct only a parent
        // we just created; preserve existing user-managed directory modes.
        if (created && chmod(path.fileSystemRepresentation, mode)) return 73;
    }
    NSString *destination = [[root stringByAppendingPathComponent:@"Packages"] stringByAppendingPathComponent:expected];
    struct stat st;
    if (!lstat(destination.fileSystemRepresentation, &st)) {
        if (!Validate(destination, 0, expected)) return 65;
    } else {
        if (errno != ENOENT || ![NSFileManager.defaultManager moveItemAtPath:source toPath:destination error:NULL]) return 73;
        if (!Validate(destination, 0, expected)) return 65;
    }
    BOOL combined = [manifest[@"CombinedInstallation"] isKindOfClass:NSDictionary.class];
    NSString *relayState=@"relay-install-failed";
    BOOL relay = combined ? InstallCombined(destination, manifest) : EnableRelay(destination,&relayState);
    if (combined) relayState = relay ? @"combined-components-installed" : @"combined-installation-conflict";
    // A rejected newer package must not replace a working older package's
    // receipt. The old coordinator binds its installed files to that receipt.
    // Keep the staged candidate for diagnosis; the host records this failure.
    if (!relay) {
        fprintf(stderr, "VM27_RADIO_INSTALLATION_CONFLICT\n");
        return 73;
    }
    NSDictionary *receipt = @{@"Schema":@1, @"PackageManifestSHA256":expected,
        @"GuestBuild":@(build), @"State":relay && combined ? @"components-installed-awaiting-activation" : @"components-staged",
        @"CombinedInstallation":@(combined && relay),
        @"GuestBootPolicyPrepared":@NO, @"WiFiConnectionVerified":@NO,
        @"BluetoothPairingImplemented":@NO,
        @"BluetoothRelayProvisioning":relayState,
        @"NextStep":@"prepare-per-guest-boot-policy-and-activate",
        @"PackagePath":destination};
    if (!WritePlist(receipt, [root stringByAppendingPathComponent:@"Provisioning.plist"])) return 73;
    if (combined && !Bootstrap(@"com.virtualmac.radio-first-boot-v1")) return 73;
    puts("VM27_RADIO_COMPONENTS_STAGED"); return 0;
} }
