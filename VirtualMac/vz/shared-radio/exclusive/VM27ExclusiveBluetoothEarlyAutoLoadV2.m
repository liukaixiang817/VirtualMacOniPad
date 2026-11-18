// Development-guest early loader. Keeps Apple's executable and sealed service
// definition intact. Only this service receives the transport library; no
// debugger attachment or global DYLD environment is needed.
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#ifndef VM27_EARLY_MODULE_SHA
#error Supply the reviewed early module hash.
#endif
#ifndef VM27_EARLY_NATIVE_BUILD
#define VM27_EARLY_NATIVE_BUILD "25G83"
#define VM27_EARLY_NATIVE_SHA "8afb2a8c2d6aa90b1e1e9e22a7c0ec3201ce46b02ccb37775bb0c9698b93575a"
#define VM27_EARLY_MODULE_FILENAME "VM27ExclusiveBluetoothGuestV15.dylib"
#define VM27_EARLY_PRIVATE_FILENAME "native-bluetoothd-exclusive-v15.plist"
#define VM27_EARLY_NATIVE_LABEL "com.virtualmac.exclusive-bluetooth-native-v15"
#define VM27_EARLY_CONSTRUCTOR_FILENAME "exclusive-before-main-v15.json"
#endif
static NSString *const Root=@"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";
static NSString *const Module=@"/Library/Application Support/BTServer/VirtualMacSharedRadioDevelopment-v1/" VM27_EARLY_MODULE_FILENAME;
static NSString *const Original=@"/System/Library/LaunchDaemons/com.apple.bluetoothd.plist";
static NSString *const PrivateName=@VM27_EARLY_PRIVATE_FILENAME;
static NSString *const NativeLabel=@"system/" VM27_EARLY_NATIVE_LABEL;
static NSData *secureRead(NSString *path,NSUInteger limit) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(fd<0)return nil;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0022)||st.st_size<0||(uint64_t)st.st_size>limit){close(fd);return nil;}
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];NSUInteger at=0;
    while(at<data.length){ssize_t n=read(fd,(uint8_t *)data.mutableBytes+at,data.length-at);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return nil;}at+=(NSUInteger)n;}
    close(fd);return data;
}
static BOOL hashMatches(NSString *path,NSString *expected,NSUInteger maximum) {
    NSData *data=secureRead(path,maximum);if(!data)return NO;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *hex=[NSMutableString string];for(unsigned i=0;i<sizeof(digest);++i)[hex appendFormat:@"%02x",digest[i]];
    return [hex isEqual:expected];
}
static BOOL writeOwned(NSData *data,NSString *path) {
    // Root is root-only. Atomic replacement cannot follow a destination link.
    return data&&[data writeToFile:path options:NSDataWritingAtomic error:NULL]&&chmod(path.fileSystemRepresentation,0600)==0;
}
static int control(NSArray<NSString *> *arguments,NSString **output) {
    NSString *path=[Root stringByAppendingPathComponent:@"exclusive-early-control-v2.log"];
    int fd=open(path.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);struct stat st;
    if(fd<0)return errno;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||ftruncate(fd,0)){close(fd);return EPERM;}
    NSFileHandle *file=[[NSFileHandle alloc]initWithFileDescriptor:fd closeOnDealloc:YES];
    NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:@"/bin/launchctl"];task.arguments=arguments;
    task.standardInput=NSFileHandle.fileHandleWithNullDevice;task.standardOutput=file;task.standardError=file;
    NSError *error=nil;if(![task launchAndReturnError:&error]){[file closeFile];return EIO;}
    double deadline=NSProcessInfo.processInfo.systemUptime+5;
    while(task.running&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(10000);
    BOOL timeout=task.running;
    if(timeout){[task terminate];usleep(100000);if(task.running)kill(task.processIdentifier,SIGKILL);}
    [task waitUntilExit];[file synchronizeFile];[file closeFile];
    if(output)*output=[[NSString alloc]initWithData:secureRead(path,131072) encoding:NSUTF8StringEncoding];
    return timeout?ETIMEDOUT:task.terminationStatus;
}
static NSString *jobPath(NSString *state) {
    for(NSString *line in [state componentsSeparatedByString:@"\n"]){NSString *trim=[line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];if([trim hasPrefix:@"path = "])return [trim substringFromIndex:7];}
    return nil;
}
static BOOL originalDisabled(BOOL *disabled) {
    NSString *state=nil;if(control(@[@"print-disabled",@"system"],&state)||!state)return NO;
    *disabled=NO;
    for(NSString *line in [state componentsSeparatedByString:@"\n"])
        if([line containsString:@"\"com.apple.bluetoothd\" => "]){
            if([line containsString:@"=> disabled"]){*disabled=YES;return YES;}
            return [line containsString:@"=> enabled"];
        }
    return YES; // No override means Apple's original service is enabled.
}
static BOOL restoreNative(void) {
    NSData *data=secureRead([Root stringByAppendingPathComponent:@"native-service-before-early-v2.json"],4096);
    id previous=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
    if(![previous isKindOfClass:NSDictionary.class]||![previous[@"originalDisabled"]isKindOfClass:NSNumber.class])return NO;
    NSString *state=nil;int status=control(@[@"print",NativeLabel],&state);
    if(status==0&&![jobPath(state)isEqual:[Root stringByAppendingPathComponent:PrivateName]])return NO;
    if(status==0&&control(@[@"bootout",NativeLabel],NULL))return NO;
    if([previous[@"originalDisabled"]boolValue])return control(@[@"disable",@"system/com.apple.bluetoothd"],NULL)==0;
    if(control(@[@"enable",@"system/com.apple.bluetoothd"],NULL))return NO;
    state=nil;status=control(@[@"print",@"system/com.apple.bluetoothd"],&state);
    if(status==0)return [jobPath(state)isEqual:Original];
    return control(@[@"bootstrap",@"system",Original],NULL)==0;
}
int main(int argc,char **argv){@autoreleasepool{
    if(geteuid()||argc!=2)return EPERM;
    BOOL restore=!strcmp(argv[1],"--restore-native"),check=!strcmp(argv[1],"--check-once"),validate=!strcmp(argv[1],"--validate");
    if(!restore&&!check&&!validate)return EINVAL;
    char build[32]={0},boot[64]={0};size_t n=sizeof(build),m=sizeof(boot);struct stat st;
    if(sysctlbyname("kern.osversion",build,&n,NULL,0)||sysctlbyname("kern.bootsessionuuid",boot,&m,NULL,0)||
       lstat(Root.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0077))return EPERM;
    NSString *marker=[Root stringByAppendingPathComponent:@"exclusive-autoload-enabled-v1"];
    NSData *enabled=[@"VM27-EXCLUSIVE-BLUETOOTH-V1\n" dataUsingEncoding:NSASCIIStringEncoding];
    if(![secureRead(marker,64)isEqual:enabled])return EPERM;
    int lock=open([[Root stringByAppendingPathComponent:@"exclusive-early-autoload-v2.lock"]fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock<0)return errno;
    if(fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB)){close(lock);return EBUSY;}
    if(restore){
        BOOL ok=restoreNative();if(ok)ok=rename(marker.fileSystemRepresentation,[[Root stringByAppendingPathComponent:@"exclusive-autoload-disabled-v2"]fileSystemRepresentation])==0;
        close(lock);return ok?0:EIO;
    }
    // Recovery restores only launchd configuration and remains usable after an
    // OS update. Installing the exact transport still requires its audited OS.
    if(strcmp(build,VM27_EARLY_NATIVE_BUILD)){close(lock);return EPROTONOSUPPORT;}
    if(NSProcessInfo.processInfo.systemUptime<20){close(lock);return 0;}
    if(!hashMatches(Module,@VM27_EARLY_MODULE_SHA,4*1024*1024)||
       !hashMatches(@"/usr/sbin/bluetoothd",@VM27_EARLY_NATIVE_SHA,32*1024*1024)){close(lock);return EPERM;}
    NSData *source=secureRead(Original,65536);
    id definition=source?[NSPropertyListSerialization propertyListWithData:source options:NSPropertyListMutableContainers format:NULL error:NULL]:nil;
    if(![definition isKindOfClass:NSMutableDictionary.class]||![definition[@"Label"]isEqual:@"com.apple.bluetoothd"]||
       ![definition[@"ProgramArguments"]isEqual:@[@"/usr/sbin/bluetoothd"]]){close(lock);return EPROTONOSUPPORT;}
    if(validate){puts("{\"schema\":2,\"nativeImageAndModuleHashesVerified\":true,\"nativeServiceDefinitionVerified\":true,\"radioStateChanged\":false}");close(lock);return 0;}
    // A late replacement at each boot would briefly initialize the simulator
    // identity and can make native keychain migration discard physical bonds.
    // Keep that original job disabled, and run its unchanged executable under
    // our own service label after removing the disabled job's reserved ports.
    BOOL disabled=NO;if(!originalDisabled(&disabled)){close(lock);return EIO;}
    NSString *backup=[Root stringByAppendingPathComponent:@"native-service-before-early-v2.json"];
    NSData *saved=secureRead(backup,4096);
    if(!saved){
        if(!lstat(backup.fileSystemRepresentation,&st)){close(lock);return EPERM;}
        if(!writeOwned([NSJSONSerialization dataWithJSONObject:@{@"schema":@1,@"originalDisabled":@(disabled)} options:0 error:NULL],backup)){close(lock);return EIO;}
    }else{
        id prior=[NSJSONSerialization JSONObjectWithData:saved options:0 error:NULL];
        if(![prior isKindOfClass:NSDictionary.class]||![prior[@"originalDisabled"]isKindOfClass:NSNumber.class]){close(lock);return EPERM;}
    }
    definition[@"Label"]=@VM27_EARLY_NATIVE_LABEL;
    NSMutableDictionary *environment=[definition[@"EnvironmentVariables"]mutableCopy]?:[NSMutableDictionary dictionary];
    environment[@"DYLD_INSERT_LIBRARIES"]=Module;definition[@"EnvironmentVariables"]=environment;
    NSString *private=[Root stringByAppendingPathComponent:PrivateName];
    NSData *existing=secureRead(private,65536);
    id old=existing?[NSPropertyListSerialization propertyListWithData:existing options:0 format:NULL error:NULL]:nil;
    if(![old isEqual:definition]&&!writeOwned([NSPropertyListSerialization dataWithPropertyList:definition format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL],private)){close(lock);return EIO;}
    NSString *state=nil;int status=control(@[@"print",NativeLabel],&state);
    BOOL already=status==0&&[jobPath(state)isEqual:private];
    if(status==0&&!already){close(lock);return EPERM;}
    if(!disabled&&control(@[@"disable",@"system/com.apple.bluetoothd"],NULL)){close(lock);return EIO;}
    NSString *oldState=nil;int oldStatus=control(@[@"print",@"system/com.apple.bluetoothd"],&oldState);
    if(oldStatus==0){
        NSString *oldPath=jobPath(oldState);
        BOOL ours=[oldPath isEqual:Original]||[oldPath isEqual:[Root stringByAppendingPathComponent:@"native-bluetoothd-early-v15.plist"]];
        if(!ours){close(lock);return EPERM;}
        if(control(@[@"bootout",@"system/com.apple.bluetoothd"],NULL)){close(lock);return EIO;}
    }
    if(!already){
        if(control(@[@"bootstrap",@"system",private],NULL)){restoreNative();close(lock);return EIO;}
    }
    NSData *constructor=secureRead([Root stringByAppendingPathComponent:@VM27_EARLY_CONSTRUCTOR_FILENAME],4096);
    id result=constructor?[NSJSONSerialization JSONObjectWithData:constructor options:0 error:NULL]:nil;
    pid_t pid=[result isKindOfClass:NSDictionary.class]?[result[@"bluetoothdPID"]intValue]:0;
    char executable[PROC_PIDPATHINFO_MAXSIZE]={0};
    BOOL same=pid>1&&proc_pidpath(pid,executable,sizeof(executable))>0&&!strcmp(executable,"/usr/sbin/bluetoothd");
    NSDictionary *report=@{@"schema":@2,@"bootUUID":@(boot),@"nativeServiceRegistered":@YES,@"alreadyRegistered":@(already),
        @"constructorProcessStillRunning":@(same),@"constructorReportedSuccess":@(same&&[result[@"installerResult"]intValue]==0),
        @"moduleSHA256":@VM27_EARLY_MODULE_SHA,@"systemVolumeModified":@NO,@"globalLoaderEnvironmentModified":@NO};
    BOOL recorded=writeOwned([NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL],
        [Root stringByAppendingPathComponent:@"exclusive-early-autoload-v2.json"]);
    close(lock);return recorded?0:EIO;
}}
