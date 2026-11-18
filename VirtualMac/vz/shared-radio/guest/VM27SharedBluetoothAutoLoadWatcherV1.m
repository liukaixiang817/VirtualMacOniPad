// Exact-development-guest watchdog. Attaches only when a new bluetoothd process
// needs the reviewed module; successful checks return without starting LLDB.
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
#ifndef VM27_AUTO_MODULE_SHA
#error Build with the reviewed module, runtime, and script hashes.
#endif
static NSString *const Root=@"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";
static NSString *const Module=@"/Library/Application Support/BTServer/VirtualMacSharedRadioDevelopment-v1/VM27SharedBluetoothClassicSupplementV2.dylib";
static volatile sig_atomic_t Stopping;
static void stopWatcher(int value){(void)value;Stopping=1;}
static NSData *secureRead(NSString *path,size_t limit) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat info;
    if(fd<0)return nil;
    if(fstat(fd,&info)||!S_ISREG(info.st_mode)||info.st_uid||info.st_nlink!=1||(info.st_mode&0022)||info.st_size<0||
        (uint64_t)info.st_size>limit){close(fd);return nil;}
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)info.st_size];size_t count=0;
    while(count<data.length) {
        ssize_t size=read(fd,(uint8_t *)data.mutableBytes+count,data.length-count);
        if(size<0&&errno==EINTR)continue;if(size<=0){close(fd);return nil;}count+=(size_t)size;
    }
    close(fd);return data;
}
static BOOL hashMatches(NSString *path,NSString *expected) {
    NSData *data=secureRead(path,4*1024*1024);if(!data)return NO;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *text=[NSMutableString stringWithCapacity:64];
    for(unsigned i=0;i<sizeof(digest);++i)[text appendFormat:@"%02x",digest[i]];
    return [text isEqual:expected];
}
static BOOL writeReceipt(NSDictionary *report,NSString *path) {
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL];
    if(!data||data.length>4096)return NO;
    // The parent is root-only and has already been validated. Atomic rename
    // keeps a previous receipt intact until the replacement is complete.
    BOOL result=[data writeToFile:path options:NSDataWritingAtomic error:NULL];
    if(result)result=chmod(path.fileSystemRepresentation,0600)==0;return result;
}
int main(int argc,char **argv) { @autoreleasepool {
    if(argc!=2||strcmp(argv[1],"--check-once")||geteuid())return EPERM;
    signal(SIGTERM,stopWatcher);signal(SIGINT,stopWatcher);
    char boot[64]={0},build[32]={0};size_t n=sizeof(boot),m=sizeof(build);struct stat folder;
    if(sysctlbyname("kern.osversion",build,&m,NULL,0)||strcmp(build,"25G83")||
       sysctlbyname("kern.bootsessionuuid",boot,&n,NULL,0)||strlen(boot)!=36||
       lstat(Root.fileSystemRepresentation,&folder)||!S_ISDIR(folder.st_mode)||folder.st_uid||(folder.st_mode&0077))return EPERM;
    if(NSProcessInfo.processInfo.systemUptime<20)return 0;
    NSString *marker=[Root stringByAppendingPathComponent:@"development-autoload-enabled-v1"];
    if(![secureRead(marker,64)isEqual:[@"VM27-CLASSIC-DEVELOPMENT-V1\n" dataUsingEncoding:NSASCIIStringEncoding]])return EPERM;
    int lock=open([[Root stringByAppendingPathComponent:@"autoload-v1.lock"]fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat info;
    if(lock<0)return errno;
    if(fstat(lock,&info)||!S_ISREG(info.st_mode)||info.st_uid||info.st_nlink!=1||(info.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB)) {close(lock);return EBUSY;}
    pid_t pids[4096],target=0;unsigned matches=0;int bytes=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    if(bytes<=0||bytes==(int)sizeof(pids)){close(lock);return EOVERFLOW;}
    for(unsigned i=0;i<(unsigned)bytes/sizeof(pid_t);++i) {
        char path[PROC_PIDPATHINFO_MAXSIZE]={0};
        if(proc_pidpath(pids[i],path,sizeof(path))>0&&!strcmp(path,"/usr/sbin/bluetoothd")){target=pids[i];++matches;}
    }
    if(matches!=1){close(lock);return 0;}
    NSString *receiptPath=[Root stringByAppendingPathComponent:@"native-classic-autoload-v1.json"];
    NSData *oldData=secureRead(receiptPath,4096);NSDictionary *old=oldData?[NSJSONSerialization JSONObjectWithData:oldData options:0 error:NULL]:nil;
    if(!oldData&&lstat(receiptPath.fileSystemRepresentation,&info)==0){close(lock);return EPERM;}
    BOOL same=[old isKindOfClass:NSDictionary.class]&&[old[@"bootUUID"]isEqual:@(boot)]&&
        [old[@"bluetoothdPID"]intValue]==target&&[old[@"moduleSHA256"]isEqual:@VM27_AUTO_MODULE_SHA];
    if(same&&[old[@"installed"]boolValue]&&[old[@"debuggerDetached"]boolValue]){close(lock);return 0;}
    double now=NSDate.date.timeIntervalSince1970;unsigned attempt=same?[old[@"attemptIndex"]unsignedIntValue]+1:1;
    if(same&&(attempt>3||now-[old[@"timestampUnix"]doubleValue]<120)){close(lock);return 0;}
    NSString *binary=[Root stringByAppendingPathComponent:@"Runtime/Developer/usr/bin/lldb"];
    NSString *script=[Root stringByAppendingPathComponent:@"autoload_native_bluetooth_v1.py"];
    if(!hashMatches(Module,@VM27_AUTO_MODULE_SHA)||!hashMatches(binary,@VM27_AUTO_LLDB_SHA)||!hashMatches(script,@VM27_AUTO_SCRIPT_SHA)) {close(lock);return EPERM;}
    NSMutableDictionary *pending=[@{@"schema":@1,@"bootUUID":@(boot),@"bluetoothdPID":@(target),@"moduleSHA256":@VM27_AUTO_MODULE_SHA,
        @"attemptIndex":@(attempt),@"timestampUnix":@(now),@"installed":@NO,@"debuggerDetached":@NO}mutableCopy];
    if(!writeReceipt(pending,receiptPath)){close(lock);return EIO;}
    NSString *log=[Root stringByAppendingPathComponent:@"autoload-lldb-v1.log"];
    int logFD=open(log.fileSystemRepresentation,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if(logFD<0||fstat(logFD,&info)||!S_ISREG(info.st_mode)||info.st_uid||info.st_nlink!=1||(info.st_mode&0777)!=0600) {if(logFD>=0)close(logFD);close(lock);return EPERM;}
    if(info.st_size>262144&&ftruncate(logFD,0)){close(logFD);close(lock);return EIO;}
    NSFileHandle *output=[[NSFileHandle alloc]initWithFileDescriptor:logFD closeOnDealloc:YES];
    NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:binary];
    task.arguments=@[@"--batch",@"-o",[@"command script import " stringByAppendingString:script]];
    NSMutableDictionary *environment=[NSProcessInfo.processInfo.environment mutableCopy];
    environment[@"PYTHONHOME"]=[Root stringByAppendingPathComponent:@"Runtime/Developer/Library/Frameworks/Python3.framework/Versions/3.9"];
    environment[@"PYTHONPATH"]=[Root stringByAppendingPathComponent:@"Runtime/SharedFrameworks/LLDB.framework/Resources/Python"];
    environment[@"PYTHONDONTWRITEBYTECODE"]=@"1";
    environment[@"LLDB_DEBUGSERVER_PATH"]=[Root stringByAppendingPathComponent:@"Runtime/SharedFrameworks/LLDB.framework/Resources/debugserver"];
    environment[@"VM27_CLASSIC_BOOT_UUID"]=@(boot);environment[@"VM27_CLASSIC_PID"]=[NSString stringWithFormat:@"%d",target];
    environment[@"VM27_CLASSIC_ATTEMPT"]=[NSString stringWithFormat:@"%u",attempt];
    task.environment=environment;task.standardInput=NSFileHandle.fileHandleWithNullDevice;task.standardOutput=output;task.standardError=output;
    NSError *error=nil;BOOL launched=[task launchAndReturnError:&error];double deadline=NSProcessInfo.processInfo.systemUptime+55;
    while(launched&&task.running&&!Stopping&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(100000);
    if(launched&&task.running) {
        [task terminate];deadline=NSProcessInfo.processInfo.systemUptime+3;
        while(task.running&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(100000);
        if(task.running)kill(task.processIdentifier,SIGKILL);
    }
    [output synchronizeFile];
    NSDictionary *result=[NSJSONSerialization JSONObjectWithData:secureRead(receiptPath,4096)?:NSData.data options:0 error:NULL];
    BOOL ok=[result[@"bootUUID"]isEqual:@(boot)]&&[result[@"bluetoothdPID"]intValue]==target&&
        [result[@"installed"]boolValue]&&[result[@"debuggerDetached"]boolValue];
    if(!ok&&(!launched||![result objectForKey:@"error"])) {
        pending[@"error"]=launched?@"bounded local loader did not confirm completion":@"private runtime launch failed";
        pending[@"timestampUnix"]=@(NSDate.date.timeIntervalSince1970);writeReceipt(pending,receiptPath);
    }
    fprintf(stderr,"VM27 classic automatic load pid=%d success=%d attempt=%u\n",target,ok,attempt);
    close(lock);return ok?0:EIO;
} }
