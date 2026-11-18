// One-invocation development module in the guest's entitled native hidd.
// Does not modify Apple's executable, its lifetime, or the pairing policy.
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/stat.h>
extern int VM27StartExclusiveHOGPServiceV1(void);
__attribute__((constructor)) static void startGuestHID(void){@autoreleasepool{
 char path[PROC_PIDPATHINFO_MAXSIZE]={0},build[32]={0},boot[64]={0};size_t n=sizeof(build),m=sizeof(boot);
 if(geteuid()||proc_pidpath(getpid(),path,sizeof(path))<=0||strcmp(path,"/usr/libexec/hidd")||
    sysctlbyname("kern.osversion",build,&n,NULL,0)||strcmp(build,"25G83")||
    sysctlbyname("kern.bootsessionuuid",boot,&m,NULL,0)||strcmp(boot,"5ADAD59F-FF0D-41D0-B3C1-A725D5B1A41C"))return;
 dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),dispatch_get_main_queue(),^{
  int status=VM27StartExclusiveHOGPServiceV1();
  NSDictionary *receipt=@{@"schema":@1,@"processPID":@(getpid()),@"installationResult":@(status),@"firstPairingRequested":@NO};
  NSData *data=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];
  NSString *file=@"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1/exclusive-hogp-module-v1.json";
  if([data writeToFile:file options:NSDataWritingAtomic error:NULL])chmod(file.fileSystemRepresentation,0600);
 });
}}
