// One-time native volume-owner authentication for a new macOS 26 guest.
// Passwords travel only through anonymous pipes/PTYs and are never logged or
// saved. bputil, csrutil and SystemPolicy still verify the real owner.
#import <AppKit/AppKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include "VM27RadioConsoleSessionV1.h"
#include "VM27RadioGuestProfileV1.h"
#include "VM27RadioCompletedSetupResumeV1.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <termios.h>
#include <util.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <libproc.h>

static NSString *const Root=@"/Library/VirtualMac/SharedRadio";
static const char *Self="/Library/PrivilegedHelperTools/com.virtualmac.RadioOwnerAuthorizationV1";
static int setupAssistantStatus(void){
    int pids[8192];int count=proc_listallpids(pids,sizeof(pids));
    if(count<=0||count>=(int)(sizeof(pids)/sizeof(*pids)))return EAGAIN;
    for(int i=0;i<count;i++){
        char path[PROC_PIDPATHINFO_MAXSIZE]={0};
        if(pids[i]>0&&proc_pidpath(pids[i],path,sizeof(path))>0&&
           !strcmp(path,"/System/Library/CoreServices/Setup Assistant.app/Contents/MacOS/Setup Assistant"))return 0;
    }
    return ENOENT;
}
static NSDictionary *ownerConsoleSessionV2(void){
    SCDynamicStoreRef store=SCDynamicStoreCreate(kCFAllocatorDefault,CFSTR("VirtualMac radio owner session"),NULL,NULL);
    id session=store?CFBridgingRelease(SCDynamicStoreCopyValue(store,CFSTR("State:/Users/ConsoleUser"))):nil;
    if(store)CFRelease(store);
    return [session isKindOfClass:NSDictionary.class]?session:nil;
}
static BOOL ownerDesktopProcessesV2(uid_t uid){
    int pids[8192];int count=proc_listallpids(pids,sizeof(pids));BOOL finder=NO,dock=NO;
    if(count<=0||count>=(int)(sizeof(pids)/sizeof(*pids)))return NO;
    for(int i=0;i<count;i++){
        char path[PROC_PIDPATHINFO_MAXSIZE]={0};struct proc_bsdinfo info={0};
        if(pids[i]<=0 || proc_pidinfo(pids[i],PROC_PIDTBSDINFO,0,&info,sizeof(info))!=(int)sizeof(info) ||
           info.pbi_uid!=uid || proc_pidpath(pids[i],path,sizeof(path))<=0)continue;
        finder|=!strcmp(path,"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
        dock|=!strcmp(path,"/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock");
    }
    return finder&&dock;
}
static BOOL ownerConsoleVisibleV2(uid_t uid){
    return setupAssistantStatus()==ENOENT &&
        VM27RadioConsoleSessionReadyV1(ownerConsoleSessionV2(),uid,YES) && ownerDesktopProcessesV2(uid);
}
static void erase(void *pointer,size_t size){volatile uint8_t *p=pointer;while(size--)*p++=0;}
static NSData *run(NSString *program,NSArray *arguments,NSData *input,int *exitCode,double timeout){
    NSTask *task=[NSTask new];NSPipe *out=[NSPipe pipe],*in=input?[NSPipe pipe]:nil;
    task.executableURL=[NSURL fileURLWithPath:program];task.arguments=arguments;
    task.standardInput=in?:NSFileHandle.fileHandleWithNullDevice;task.standardOutput=out;task.standardError=NSFileHandle.fileHandleWithNullDevice;
    if(![task launchAndReturnError:NULL]){*exitCode=EIO;return nil;}
    if(in){[in.fileHandleForWriting writeData:input];[in.fileHandleForWriting closeFile];}
    double deadline=NSProcessInfo.processInfo.systemUptime+timeout;
    while(task.running&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(100000);
    BOOL expired=task.running;
    if(expired){[task terminate];usleep(100000);if(task.running)kill(task.processIdentifier,SIGKILL);}
    [task waitUntilExit];NSData *data=[out.fileHandleForReading readDataToEndOfFile];
    *exitCode=expired?ETIMEDOUT:task.terminationStatus;return data.length<32768?data:nil;
}
#include "VM27RadioOwnerGUIV2.inc"
static int nativePolicy(const char *program,char *const argv[],const char *owner,NSData *password){
    int master=-1,slave=-1;if(openpty(&master,&slave,NULL,NULL,NULL))return errno;
    struct termios terminal;if(tcgetattr(slave,&terminal)){close(master);close(slave);return errno;}
    terminal.c_lflag&=~ECHO;tcsetattr(slave,TCSANOW,&terminal);
    pid_t child=fork();
    if(child==0){
        close(master);setsid();ioctl(slave,TIOCSCTTY,0);dup2(slave,0);dup2(slave,1);dup2(slave,2);if(slave>2)close(slave);
        setenv("LC_ALL","C",1);execv(program,argv);_exit(127);
    }
    close(slave);if(child<0){close(master);return errno;}
    char buffer[32768]={0};size_t used=0,consumed=0;unsigned passwords=0,users=0,consents=0;
    int status=0,result=ETIMEDOUT;double deadline=NSProcessInfo.processInfo.systemUptime+45;
    while(NSProcessInfo.processInfo.systemUptime<deadline){
        if(waitpid(child,&status,WNOHANG)==child){result=WIFEXITED(status)?WEXITSTATUS(status):EIO;child=-1;break;}
        struct pollfd p={master,POLLIN,0};if(poll(&p,1,100)<=0)continue;
        ssize_t n=read(master,buffer+used,sizeof(buffer)-used-1);if(n<=0)continue;used+=(size_t)n;
        if(used>=sizeof(buffer)-1){result=EOVERFLOW;break;}
        NSString *text=[[NSString alloc]initWithBytes:buffer+consumed length:used-consumed encoding:NSUTF8StringEncoding];
        if(!text)continue;
        const char *response=NULL;size_t length=0;BOOL secret=NO;
        NSRegularExpression *regex=[NSRegularExpression regularExpressionWithPattern:@"(?:Password(?: for [^:\\r\\n]+)?|Enter (?:the )?password(?: for [^:\\r\\n]+)?)\\s*:" options:NSRegularExpressionCaseInsensitive error:NULL];
        NSTextCheckingResult *match=[regex firstMatchInString:text options:0 range:NSMakeRange(0,text.length)];
        if(match){if(++passwords>3){result=EACCES;break;}secret=YES;}
        else{
            regex=[NSRegularExpression regularExpressionWithPattern:@"(?:Authorized user|Username|Enter [^:\\r\\n]*user[^:\\r\\n]*)\\s*:" options:NSRegularExpressionCaseInsensitive error:NULL];
            match=[regex firstMatchInString:text options:0 range:NSMakeRange(0,text.length)];
            if(match){if(++users>2){result=EACCES;break;}response=owner;length=strlen(owner);}
            else{
                NSRange consent=[text rangeOfString:@"[y/n]:" options:NSCaseInsensitiveSearch];
                if(consent.location!=NSNotFound){if(++consents>2){result=EACCES;break;}response="y";length=1;}
            }
        }
        if(secret||response){
            const void *bytes=secret?password.bytes:response;size_t count=secret?password.length:length;
            if(write(master,bytes,count)!=(ssize_t)count||write(master,"\n",1)!=1){result=EIO;break;}
            consumed=used;
        }
    }
    if(child>0){kill(child,SIGTERM);usleep(100000);if(waitpid(child,&status,WNOHANG)==0){kill(child,SIGKILL);waitpid(child,&status,0);}}
    erase(buffer,sizeof(buffer));close(master);return result;
}
#include "VM27RadioCompletedSetupResumeV1.inc"

int main(int argc,char **argv){@autoreleasepool{
    BOOL prompt=argc==4&&!strcmp(argv[1],"--prompt-gui")&&
        (!strcmp(argv[2],"OwnerPolicy")||!strcmp(argv[2],"DriverApproval"));
    if(argc!=2 && !prompt)return EINVAL;
    NSDictionary *version=[NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if(![version[@"ProductBuildVersion"]isEqual:@VM27_RADIO_GUEST_BUILD])return ENOTSUP;
    if(prompt)return ownerPromptGUIV2(argv[3],!strcmp(argv[2],"OwnerPolicy"));
    if(!strcmp(argv[1],"--inspect-owner-setup-resume"))return ownerSetupResumeV1(NO);
    if(!strcmp(argv[1],"--apply-owner-setup-resume"))return ownerSetupResumeV1(YES);
    BOOL policy=!strcmp(argv[1],"--policy"),approve=!strcmp(argv[1],"--approve-driver");
    BOOL ready=!strcmp(argv[1],"--ready-for-restart");
    BOOL visible=!strcmp(argv[1],"--ready-for-owner-ui");
    BOOL sessionVisible=!strcmp(argv[1],"--owner-session-visible");
    BOOL setup=!strcmp(argv[1],"--setup-assistant-active");
    BOOL settle=!strcmp(argv[1],"--settle-completed-setup-resume");
    if(geteuid()||(!policy&&!approve&&!ready&&!visible&&!sessionVisible&&!setup&&!settle))return EPERM;
    NSDictionary *installed=[NSDictionary dictionaryWithContentsOfFile:[Root stringByAppendingPathComponent:@"Provisioning.plist"]];
    if(![installed[@"CombinedInstallation"]isEqual:@YES])return EPERM;
    int setupState=setupAssistantStatus();if(setup)return setupState;
    struct stat console;if(stat("/dev/console",&console)||console.st_uid<500)return EAGAIN;
    if(setupState!=ENOENT)return EAGAIN;
    NSDictionary *session=ownerConsoleSessionV2();
    BOOL sessionReady=VM27RadioConsoleSessionReadyV1(session,console.st_uid,YES);
    if(sessionVisible)return sessionReady?0:EAGAIN;
    if(ready){
        NSDictionary *progress=[NSDictionary dictionaryWithContentsOfFile:[Root stringByAppendingPathComponent:@"ActivationProgress.plist"]];
        char boot[64]={0};size_t size=sizeof(boot);
        BOOL samePackage=[progress[@"PackageManifestSHA256"] isEqual:installed[@"PackageManifestSHA256"]];
        BOOL sameBoot=!sysctlbyname("kern.bootsessionuuid",boot,&size,NULL,0);
        BOOL setupSeen=samePackage&&sameBoot&&[progress[@"SetupAssistantObservedBootUUID"] isEqual:@(boot)];
        BOOL ownerSeen=sameBoot&&[progress[@"OwnerVisibleObservedBootUUID"] isEqual:@(boot)];
        BOOL noCompletedStage=!progress[@"ConsoleHandoffRestartBootUUID"]&&!progress[@"PolicyRestartBootUUID"]&&!progress[@"DriverRestartBootUUID"];
        sessionReady=VM27RadioSetupHandoffPendingV1(session,console.st_uid) ||
            (noCompletedStage&&VM27RadioInitialRootHandoffPendingV2(session,console.st_uid,setupSeen,ownerSeen));
    }else if(settle)sessionReady=VM27RadioConsoleSessionReadyV1(session,console.st_uid,NO)&&ownerDesktopProcessesV2(console.st_uid);
    else sessionReady=sessionReady&&ownerDesktopProcessesV2(console.st_uid);
    if(!sessionReady)return EAGAIN;
    if(settle)return settleOwnerSetupResumeV1(console.st_uid);
    if(ready||visible)return 0;
    struct passwd *owner=getpwuid(console.st_uid);if(!owner||!strcmp(owner->pw_name,"_mbsetupuser")||strlen(owner->pw_name)>64)return EAGAIN;
    char ownerName[65];strlcpy(ownerName,owner->pw_name,sizeof(ownerName));
    int authorizationFailure=EAGAIN;
    NSMutableData *password=ownerPasswordGUIV2(owner->pw_uid,policy?@"OwnerPolicy":@"DriverApproval",&authorizationFailure);
    if(!password)return authorizationFailure;
    int result=0;
    if(policy){
        NSString *backup=[Root stringByAppendingPathComponent:@"SecurityBeforeRadio.plist"];
        if(![NSFileManager.defaultManager fileExistsAtPath:backup]){
            int a=0,b=0;NSData *oldPolicy=run(@"/usr/bin/bputil",@[@"-d"],nil,&a,10),*oldArgs=run(@"/usr/sbin/nvram",@[@"boot-args"],nil,&b,10);
            NSDictionary *record=@{@"Schema":@1,@"NativePolicyBefore":oldPolicy?:NSData.data,@"BootArgumentsBefore":oldArgs?:NSData.data};
            NSData *data=[NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
            if(a||![data writeToFile:backup options:NSDataWritingWithoutOverwriting error:NULL]||chmod(backup.fileSystemRepresentation,0600))result=EIO;
        }
        if(!result){char *arguments[]={"/usr/bin/bputil","--enable-kexts",NULL};result=nativePolicy(arguments[0],arguments,ownerName,password);}
        if(!result){char *arguments[]={"/usr/bin/csrutil","enable","--without","kext","--without","fs","--without","debug","--without","nvram",NULL};result=nativePolicy(arguments[0],arguments,ownerName,password);}
    }else{
        setenv("SUDO_USER",ownerName,1);NSMutableData *input=[password mutableCopy];[input appendBytes:"\n" length:1];
        run(@"/Library/PrivilegedHelperTools/com.virtualmac.RadioApproveDriverV1",@[@"--approve"],input,&result,30);erase(input.mutableBytes,input.length);
    }
    erase(password.mutableBytes,password.length);
    fprintf(stdout,"{\"nativeOwnerOperation\":\"%s\",\"exit\":%d,\"passwordSaved\":false}\n",policy?"policy":"approve-driver",result);
    return result;
}}
