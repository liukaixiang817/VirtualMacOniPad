// Included by the owner helper after its bounded run()/erase() utilities.
// launchd creates the prompt in the actual Aqua login domain. The root policy
// process and that exact executable exchange a single bounded response over a
// peer-credential-checked Unix socket. Only the random socket name is on disk.
#include "VM27RadioOwnerChannelV2.h"
#include <sys/un.h>

static BOOL ownerPeerV2(int fd,uid_t expected,pid_t *peerPID) {
    uid_t uid;gid_t gid;pid_t pid=0;socklen_t size=sizeof(pid);
    char executable[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(getpeereid(fd,&uid,&gid)||uid!=expected ||
       getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&size)||size!=sizeof(pid)||pid<=0 ||
       proc_pidpath(pid,executable,sizeof(executable))<=0 || strcmp(executable,Self))return NO;
    if(peerPID)*peerPID=pid;
    return YES;
}
static BOOL ownerDirectoryV2(const char *path) {
    if(!mkdir(path,0755)){if(chmod(path,0755))return NO;}
    else if(errno!=EEXIST)return NO;
    struct stat s;
    return !lstat(path,&s)&&S_ISDIR(s.st_mode)&&!s.st_uid&&!(s.st_mode&0022)&&
        (s.st_mode&0111)==0111;
}
static int ownerPromptGUIV2(const char *path,BOOL policy) {
    static const char prefix[]="/private/var/run/virtualmac-radio-owner-v2/";
    if(getuid()<500 || geteuid()!=getuid() ||
       strncmp(path,prefix,sizeof(prefix)-1) ||
       strlen(path)>=sizeof(((struct sockaddr_un *)0)->sun_path))return EPERM;
    struct stat s;if(lstat(path,&s)||!S_ISSOCK(s.st_mode)||s.st_uid!=getuid() ||
                     (s.st_mode&0777)!=0600)return EPERM;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return errno;
    fcntl(fd,F_SETFD,FD_CLOEXEC);int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct sockaddr_un address={.sun_len=sizeof(struct sockaddr_un),.sun_family=AF_UNIX};strlcpy(address.sun_path,path,sizeof(address.sun_path));
    if(connect(fd,(struct sockaddr *)&address,sizeof(address)) || !ownerPeerV2(fd,0,NULL) ||
       !ownerConsoleVisibleV2(getuid())){close(fd);return EAGAIN;}
    [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    NSAlert *alert=[NSAlert new];
    alert.messageText=policy?@"Allow Virtual Mac Radio Security Changes":@"Complete Virtual Mac Wi-Fi and Bluetooth Setup";
    alert.informativeText=policy?
        @"This enables third-party kernel extensions and persistently relaxes kernel-extension, filesystem, debugging and NVRAM protections in this virtual Mac. Authenticated Root is not changed. Your iPad’s security settings are not changed. Enter this virtual Mac’s administrator password to continue. It will restart; your password will not be saved.":
        @"Enter this virtual Mac’s administrator password to approve its bundled radio driver. The virtual Mac will restart to finish setup. Your password will not be saved.";
    NSSecureTextField *field=[[NSSecureTextField alloc]initWithFrame:NSMakeRect(0,0,360,24)];
    alert.accessoryView=field;[alert addButtonWithTitle:@"Continue"];[alert addButtonWithTitle:@"Cancel"];
    [alert.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
    [alert.window makeFirstResponder:field];
    if(!alert.window.visible || VM27OwnerSendV2(fd,VM27OwnerUIReadyV2,NULL,0)){
        [alert.window orderOut:nil];close(fd);return EAGAIN;
    }
    __block BOOL interrupted=NO;
    double deadline=VM27OwnerMonotonicV2()+300;
    NSTimer *timer=[NSTimer timerWithTimeInterval:1 repeats:YES block:^(NSTimer *unused){
        (void)unused;
        struct pollfd peer={fd,POLLIN,0};int pending=poll(&peer,1,0);
        if(pending!=0 || VM27OwnerMonotonicV2()>=deadline || !ownerConsoleVisibleV2(getuid())){
            interrupted=YES;[NSApp abortModal];[alert.window orderOut:nil];
        }
    }];
    [NSRunLoop.currentRunLoop addTimer:timer forMode:NSModalPanelRunLoopMode];
    NSModalResponse response=[alert runModal];[timer invalidate];
    int rc=ECANCELED;
    if(!interrupted&&response==NSAlertFirstButtonReturn){
        NSMutableData *secret=[[field.stringValue dataUsingEncoding:NSUTF8StringEncoding]mutableCopy];
        field.stringValue=@"";
        if(secret.length<=255&&VM27OwnerSecretValidV2(secret.bytes,secret.length))
            rc=VM27OwnerSendV2(fd,VM27OwnerPasswordV2,secret.bytes,(uint16_t)secret.length);
        else rc=EINVAL;
        erase(secret.mutableBytes,secret.length);
    }else VM27OwnerSendV2(fd,VM27OwnerCancelledV2,NULL,0);
    field.stringValue=@"";[alert.window orderOut:nil];close(fd);return rc;
}
static void ownerUIReceiptV2(NSMutableDictionary *receipt,NSString *stage) {
    NSString *path=[Root stringByAppendingPathComponent:[stage stringByAppendingString:@"UIStatus.plist"]];
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:receipt format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
    if(data&&[data writeToFile:path options:NSDataWritingAtomic error:NULL])chmod(path.fileSystemRepresentation,0600);
}
static NSMutableData *ownerPasswordGUIV2(uid_t uid,NSString *stage,int *failure) {
    *failure=EAGAIN;
    if(!ownerDirectoryV2("/private/var/run/virtualmac-radio-owner-v2") ||
       !ownerDirectoryV2("/Library/VirtualMac/OwnerUI-v2"))return nil;
    NSString *nonce=NSUUID.UUID.UUIDString.lowercaseString;
    NSString *label=[@"com.virtualmac.radio-owner-ui-v2." stringByAppendingString:nonce];
    NSString *path=[@"/private/var/run/virtualmac-radio-owner-v2/" stringByAppendingString:nonce];
    NSString *jobPath=[[@"/Library/VirtualMac/OwnerUI-v2/" stringByAppendingString:label]stringByAppendingPathExtension:@"plist"];
    NSString *domain=[NSString stringWithFormat:@"gui/%u",uid];
    NSString *service=[domain stringByAppendingFormat:@"/%@",label];
    char boot[64]={0};size_t bootSize=sizeof(boot);
    if(sysctlbyname("kern.bootsessionuuid",boot,&bootSize,NULL,0))return nil;
    NSMutableDictionary *receipt=[@{@"Schema":@2,@"BootUUID":@(boot),@"Stage":stage,
        @"Transport":@"aqua-agent-v2",@"LaunchDomain":domain,@"Label":label,
        @"OwnerUID":@(uid),@"CredentialSaved":@NO,@"UIReadinessReceived":@NO}mutableCopy];
    struct sockaddr_un address={.sun_len=sizeof(struct sockaddr_un),.sun_family=AF_UNIX};
    if(path.length>=sizeof(address.sun_path))return nil;
    strlcpy(address.sun_path,path.fileSystemRepresentation,sizeof(address.sun_path));
    int listener=socket(AF_UNIX,SOCK_STREAM,0),client=-1,rc=0;
    if(listener<0)return nil;
    fcntl(listener,F_SETFD,FD_CLOEXEC);int one=1;setsockopt(listener,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    NSMutableData *secret=nil;BOOL submitted=NO;
    do {
        if(bind(listener,(struct sockaddr *)&address,sizeof(address)) ||
           chown(path.fileSystemRepresentation,uid,(gid_t)-1) || chmod(path.fileSystemRepresentation,0600) || listen(listener,1))break;
        NSDictionary *job=@{@"Label":label,@"ProgramArguments":@[@(Self),@"--prompt-gui",stage,path],
            @"LimitLoadToSessionType":@"Aqua",@"ProcessType":@"Interactive",@"RunAtLoad":@YES,
            @"KeepAlive":@NO,@"Umask":@63,@"ExitTimeOut":@5,
            @"StandardOutPath":@"/dev/null",@"StandardErrorPath":@"/dev/null"};
        NSData *data=[NSPropertyListSerialization dataWithPropertyList:job format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        if(![data writeToFile:jobPath options:NSDataWritingWithoutOverwriting error:NULL] || chmod(jobPath.fileSystemRepresentation,0644))break;
        run(@"/bin/launchctl",@[@"bootstrap",domain,jobPath],nil,&rc,10);submitted=YES;
        if(rc)break;
        struct pollfd p={listener,POLLIN,0};
        int available;do{available=poll(&p,1,30000);}while(available<0&&errno==EINTR);
        if(available<=0)break;
        client=accept(listener,NULL,NULL);pid_t peer=0;
        if(client<0 || !ownerPeerV2(client,uid,&peer))break;
        fcntl(client,F_SETFD,FD_CLOEXEC);setsockopt(client,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
        VM27OwnerMessageV2 message={0};
        rc=VM27OwnerReceiveV2(client,&message,30);
        if(rc || message.kind!=VM27OwnerUIReadyV2) {erase(&message,sizeof(message));break;}
        receipt[@"UIReadinessReceived"]=@YES;receipt[@"PeerPID"]=@(peer);
        receipt[@"PeerExecutableVerified"]=@YES;ownerUIReceiptV2(receipt,stage);
        fprintf(stdout,"{\"nativeOwnerUI\":\"aqua-agent-v2\",\"uid\":%u,\"pid\":%d,\"peerExecutableVerified\":true,\"credentialLogged\":false}\n",uid,peer);fflush(stdout);
        rc=VM27OwnerReceiveV2(client,&message,305);
        if(!rc&&message.kind==VM27OwnerPasswordV2){
            secret=[NSMutableData dataWithBytes:message.bytes length:message.length];*failure=0;
        }else *failure=rc?:ECANCELED;
        erase(&message,sizeof(message));
    }while(0);
    if(client>=0)close(client);close(listener);
    if(submitted){run(@"/bin/launchctl",@[@"bootout",service],nil,&rc,10);receipt[@"AgentBootoutExit"]=@(rc);}
    BOOL jobRemoved=!unlink(jobPath.fileSystemRepresentation)||errno==ENOENT;
    BOOL endpointRemoved=!unlink(path.fileSystemRepresentation)||errno==ENOENT;
    receipt[@"Finished"]=@YES;receipt[@"Exit"]=@(*failure);
    receipt[@"LocalEndpointRemoved"]=@(endpointRemoved);receipt[@"JobFileRemoved"]=@(jobRemoved);
    ownerUIReceiptV2(receipt,stage);
    return secret;
}
