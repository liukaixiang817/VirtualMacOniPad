// Exact 25G83 guest-local boot installation. Personalized IMG4 envelopes and
// rollback copies stay on the guest. No host or system-volume writes occur.
#include "VM27RadioIMG4V1.inc"
#include "VM27RadioGuestProfileV1.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

static NSString *const Root=@VM27_RADIO_BOOT_ROOT;
static NSData *readCheckedFile(NSString *path, NSUInteger limit, BOOL factoryRestore) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat a,b;
    if(fd<0)return nil;
    BOOL ok=!fstat(fd,&a)&&S_ISREG(a.st_mode)&&!a.st_uid&&a.st_nlink==1&&
        (!(a.st_mode&0022)||(factoryRestore&&(a.st_mode&07777)==0666))&&a.st_size>0&&(uint64_t)a.st_size<=limit;
    NSMutableData *data=ok?[NSMutableData dataWithLength:(NSUInteger)a.st_size]:nil;NSUInteger at=0;
    while(ok&&at<data.length){ssize_t n=read(fd,(uint8_t *)data.mutableBytes+at,data.length-at);
        if(n<0&&errno==EINTR)continue;if(n<=0){ok=NO;break;}at+=(NSUInteger)n;}
    if(fstat(fd,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mtime!=b.st_mtime||
       a.st_mtimespec.tv_nsec!=b.st_mtimespec.tv_nsec||a.st_mode!=b.st_mode||a.st_uid!=b.st_uid||a.st_nlink!=b.st_nlink)ok=NO;
    close(fd);return ok?data:nil;
}
static NSData *readFile(NSString *path,NSUInteger limit){return readCheckedFile(path,limit,NO);}
static BOOL restoreTarget(NSString *name){return [name isEqual:@"RestoreKernel"]||[name isEqual:@"RestoreIBoot"];}
static NSData *readSource(NSString *path,NSString *name){
    // A genuine fresh 25G83 restore creates these two root-owned files with
    // mode0666. Only these exact, volume-derived inputs accept that factory
    // mode; all their public payload bytes must still match the audited SHA.
    // Candidates/backups and every other source retain the strict mode check.
    return readCheckedFile(path,128*1024*1024,restoreTarget(name));
}
static BOOL save(NSString *path,NSData *data){
    int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return NO;NSUInteger at=0;BOOL good=YES;
    while(at<data.length){ssize_t n=write(fd,(const uint8_t *)data.bytes+at,data.length-at);
        if(n<0&&errno==EINTR)continue;if(n<=0){good=NO;break;}at+=(NSUInteger)n;}
    if(fsync(fd))good=NO;close(fd);return good;
}
static NSData *command(NSString *program,NSArray *arguments){
    NSTask *task=[NSTask new];NSPipe *pipe=[NSPipe pipe];task.executableURL=[NSURL fileURLWithPath:program];task.arguments=arguments;
    task.standardInput=NSFileHandle.fileHandleWithNullDevice;task.standardOutput=pipe;task.standardError=NSFileHandle.fileHandleWithNullDevice;
    if(![task launchAndReturnError:NULL])return nil;
    // The fixed diskutil/bputil commands emit less than a pipe buffer. A
    // deadline also prevents a stuck mount from blocking future boot checks.
    double deadline=NSProcessInfo.processInfo.systemUptime+15;
    while(task.running&&NSProcessInfo.processInfo.systemUptime<deadline)usleep(100000);
    if(task.running){[task terminate];usleep(100000);if(task.running)kill(task.processIdentifier,SIGKILL);}
    [task waitUntilExit];NSData *data=[pipe.fileHandleForReading readDataToEndOfFile];
    return !task.terminationStatus&&data.length<262144?data:nil;
}
static NSDictionary *diskInfo(NSString *path){
    NSData *data=command(@"/usr/sbin/diskutil",@[@"info",@"-plist",path]);
    id value=data?[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL]:nil;
    return [value isKindOfClass:NSDictionary.class]?value:nil;
}
static BOOL hex(NSString *text,NSUInteger size){
    return [text isKindOfClass:NSString.class]&&text.length==size&&
        [text rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"] invertedSet]].location==NSNotFound;
}
static NSData *candidate(NSData *original,BOOL kernel){
    NSDictionary *image=radioImage(original);
    if(!image||!radioString(image[@"parts"][1],kernel?"krnl":"ibot"))return nil;
#if VM27_RADIO_GUEST_MAJOR == 26
    NSString *expected=kernel?@"268f431e7366409dc798cd8f719a93cf3a30c6f828201d8eeceae889358099c6":
        @"4c7fb3f12df511b488b6d3dc0326ac0644a66f2d8e68ebddc5f45ed9b37bd4f6";
    if(![radioSHA(image[@"payload"])isEqual:expected])return nil;
    NSMutableData *data=[image[@"payload"]mutableCopy];
    if(kernel){
        for(NSNumber *number in @[@0x16f0a98,@0x16f1bb4]){
            NSUInteger at=number.unsignedIntegerValue;uint32_t before=0;
            if(at+4>data.length)return nil;memcpy(&before,(const uint8_t *)data.bytes+at,4);
            int32_t delta=(int32_t)(before<<6)>>6;
            if((before&0xfc000000)!=0x94000000||(int64_t)at+(int64_t)delta*4!=0x16f6444)return nil;
            uint32_t after=0xd503201f;memcpy((uint8_t *)data.mutableBytes+at,&after,4);
        }
    }else{
        uint32_t before=0xaa1603e0,after=0xd2800000;
        if(data.length!=738376||memcmp((const uint8_t *)data.bytes+0x813c,&before,4))return nil;
        memcpy((uint8_t *)data.mutableBytes+0x813c,&after,4);
    }
    return radioReplace(image,data);
#else
    NSString *expected;
#if VM27_RADIO_GUEST_MAJOR == 15
    expected=kernel?@"333e6c7e8a8082f9a2cc6ce021a5664e6cdc2b5eac2f34b822886c844a6b91f8":
        @"62538f2a5a1c36ddfbae0ab3f8c13a4bec5f8fb006b3a18e6bc0a497b982495b";
    const NSUInteger kernelOffsets[]={0x1eba8c8,0x1ebb9e8};
    const uint32_t kernelWords[]={0x9400171f,0x940012d7};
    const NSUInteger bootOffsets[]={0x5d50,0xfce4};
    const uint32_t bootWords[]={0x9401374b,0x94010f66};
#elif VM27_RADIO_GUEST_MAJOR == 27
    expected=kernel?@"0fe14b0bf2d447b269e74b8f3b2cc8c008275c86c5c8e7fb1ef000bbddcaf4f2":
        @"3842735c0196a45ff5e33b0e060f69259f82e5d4c94ba3559eaba4971b6cdd80";
    const NSUInteger kernelOffsets[]={0x18a29ac,0x18a3260};
    const uint32_t kernelWords[]={0x97fff38e,0x97fff161};
    const NSUInteger bootOffsets[]={0x83b0};
    const uint32_t bootWords[]={0xaa1603e0};
#endif
    if(![radioSHA(image[@"payload"])isEqual:expected])return nil;
    NSMutableData *data=[image[@"payload"]mutableCopy];
    NSUInteger count=kernel?sizeof(kernelOffsets)/sizeof(*kernelOffsets):sizeof(bootOffsets)/sizeof(*bootOffsets);
    for(NSUInteger i=0;i<count;i++){
        NSUInteger offset=kernel?kernelOffsets[i]:bootOffsets[i];
        uint32_t before=kernel?kernelWords[i]:bootWords[i],after=kernel?0xd503201f:0xd2800000;
        if(offset>data.length||data.length-offset<4||memcmp((const uint8_t *)data.bytes+offset,&before,4))return nil;
        memcpy((uint8_t *)data.mutableBytes+offset,&after,4);
    }
    return radioReplace(image,data);
#endif
}
int main(int argc,char **argv){@autoreleasepool{
    BOOL inspect=argc==2&&!strcmp(argv[1],"--inspect");
    if((argc!=1&&!inspect)||geteuid())return EPERM;
    NSDictionary *version=[NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSDictionary *installed=[NSDictionary dictionaryWithContentsOfFile:@"/Library/VirtualMac/SharedRadio/Provisioning.plist"];
    if(![version[@"ProductBuildVersion"]isEqual:@VM27_RADIO_GUEST_BUILD]||![installed[@"CombinedInstallation"]isEqual:@YES])return ENOTSUP;
    NSDictionary *info=diskInfo(@"/");NSString *group=info[@"APFSVolumeGroupID"],*recoveryDevice=info[@"RecoveryDeviceIdentifier"];
    if(![[NSUUID alloc]initWithUUIDString:group]||![recoveryDevice isKindOfClass:NSString.class]||
       ![recoveryDevice hasPrefix:@"disk"]||recoveryDevice.length>32)return EINVAL;
    NSString *policy=[[NSString alloc]initWithData:command(@"/usr/bin/bputil",@[@"-d"]) encoding:NSUTF8StringEncoding];
    NSString *nsih=nil;
    for(NSString *line in [policy componentsSeparatedByString:@"\n"]){
        if(![line containsString:@"(nsih):"])continue;
        nsih=[[line componentsSeparatedByString:@":"]lastObject];nsih=[nsih stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    }
    if(!hex(nsih,96))return EINVAL;
    NSDictionary *recovery=diskInfo(recoveryDevice);
    if(![recovery[@"Mounted"]boolValue]){
        if(!command(@"/usr/sbin/diskutil",@[@"mount",recoveryDevice]))return EIO;
        recovery=diskInfo(recoveryDevice);
    }
    NSString *mount=recovery[@"MountPoint"];
    if(![mount isKindOfClass:NSString.class]||![mount hasPrefix:@"/Volumes/"]||![recovery[@"DeviceIdentifier"]isEqual:recoveryDevice])return EINVAL;
    NSString *preboot=[@"/System/Volumes/Preboot" stringByAppendingPathComponent:group];
    NSString *boot=[preboot stringByAppendingPathComponent:[@"boot" stringByAppendingPathComponent:nsih]];
#if VM27_RADIO_GUEST_MAJOR == 27
    (void)boot; // This profile preserves both normal MainOS boot files.
#endif
    NSString *recoveryBoot=[[mount stringByAppendingPathComponent:group] stringByAppendingPathComponent:[@"boot" stringByAppendingPathComponent:nsih]];
    NSString *kernel=@"System/Library/Caches/com.apple.kernelcaches/kernelcache",*iboot=@"usr/standalone/firmware/iBoot.img4";
    NSArray *targets=@[
#if VM27_RADIO_GUEST_MAJOR == 26
        @[@"MainKernel",[boot stringByAppendingPathComponent:kernel],@YES],
#endif
#if VM27_RADIO_GUEST_MAJOR != 27
        @[@"MainIBoot",[boot stringByAppendingPathComponent:iboot],@NO],
#endif
        @[@"RestoreKernel",[preboot stringByAppendingPathComponent:@"restore/kernelcache.release.vma2"],@YES],
        @[@"RestoreIBoot",[preboot stringByAppendingPathComponent:@"restore/Firmware/all_flash/iBoot.vma2.RELEASE.im4p"],@NO],
        @[@"RecoveryKernel",[recoveryBoot stringByAppendingPathComponent:kernel],@YES],
        @[@"RecoveryIBoot",[recoveryBoot stringByAppendingPathComponent:iboot],@NO]];
    if(inspect){
        NSMutableArray *metadata=[NSMutableArray array];
        for(NSArray *entry in targets){
            NSData *data=readSource(entry[1],entry[0]);NSDictionary *image=data?radioImage(data):nil;
            NSString *kind=image?[[NSString alloc]initWithData:radioBody(image[@"parts"][1],NULL) encoding:NSASCIIStringEncoding]:nil;
            [metadata addObject:@{@"name":entry[0],@"readable":@(data!=nil),@"fourcc":kind?:@"",
                @"publicPayloadSHA256":image?radioSHA(image[@"payload"]):@"",@"payloadBytes":@([image[@"payload"]length])}];
        }
        NSData *json=[NSJSONSerialization dataWithJSONObject:metadata options:NSJSONWritingSortedKeys error:NULL];
        fwrite(json.bytes,1,json.length,stdout);putchar('\n');return 0;
    }
    struct stat st;
    if(mkdir(Root.fileSystemRepresentation,0700)&&errno!=EEXIST)return EIO;
    if(lstat(Root.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0077))return EPERM;
    NSString *planPath=[Root stringByAppendingPathComponent:@"Plan.plist"];
    NSData *prior=readFile(planPath,65536);
    NSDictionary *plan=prior?[NSPropertyListSerialization propertyListWithData:prior options:0 format:NULL error:NULL]:nil;
    NSMutableArray *rows=[NSMutableArray array];
    if(plan){
        if(![plan[@"GuestBuild"]isEqual:@VM27_RADIO_GUEST_BUILD]||![plan[@"VolumeGroup"]isEqual:group]||![plan[@"NSIH"]isEqual:nsih]||[plan[@"Targets"]count]!=targets.count)return EPERM;
        [rows addObjectsFromArray:plan[@"Targets"]];
    }else{
        // Validate every target before writing any candidate or live image.
        NSMutableArray *originals=[NSMutableArray array],*candidates=[NSMutableArray array];
        for(NSArray *entry in targets){
            NSData *original=readSource(entry[1],entry[0]),*next=original?candidate(original,[entry[2]boolValue]):nil;
            if(!next){fprintf(stderr,"Boot source profile refused: %s\n",[entry[0]UTF8String]);return EINVAL;}
            [originals addObject:original];[candidates addObject:next];
        }
        for(NSUInteger i=0;i<targets.count;i++){
            NSArray *entry=targets[i];NSString *backup=[Root stringByAppendingPathComponent:[entry[0]stringByAppendingString:@".original"]];
            NSString *next=[Root stringByAppendingPathComponent:[entry[0]stringByAppendingString:@".candidate"]];
            if(!save(backup,originals[i])||!save(next,candidates[i]))return EIO;
            [rows addObject:@{@"Name":entry[0],@"Path":entry[1],@"Original":backup,@"Candidate":next,
                             @"OriginalHash":radioSHA(originals[i]),@"CandidateHash":radioSHA(candidates[i])}];
        }
        plan=@{@"Schema":@1,@"GuestBuild":@VM27_RADIO_GUEST_BUILD,@"VolumeGroup":group,@"NSIH":nsih,@"Targets":rows};
        if(!save(planPath,[NSPropertyListSerialization dataWithPropertyList:plan format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL]))return EIO;
    }
    for(NSUInteger i=0;i<targets.count;i++){
        NSDictionary *row=rows[i];NSArray *expected=targets[i];
        if(![row[@"Name"]isEqual:expected[0]]||![row[@"Path"]isEqual:expected[1]]||
           ![row[@"Original"]isEqual:[Root stringByAppendingPathComponent:[expected[0]stringByAppendingString:@".original"]]]||
           ![row[@"Candidate"]isEqual:[Root stringByAppendingPathComponent:[expected[0]stringByAppendingString:@".candidate"]]])return EPERM;
        NSData *old=readFile(row[@"Original"],128*1024*1024),*next=readFile(row[@"Candidate"],128*1024*1024),*current=readSource(row[@"Path"],row[@"Name"]);
        if(![radioSHA(old)isEqual:row[@"OriginalHash"]]||![candidate(old,[expected[2]boolValue])isEqual:next]||
           ![radioSHA(next)isEqual:row[@"CandidateHash"]]||(![current isEqual:old]&&![current isEqual:next]))return EINVAL;
    }
    NSMutableArray *applied=[NSMutableArray array];
    for(NSDictionary *row in rows){
        NSData *current=readSource(row[@"Path"],row[@"Name"]);if([radioSHA(current)isEqual:row[@"CandidateHash"]])continue;
        if(![radioSHA(current)isEqual:row[@"OriginalHash"]])return EINVAL;
        NSData *next=readFile(row[@"Candidate"],128*1024*1024);
        if(![next writeToFile:row[@"Path"] options:NSDataWritingAtomic error:NULL]||
           chmod([row[@"Path"]fileSystemRepresentation],0600)||
           ![radioSHA(readFile(row[@"Path"],128*1024*1024))isEqual:row[@"CandidateHash"]]){
            // Roll back writes made in this invocation. Earlier interrupted
            // writes remain verifiable and resumable from the complete plan.
            for(NSDictionary *done in [applied arrayByAddingObject:row]){
                [readFile(done[@"Original"],128*1024*1024)writeToFile:done[@"Path"] options:NSDataWritingAtomic error:NULL];
                chmod([done[@"Path"]fileSystemRepresentation],0600);
            }
            return EIO;
        }
        [applied addObject:row];
    }
    printf("VM27_RADIO%d_GUEST_BOOT_IMAGES_PREPARED\n",VM27_RADIO_GUEST_MAJOR);return 0;
}}
