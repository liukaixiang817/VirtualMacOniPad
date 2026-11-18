// Prepare only the fixed disposable 26A5416b guest's complete boot candidates.
// Personalized envelopes and original backups remain inside this guest.
#include "VM27RadioIMG4V1.inc"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static NSData *readOriginal(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat before={0},after={0};
    if(fd<0)return nil;
    BOOL valid=!fstat(fd,&before)&&S_ISREG(before.st_mode)&&before.st_uid==0&&
        before.st_nlink==1&&before.st_size>0&&before.st_size<128*1024*1024;
    NSMutableData *data=valid?[NSMutableData dataWithLength:(NSUInteger)before.st_size]:nil;
    NSUInteger offset=0;
    while(valid&&offset<data.length){
        ssize_t n=read(fd,(uint8_t *)data.mutableBytes+offset,data.length-offset);
        if(n<=0){valid=NO;break;}offset+=(NSUInteger)n;
    }
    if(fstat(fd,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
       before.st_size!=after.st_size||before.st_mtime!=after.st_mtime)valid=NO;
    close(fd);return valid?data:nil;
}
static BOOL saveNew(NSString *path,NSData *data){
    if(!data.length)return NO;
    int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return NO;
    NSUInteger at=0;BOOL valid=YES;
    while(at<data.length){ssize_t n=write(fd,(const uint8_t *)data.bytes+at,data.length-at);
        if(n<=0){valid=NO;break;}at+=(NSUInteger)n;}
    if(fsync(fd))valid=NO;close(fd);return valid;
}
static BOOL instruction(NSMutableData *data,NSUInteger at,uint32_t before,uint32_t after){
    if((at&3)||at+4>data.length||memcmp((const uint8_t *)data.bytes+at,&before,4))return NO;
    memcpy((uint8_t *)data.mutableBytes+at,&after,4);return YES;
}
static NSData *candidatePayload(NSDictionary *image,BOOL kernel,BOOL mainKernel){
    NSString *expected=kernel?@"0fe14b0bf2d447b269e74b8f3b2cc8c008275c86c5c8e7fb1ef000bbddcaf4f2":
        @"3842735c0196a45ff5e33b0e060f69259f82e5d4c94ba3559eaba4971b6cdd80";
    if(![radioSHA(image[@"payload"])isEqual:expected]||
       !radioString(image[@"parts"][1],kernel?"krnl":"ibot"))return nil;
    NSMutableData *data=[image[@"payload"]mutableCopy];
    if(kernel){
        // Exact shared BOOP implementations: auxk linked-manifest and Kcgen
        // policy update only. Each caller has w0=1 before this Boolean call.
        // The separate custom-OS fuos branch retains owner authentication.
        if(!instruction(data,0x18a29ac,0x97fff38e,0xd503201f)||
           !instruction(data,0x18a3260,0x97fff161,0xd503201f))return nil;
        for(NSNumber *offset in @[@248814,@248917]){
            NSUInteger at=offset.unsignedIntegerValue;
            if(at+7>data.length||memcmp((const uint8_t *)data.bytes+at,"RELEASE",7))return nil;
            memcpy((uint8_t *)data.mutableBytes+at,mainKernel?"RADIO27":"RADIOKC",7);
        }
    }else{
        // mBoot20457's full property-validation callback still executes and
        // fills its output context; change only its audited return value.
        if(!instruction(data,0x83b0,0xaa1603e0,0xd2800000))return nil;
    }
    return data;
}
int main(int argc,const char **argv){@autoreleasepool{
    (void)argv;
    NSDictionary *version=[NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if(argc!=1||geteuid()||![version[@"ProductBuildVersion"]isEqual:@"26A5416b"])return EPERM;
    NSString *base=@"/private/var/root/VirtualMacWiFiReview27-v034";struct stat st;
    if(lstat(base.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0077))return EPERM;
    NSString *group=@"4AB9ED39-1F96-474C-ACB6-128FBDBE6525";
    NSString *nsih=@"015D76000C9EADA92D1D8862E03B93AF9C09E6C65A1A2DBBDAA4B39602FEB23021340E5A3DDF04DF90708948E0DE86DC";
    NSString *preboot=[@"/System/Volumes/Preboot" stringByAppendingPathComponent:group];
    NSString *boot=[preboot stringByAppendingPathComponent:[@"boot" stringByAppendingPathComponent:nsih]];
    NSString *recovery=[@"/Volumes/Recovery" stringByAppendingPathComponent:group];
    NSString *recoveryBoot=[recovery stringByAppendingPathComponent:[@"boot" stringByAppendingPathComponent:nsih]];
    NSString *kernelPath=@"System/Library/Caches/com.apple.kernelcaches/kernelcache";
    NSString *ibootPath=@"usr/standalone/firmware/iBoot.img4";
    NSArray *targets=@[
        @[@"PrebootRestoreKernel",[preboot stringByAppendingPathComponent:@"restore/kernelcache.release.vma2"],@YES],
        @[@"GuestIBoot",[boot stringByAppendingPathComponent:ibootPath],@NO],
        @[@"RestoreIBoot",[preboot stringByAppendingPathComponent:@"restore/Firmware/all_flash/iBoot.vma2.RELEASE.im4p"],@NO],
        @[@"RecoveryKernel",[recoveryBoot stringByAppendingPathComponent:kernelPath],@YES],
        @[@"RecoveryIBoot",[recoveryBoot stringByAppendingPathComponent:ibootPath],@NO],
        @[@"MainCustomKernel",[boot stringByAppendingPathComponent:kernelPath],@YES]];
    // Validate all source payloads before creating a partial output directory.
    for(NSArray *entry in targets){@autoreleasepool{
        NSDictionary *image=radioImage(readOriginal(entry[1]));
        if(!image||!candidatePayload(image,[entry[2]boolValue],[entry[0]isEqual:@"MainCustomKernel"])){
            fprintf(stderr,"Source validation failed: %s\n",[entry[0]UTF8String]);return EINVAL;
        }
    }}
    NSString *output=[base stringByAppendingPathComponent:@"BootChainCandidates27-v1"];
    if(mkdir(output.fileSystemRepresentation,0700))return EEXIST;
    NSMutableArray *rows=[NSMutableArray array];
    for(NSArray *entry in targets){@autoreleasepool{
        NSData *original=readOriginal(entry[1]);NSDictionary *image=radioImage(original);
        BOOL mainKernel=[entry[0]isEqual:@"MainCustomKernel"];
        NSData *payload=candidatePayload(image,[entry[2]boolValue],mainKernel);
        NSData *candidate=mainKernel?payload:radioReplace(image,payload);
        if(!candidate)return EINVAL;
        NSString *originalName=[entry[0]stringByAppendingString:@".original.img4"];
        NSString *candidateName=[entry[0]stringByAppendingString:mainKernel?@".candidate.kc":@".candidate.img4"];
        if(!saveNew([output stringByAppendingPathComponent:originalName],original)||
           !saveNew([output stringByAppendingPathComponent:candidateName],candidate))return EIO;
        [rows addObject:@{@"label":entry[0],@"target":entry[1],@"originalFile":originalName,
            @"candidateFile":candidateName,@"originalSHA256":radioSHA(original),@"candidateSHA256":radioSHA(candidate),
            @"sourcePublicPayloadSHA256":radioSHA(image[@"payload"]),@"candidatePublicPayloadSHA256":radioSHA(payload),
            @"candidateBytes":@(candidate.length),@"personalizedEnvelopePreserved":@(!mainKernel)}];
    }}
    NSDictionary *report=@{@"schema":@1,@"scope":@"temporary RadioReview27 only",@"prepared":@YES,
        @"installed":@NO,@"personalizedImagesExported":@NO,@"candidates":rows};
    NSData *json=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
    if(!saveNew([output stringByAppendingPathComponent:@"plan.json"],json))return EIO;
    fwrite(json.bytes,1,json.length,stdout);putchar('\n');return 0;
}}
