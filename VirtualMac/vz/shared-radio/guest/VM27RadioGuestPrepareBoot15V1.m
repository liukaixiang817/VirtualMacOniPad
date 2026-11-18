// Prepares fixed candidates and local backups in the single disposable 24G90
// guest. It cannot install them. Personalized manifests never leave the guest.
#include "VM27RadioIMG4V1.inc"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#ifndef VM27_PREPARE_RESTORE_IBOOT_ONLY
#define VM27_PREPARE_RESTORE_IBOOT_ONLY 0
#endif
#ifndef VM27_PREPARE_RECOVERY_VOLUME_ONLY
#define VM27_PREPARE_RECOVERY_VOLUME_ONLY 0
#endif

static NSData *readPinnedFile(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat st,after;
    if (fd<0) return nil;
    BOOL valid=!fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_nlink==1&&st.st_size>0&&st.st_size<128*1024*1024;
    NSMutableData *data=valid?[NSMutableData dataWithLength:(NSUInteger)st.st_size]:nil; NSUInteger at=0;
    while (valid&&at<data.length) {
        ssize_t count=read(fd,(uint8_t *)data.mutableBytes+at,data.length-at);
        if (count<=0) { valid=NO; break; } at+=(NSUInteger)count;
    }
    if (fstat(fd,&after)||st.st_dev!=after.st_dev||st.st_ino!=after.st_ino||
        st.st_size!=after.st_size||st.st_mtime!=after.st_mtime) valid=NO;
    close(fd); return valid?data:nil;
}
static BOOL writeNew(NSString *path, NSData *data) {
    if (!data.length) return NO;
    int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return NO;
    NSUInteger at=0; BOOL valid=YES;
    while (at<data.length) {
        ssize_t count=write(fd,(const uint8_t *)data.bytes+at,data.length-at);
        if (count<=0) { valid=NO; break; } at+=(NSUInteger)count;
    }
    if (fsync(fd)) valid=NO; close(fd); return valid;
}
static BOOL instruction(NSMutableData *payload, NSUInteger offset, uint32_t before, uint32_t after) {
    if ((offset&3)||offset+4>payload.length||memcmp((const uint8_t *)payload.bytes+offset,&before,4)) return NO;
    memcpy((uint8_t *)payload.mutableBytes+offset,&after,4); return YES;
}
int main(int argc,const char **argv) { @autoreleasepool {
    (void)argv;
    NSDictionary *version=[NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    char kernel[512]={0}; size_t size=sizeof(kernel);
    if (argc!=1||geteuid()||![version[@"ProductBuildVersion"]isEqual:@"24G90"]||
        sysctlbyname("kern.version",kernel,&size,NULL,0)||!strstr(kernel,"RADIO15_ARM64_VMAPPLE")) return 77;
    NSString *base=@"/private/var/root/VirtualMacWiFiReview15-v033"; struct stat st;
    if (lstat(base.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0077)) return 77;
    NSString *out=[base stringByAppendingPathComponent:VM27_PREPARE_RECOVERY_VOLUME_ONLY?
        @"BootChainRecoveryVolume15-v1":VM27_PREPARE_RESTORE_IBOOT_ONLY?
        @"BootChainRestoreIBoot15-v1":@"BootChainCandidates15-v1"];
    if (mkdir(out.fileSystemRepresentation,0700)) return 73;
    NSString *preboot=VM27_PREPARE_RECOVERY_VOLUME_ONLY?
        @"/Volumes/Recovery/D2DEF9D2-5B3D-4BDC-A473-E6958FE7E29C":
        @"/System/Volumes/Preboot/D2DEF9D2-5B3D-4BDC-A473-E6958FE7E29C";
#if VM27_PREPARE_RESTORE_IBOOT_ONLY
    NSArray *paths=@[[preboot stringByAppendingPathComponent:@"restore/Firmware/all_flash/iBoot.vma2.RELEASE.im4p"]];
    NSArray *names=@[@"RestoreIBoot"];
    NSArray *hashes=@[@"62538f2a5a1c36ddfbae0ab3f8c13a4bec5f8fb006b3a18e6bc0a497b982495b"];
#else
    NSArray *paths=@[[preboot stringByAppendingPathComponent:VM27_PREPARE_RECOVERY_VOLUME_ONLY?
        @"boot/4E5E204AE9F945CEEB65FCC5D455CA9FC7A99C9EB29B4CDE7AB27EE9D60825B3DFCF60A8CCAB88F0F2F51AF8F800E6AA/System/Library/Caches/com.apple.kernelcaches/kernelcache":
        @"restore/kernelcache.release.vma2"],
        [preboot stringByAppendingPathComponent:@"boot/4E5E204AE9F945CEEB65FCC5D455CA9FC7A99C9EB29B4CDE7AB27EE9D60825B3DFCF60A8CCAB88F0F2F51AF8F800E6AA/usr/standalone/firmware/iBoot.img4"]];
    NSArray *names=@[@"KcgenKernel",@"GuestIBoot"];
    NSArray *hashes=@[@"333e6c7e8a8082f9a2cc6ce021a5664e6cdc2b5eac2f34b822886c844a6b91f8",
        @"62538f2a5a1c36ddfbae0ab3f8c13a4bec5f8fb006b3a18e6bc0a497b982495b"];
#endif
    NSMutableArray *rows=[NSMutableArray array];
    for (NSUInteger i=0;i<paths.count;++i) {
        BOOL isKernel=!VM27_PREPARE_RESTORE_IBOOT_ONLY&&i==0;
        NSData *original=readPinnedFile(paths[i]); NSDictionary *image=radioImage(original);
        if (!image||![radioSHA(image[@"payload"])isEqual:hashes[i]]||
            !radioString(image[@"parts"][1],isKernel?"krnl":"ibot")) return 65;
        NSMutableData *payload=[image[@"payload"]mutableCopy];
        if (isKernel) {
            if (!instruction(payload,0x1eba8c8,0x9400171f,0xd503201f)||
                !instruction(payload,0x1ebb9e8,0x940012d7,0xd503201f)) return 65;
            // Two kernel version copies distinguish KcgenOS from MainOS.
            for (NSUInteger offset=263005;offset<=263111;offset+=106) {
                const char *needle="Darwin Kernel Version 24.6.0: Mon Jul 14 11:30:18 PDT 2025; root:xnu-11417.140.69~1/RELEASE_ARM64_VMAPPLE";
                if (offset+strlen(needle)>payload.length||memcmp((const uint8_t *)payload.bytes+offset,needle,strlen(needle))) return 65;
                const char *suffix=strstr(needle,"RELEASE_");
                memcpy((uint8_t *)payload.mutableBytes+offset+(suffix-needle),"RADIOKC",7);
            }
        } else {
            // Both direct calls to the audited 0x53a7c boot-object validator.
            // Pre-27 iBoot otherwise rejects AuxKC objects in a VM.
            if (!instruction(payload,0x5d50,0x9401374b,0xd2800000)||
                !instruction(payload,0xfce4,0x94010f66,0xd2800000)) return 65;
        }
        NSData *candidate=radioReplace(image,payload); if (!candidate) return 65;
        NSString *originalName=[names[i]stringByAppendingString:@".original.img4"];
        NSString *candidateName=[names[i]stringByAppendingString:@".candidate.img4"];
        if (!writeNew([out stringByAppendingPathComponent:originalName],original)||
            !writeNew([out stringByAppendingPathComponent:candidateName],candidate)) return 74;
        [rows addObject:@{@"label":names[i],@"target":paths[i],@"originalFile":originalName,
            @"candidateFile":candidateName,@"sourcePublicPayloadSHA256":hashes[i],
            @"candidatePublicPayloadSHA256":radioSHA(payload),@"originalSHA256":radioSHA(original),
            @"candidateSHA256":radioSHA(candidate),@"candidateBytes":@(candidate.length),
            @"personalizedManifestAndPAYPPreserved":@YES}];
    }
    NSDictionary *result=@{@"schema":@1,@"scope":@"temporary RadioReview15 only",@"prepared":@YES,
        @"installed":@NO,@"personalizedBootImagesExported":@NO,@"candidates":rows};
    NSData *json=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:NULL];
    if (!writeNew([out stringByAppendingPathComponent:@"plan.json"],json)) return 74;
    fwrite(json.bytes,1,json.length,stdout);putchar('\n');return 0;
} }
