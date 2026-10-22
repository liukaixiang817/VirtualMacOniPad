#import "vm13_owned_runtime_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static BOOL owner13(const struct stat *s) {
#if defined(VM13_OWNED_RUNTIME_TESTING)
    return s->st_uid==geteuid() && s->st_gid==getegid();
#else
    return s->st_uid==501 && s->st_gid==501;
#endif
}

static BOOL fail13(NSError **error) {
    if (error) *error=[NSError errorWithDomain:@"VirtualMac.Complete13Runtime" code:1
        userInfo:@{NSLocalizedDescriptionKey:@"The complete macOS 13 runtime is missing or changed. Reinstall the complete runtime before selecting it."}];
    return NO;
}
static BOOL relative13(id value) {
    if (![value isKindOfClass:NSString.class] || ![value length] ||
        [value length]>1024 || [value hasPrefix:@"/"]) return NO;
    for (NSString *component in [value componentsSeparatedByString:@"/"])
        if (!component.length || [component isEqualToString:@"."] ||
            [component isEqualToString:@".."] ||
            [component rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)
            return NO;
    return YES;
}
static BOOL directory13(int descriptor) {
    struct stat s;
    return fstat(descriptor,&s)==0 && S_ISDIR(s.st_mode) &&
        owner13(&s) && (s.st_mode&07777)==0700;
}
/* Walk regular parent directories by descriptor; a framework's reviewed
 * relative alias is checked separately and is not used by this file reader. */
static int parent13(int root, NSString *path, NSString **leaf) {
    NSArray<NSString *> *parts=[path componentsSeparatedByString:@"/"];
    int fd=dup(root);
    if (fd<0) return -1;
    for (NSUInteger index=0; index+1<parts.count; index++) {
        int next=openat(fd,parts[index].fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd);fd=next;
        if (fd<0) return -1;
        if (!directory13(fd)) { close(fd);return -1; }
    }
    *leaf=parts.lastObject;return fd;
}
static BOOL stable13(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
        a->st_uid==b->st_uid && a->st_gid==b->st_gid && a->st_mode==b->st_mode && a->st_nlink==b->st_nlink &&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static BOOL read13(int root,NSString *path,uint64_t bytes,unsigned mode,
    uint8_t digest[CC_SHA256_DIGEST_LENGTH],NSMutableData *contents) {
    NSString *leaf=nil;int parent=parent13(root,path,&leaf);
    if (parent<0) return NO;
    int fd=openat(parent,leaf.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(parent);
    if (fd<0) return NO;
    struct stat before,after;BOOL ok=NO;uint64_t count=0;
    if (fstat(fd,&before)!=0 || !S_ISREG(before.st_mode) || before.st_nlink!=1 ||
        !owner13(&before) || (before.st_mode&07777)!=mode ||
        before.st_size<0 || (uint64_t)before.st_size!=bytes) goto done;
    CC_SHA256_CTX context;CC_SHA256_Init(&context);
    uint8_t buffer[65536];ssize_t n;
    while ((n=read(fd,buffer,sizeof(buffer)))>0) {
        count+=(uint64_t)n;if(count>bytes)goto done;
        CC_SHA256_Update(&context,buffer,(CC_LONG)n);
        if(contents)[contents appendBytes:buffer length:(NSUInteger)n];
    }
    if (n<0 || count!=bytes || fstat(fd,&after)!=0 || !stable13(&before,&after))goto done;
    CC_SHA256_Final(digest,&context);ok=YES;
done:
    close(fd);return ok;
}
static BOOL digest13(NSString *hex,const uint8_t actual[32]) {
    if (![hex isKindOfClass:NSString.class] || hex.length!=64) return NO;
    const char *p=hex.UTF8String;uint8_t different=0;
    for(unsigned index=0;index<32;index++) {
        unsigned byte=0;
        for(unsigned nibble=0;nibble<2;nibble++) {
            unsigned char c=(unsigned char)p[index*2+nibble];unsigned digit;
            if(c>='0'&&c<='9')digit=c-'0';else if(c>='a'&&c<='f')digit=c-'a'+10;else return NO;
            byte=(byte<<4)|digit;
        }
        different|=actual[index]^(uint8_t)byte;
    }
    return different==0;
}
BOOL VM13OwnedRuntimePreflightV1(NSString *root,NSError **error) {
    if (![root isKindOfClass:NSString.class] || !root.length ||
        !VM13OwnedRuntimeManifestBytesV1 || VM13OwnedRuntimeManifestBytesV1>262144)return fail13(error);
    char canonical[PATH_MAX];
    if (!realpath(root.fileSystemRepresentation,canonical) ||
        strcmp(canonical,root.fileSystemRepresentation)!=0)return fail13(error);
#if !defined(VM13_OWNED_RUNTIME_TESTING)
    if(strcmp(canonical,"/private/var/mobile/Library/VirtualMacFull13Runtime-v1")!=0)return fail13(error);
#endif
    int fd=open(canonical,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return fail13(error);
    BOOL ok=NO;uint8_t digest[32];NSMutableData *data=[NSMutableData data];
    id manifest=nil;NSArray *files=nil,*links=nil;NSMutableSet *seen=nil;
    if(!directory13(fd) || !read13(fd,@"VM13OwnedRuntimeManifestV1.json",VM13OwnedRuntimeManifestBytesV1,0600,digest,data) ||
        memcmp(digest,VM13OwnedRuntimeManifestSHA256V1,32)!=0)goto done;
    manifest=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if(![manifest isKindOfClass:NSDictionary.class] ||
        ![manifest[@"canonicalDeviceRoot"]isEqual:@"/private/var/mobile/Library/VirtualMacFull13Runtime-v1"])goto done;
    files=manifest[@"files"];links=manifest[@"relativeSymlinks"];
    if(![files isKindOfClass:NSArray.class] || files.count!=106 ||
        ![links isKindOfClass:NSArray.class] || links.count>128)goto done;
    seen=[NSMutableSet set];
    for(id row in files) {
        if(![row isKindOfClass:NSDictionary.class])goto done;
        NSString *path=row[@"path"],*kind=row[@"kind"];id size=row[@"bytes"];
        if(!relative13(path) || ![path hasPrefix:@"payload/"] || [seen containsObject:path] ||
            ![size isKindOfClass:NSNumber.class] || [size longLongValue]<=0 || [size unsignedLongLongValue]>134217728)goto done;
        unsigned mode=[kind isEqual:@"mach-o"]?0700:[kind isEqual:@"resource"]?0600:0;
        if(!mode || [row[@"mode"]unsignedIntValue]!=mode ||
            !read13(fd,path,[size unsignedLongLongValue],mode,digest,nil) || !digest13(row[@"sha256"],digest))goto done;
        [seen addObject:path];
    }
    for(id row in links) {
        if(![row isKindOfClass:NSDictionary.class] || !relative13(row[@"path"]) ||
            ![row[@"target"]isKindOfClass:NSString.class] || [row[@"target"]hasPrefix:@"/"])goto done;
        NSString *path=[@"payload/" stringByAppendingString:row[@"path"]],*leaf=nil;
        int parent=parent13(fd,path,&leaf);if(parent<0)goto done;
        char target[PATH_MAX];ssize_t n=readlinkat(parent,leaf.fileSystemRepresentation,target,sizeof(target)-1);close(parent);
        if(n<=0 || (size_t)n>=sizeof(target)-1)goto done;target[n]=0;
        if(strcmp(target,[row[@"target"]UTF8String])!=0)goto done;
        char resolved[PATH_MAX];NSString *full=[root stringByAppendingPathComponent:path];
        if(!realpath(full.fileSystemRepresentation,resolved) ||
            ![[NSString stringWithUTF8String:resolved]hasPrefix:[root stringByAppendingString:@"/"]])goto done;
    }
    ok=YES;
done:
    close(fd);return ok?YES:fail13(error);
}
