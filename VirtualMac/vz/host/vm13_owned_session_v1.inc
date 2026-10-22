#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

/* The original13 host/child binaries already accept these two environment
 * paths. Keep their bytes whole while avoiding another package's temporary
 * endpoint and stderr file. A small private directory is retained for logs. */
static BOOL VM13PrepareOwnedSessionV1(NSError **error) {
    const char *base="/private/var/mobile/Library/VirtualMacFull13Sessions-v1";
    struct stat info;
    int descriptor=-1;
    BOOL ok=NO;
    char directory[PATH_MAX];
    if(geteuid()!=501 || (mkdir(base,0700)!=0 && errno!=EEXIST))goto done;
    descriptor=open(base,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(descriptor<0 || fstat(descriptor,&info)!=0 || !S_ISDIR(info.st_mode) ||
       info.st_uid!=501 || info.st_gid!=501 || (info.st_mode&07777)!=0700)goto done;
    int count=snprintf(directory,sizeof(directory),"%s/session-%d-XXXXXX",base,getpid());
    if(count<=0 || count>=(int)sizeof(directory) || !mkdtemp(directory))goto done;
    NSString *root=[NSString stringWithUTF8String:directory];
    if(setenv("VZ_VMM_ENDPOINT_FILE",[root stringByAppendingPathComponent:@"vmm-endpoint.txt"].fileSystemRepresentation,1)!=0 ||
       setenv("VZ_VMM_STDERR_LOG",[root stringByAppendingPathComponent:@"vmm.stderr.log"].fileSystemRepresentation,1)!=0)goto done;
    fprintf(stderr,"[Complete13SessionV1] privateSession=%s nativeVMMBytesUnchanged=1\n",directory);
    ok=YES;
done:
    if(descriptor>=0)close(descriptor);
    if(!ok && error)*error=[NSError errorWithDomain:@"VirtualMac.Complete13Session" code:errno?:EACCES
        userInfo:@{NSLocalizedDescriptionKey:@"Could not prepare a private session for the complete macOS 13 backend."}];
    return ok;
}
