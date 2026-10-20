/* Actual app-private re-export/CF state consumer. No original VMM, VM, GPU,
 * host LaunchServices daemon, system registry or operating-system policy calls. */
#include "client_services_consumer_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned Checks, HeaderChecks, FileChecks, ScopeChecks, InventoryChecks, XPCCommandCount;
static bool XPCPIDSymbolPresent;
static char XPCUUID[33];
static char Directory[4096], SelfSHA[65];
static const char *Leaves[] = {"VM27ClientServices.dylib", "VM27ClientRegistration.dylib", "VM27PrivateProcessTitle.dylib"};
static const char *UUIDs[] = {VM27_AGGREGATE_UUID, VM27_BRIDGE_UUID, VM27_TITLE_UUID};
static const char *Hashes[] = {VM27_AGGREGATE_SHA, VM27_BRIDGE_SHA, VM27_TITLE_SHA};
static const void *Frames[3];
static void Need(bool ok, const char *why) {
    ++Checks;
    if (!ok) { fprintf(stderr, "private client services contract failure: %.120s errno=%d\n", why, errno); exit(20); }
}
static void HNeed(bool b, const char *why) { ++HeaderChecks; Need(b, why); }
static void FNeed(bool b, const char *why) { ++FileChecks; Need(b, why); }
static void SNeed(bool b, const char *why) { ++ScopeChecks; Need(b, why); }
static void INeed(bool b, const char *why) { ++InventoryChecks; Need(b, why); }
static void Limits(void) {
    struct rlimit r = {3,4}; Need(!setrlimit(RLIMIT_CPU,&r), "finite own process CPU time");
    r=(struct rlimit){1<<20,1<<20}; Need(!setrlimit(RLIMIT_FSIZE,&r), "finite own file output");
    r=(struct rlimit){64,64}; Need(!setrlimit(RLIMIT_NOFILE,&r), "finite descriptors");
    r=(struct rlimit){0,0}; Need(!setrlimit(RLIMIT_CORE,&r), "no core output");
    alarm(8);
}
static void Digest(int fd, const struct stat *before, char hex[65]) {
    CC_SHA256_CTX ctx; unsigned char block[8192], digest[32];
    CC_SHA256_Init(&ctx); size_t total=0; ssize_t n;
    while ((n=read(fd,block,sizeof(block)))>0) {
        if (total+(size_t)n>2*1024*1024) { errno=EFBIG; break; }
        CC_SHA256_Update(&ctx,block,(CC_LONG)n); total+=(size_t)n;
    }
    struct stat after;
    FNeed(n==0 && total==(size_t)before->st_size && !fstat(fd,&after) &&
        after.st_dev==before->st_dev && after.st_ino==before->st_ino &&
        after.st_size==before->st_size && after.st_nlink==1 &&
        after.st_uid==before->st_uid && after.st_gid==before->st_gid &&
        after.st_mode==before->st_mode &&
        after.st_mtimespec.tv_sec==before->st_mtimespec.tv_sec &&
        after.st_mtimespec.tv_nsec==before->st_mtimespec.tv_nsec &&
        after.st_ctimespec.tv_sec==before->st_ctimespec.tv_sec &&
        after.st_ctimespec.tv_nsec==before->st_ctimespec.tv_nsec,
        "bounded descriptor hash and stable file identity");
    CC_SHA256_Final(digest,&ctx); static const char chars[]="0123456789abcdef";
    for (unsigned i=0;i<32;++i) { hex[2*i]=chars[digest[i]>>4]; hex[2*i+1]=chars[digest[i]&15]; } hex[64]=0;
}
static void OwnFiles(void) {
    SNeed(getcwd(Directory,sizeof(Directory))!=NULL, "actual own working directory");
#if TARGET_OS_IPHONE
    SNeed(getuid()==0 && geteuid()==0 && getgid()==0 && getegid()==0, "exact native root credentials");
    const char *prefix="/private/var/tmp/vm27-client-services-native-v1-"; size_t n=strlen(prefix);
    SNeed(strlen(Directory)==n+16 && !strncmp(Directory,prefix,n), "exact native private namespace");
    for (unsigned i=0;i<16;++i) SNeed((Directory[n+i]>='0'&&Directory[n+i]<='9') || (Directory[n+i]>='a'&&Directory[n+i]<='f'), "native namespace lower hex");
#endif
    int dir=open(Directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); struct stat ds;
    FNeed(dir>=0 && !fstat(dir,&ds) && S_ISDIR(ds.st_mode) && ds.st_uid==geteuid() &&
        ds.st_gid==getegid() && (ds.st_mode&0777)==0700, "owned private directory descriptor");
    const char *files[]={"private-client-services-self-consumer",Leaves[0],Leaves[1],Leaves[2]};
    for (unsigned i=0;i<4;++i) {
        int fd=openat(dir,files[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC); struct stat before;
        FNeed(fd>=0 && !fstat(fd,&before) && S_ISREG(before.st_mode) && before.st_nlink==1 &&
            before.st_uid==geteuid() && before.st_gid==getegid() &&
            (before.st_mode&0777)==(i?0600:0700) && before.st_size>0 && before.st_size<2*1024*1024,
            "ordinary owned package file with exact mode");
        char hash[65]; Digest(fd,&before,hash);
        FNeed(i?!strcmp(hash,Hashes[i-1]):true, "exact frozen provider file SHA256");
        if (!i) memcpy(SelfSHA,hash,sizeof(SelfSHA));
        FNeed(!close(fd), "own descriptor closed");
    }
    FNeed(!close(dir), "own directory descriptor closed");
}
static void Header(const struct mach_header_64 *h, unsigned provider) {
    HNeed(h && h->magic==MH_MAGIC_64 && h->filetype==MH_DYLIB &&
        (uint32_t)h->cputype==0x100000c && ((uint32_t)h->cpusubtype&0xffffff)==2 &&
        h->ncmds && h->ncmds<=128 && h->sizeofcmds && h->sizeofcmds<=16384,
        "actual bounded arm64e provider header");
    const unsigned char *b=(const void *)(h+1); size_t at=0;
    unsigned uuidCount=0,idCount=0; char uuid[33]={0}; bool actualID=false;
    static const char digits[]="0123456789abcdef";
    for (unsigned i=0;i<h->ncmds;++i) {
        HNeed(at<=h->sizeofcmds && h->sizeofcmds-at>=8, "load command prefix");
        const struct load_command *c=(const void *)(b+at);
        HNeed(c->cmdsize>=8 && !(c->cmdsize&7) && c->cmdsize<=h->sizeofcmds-at, "bounded actual load command");
        if (c->cmd==LC_UUID) {
            HNeed(c->cmdsize==24 && ++uuidCount==1, "one actual provider UUID");
            for (unsigned j=0;j<16;++j) { uuid[2*j]=digits[b[at+8+j]>>4]; uuid[2*j+1]=digits[b[at+8+j]&15]; }
        } else if (c->cmd==LC_ID_DYLIB) {
            HNeed(c->cmdsize>=32 && ++idCount==1, "one actual provider ID");
            const struct dylib_command *d=(const void *)c; const char *p=(const void *)(b+at+d->dylib.name.offset);
            char wanted[128]; int written=snprintf(wanted,sizeof(wanted),"@rpath/%s",Leaves[provider]);
            actualID=d->dylib.name.offset>=24 && d->dylib.name.offset<c->cmdsize && written>0 &&
                (size_t)written<sizeof(wanted) && memchr(p,0,c->cmdsize-d->dylib.name.offset) &&
                !strcmp(p,wanted) && d->dylib.current_version==65536 && d->dylib.compatibility_version==65536;
        }
        at+=c->cmdsize;
    }
    HNeed(at==h->sizeofcmds && uuidCount==1 && idCount==1 && actualID && !strcmp(uuid,UUIDs[provider]),
        "exact loaded provider UUID and compatible version");
}
static void LoadedFrames(void) {
    uint32_t count=_dyld_image_count(); HNeed(count>0 && count<=2048, "bounded self dyld image enumeration");
    for (unsigned provider=0;provider<3;++provider) {
        char wanted[4096]; int n=snprintf(wanted,sizeof(wanted),"%s/%s",Directory,Leaves[provider]);
        HNeed(n>0 && (size_t)n<sizeof(wanted), "exact own loaded provider path");
        unsigned found=0; const struct mach_header_64 *h=NULL;
        for (uint32_t i=0;i<count;++i) {
            const char *name=_dyld_get_image_name(i);
            if (name && !strcmp(name,wanted)) { ++found; h=(const void *)_dyld_get_image_header(i); }
        }
        HNeed(found==1 && h!=NULL, "one actual own loaded provider frame");
        Header(h,provider); Frames[provider]=h;
    }
}
static void Owner(void *pointer, unsigned provider, bool function) {
    if (function) pointer=ptrauth_strip(pointer,ptrauth_key_function_pointer);
    Dl_info d={0}; char wanted[4096]; int n=snprintf(wanted,sizeof(wanted),"%s/%s",Directory,Leaves[provider]);
    Need(pointer && n>0 && (size_t)n<sizeof(wanted) && dladdr(pointer,&d) &&
        d.dli_fbase==Frames[provider] && d.dli_fname && !strcmp(d.dli_fname,wanted),
        "resolved symbol exact own provider frame and path");
}
static void StockXPCInventory(void) {
    /* Existence/owner inventory only. Never call a possibly unavailable entry
     * or replace it, and never fabricate a native connection for this check. */
    void *library=dlopen("/usr/lib/system/libxpc.dylib",RTLD_NOW|RTLD_LOCAL);
    INeed(library!=NULL,"actual canonical stock libxpc load");
    void *symbol=dlsym(library,"xpc_connection_get_pid"); XPCPIDSymbolPresent=symbol!=NULL;
    if (!symbol) return;
    Dl_info owner={0}; symbol=ptrauth_strip(symbol,ptrauth_key_function_pointer);
    INeed(dladdr(symbol,&owner) && owner.dli_fbase && owner.dli_fname &&
        !strcmp(owner.dli_fname,"/usr/lib/system/libxpc.dylib"), "actual PID symbol stock provider owner");
    const struct mach_header_64 *h=owner.dli_fbase;
    INeed(h->magic==MH_MAGIC_64 && h->filetype==MH_DYLIB && h->ncmds>0 && h->ncmds<=256 &&
        h->sizeofcmds>0 && h->sizeofcmds<=65536, "bounded actual stock provider header");
    XPCCommandCount=h->ncmds; const unsigned char *b=(const void *)(h+1); size_t at=0; unsigned found=0;
    static const char digits[]="0123456789abcdef";
    for (unsigned i=0;i<h->ncmds;++i) {
        INeed(at<=h->sizeofcmds && h->sizeofcmds-at>=8,"stock command prefix");
        const struct load_command *c=(const void *)(b+at);
        INeed(c->cmdsize>=8 && !(c->cmdsize&7) && c->cmdsize<=h->sizeofcmds-at,"bounded stock command");
        if (c->cmd==LC_UUID) { INeed(c->cmdsize==24 && ++found==1,"one actual stock UUID");
            for (unsigned j=0;j<16;++j) { XPCUUID[2*j]=digits[b[at+8+j]>>4]; XPCUUID[2*j+1]=digits[b[at+8+j]&15]; }
        }
        at+=c->cmdsize;
    }
    const char *expected=TARGET_OS_IPHONE?"7a0ca8d2728537ddae972efaa1de763e":"0791121fb5fc3f84bf04115e86d2d882";
    INeed(at==h->sizeofcmds && found==1 && !strcmp(XPCUUID,expected),"actual stock symbol UUID");
    /* Keep the system cache handle for the lifetime of this own process. */
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0); Limits();
    Need(argc==2 && !strcmp(argv[1],"--private-client-services-self-consumer"), "explicit private self-consumer argv");
    OwnFiles(); char aggregate[4096]; int n=snprintf(aggregate,sizeof(aggregate),"%s/%s",Directory,Leaves[0]);
    Need(n>0 && (size_t)n<sizeof(aggregate), "exact private aggregate path");
    void *handle=dlopen(aggregate,RTLD_NOW|RTLD_LOCAL);
    if (!handle) { fprintf(stderr,"private client services dlopen failure: %.1000s\n",dlerror()); return 20; }
    Need(handle!=NULL,"real private aggregate load"); LoadedFrames();
    CFTypeRef (*get)(void)=dlsym(handle,"_LSGetCurrentApplicationASN");
    int32_t (*set)(int32_t,CFTypeRef,CFStringRef,CFTypeRef,CFTypeRef *)=dlsym(handle,"_LSSetApplicationInformationItem");
    CFStringRef (*copy)(void)=dlsym(handle,"VM27CopyPrivateProcessDisplayName");
    CFArrayRef (*match)(int32_t,uint32_t,const CFStringRef *,const CFTypeRef *)=dlsym(handle,"_LSCopyMatchingApplicationsWithItems");
    CFTypeRef (*item)(int32_t,CFTypeRef,CFStringRef)=dlsym(handle,"_LSCopyApplicationInformationItem");
    int (*configure)(pid_t,const char *,uint64_t)=dlsym(handle,"VM27ClientRegistrationConfigureV1");
    const CFStringRef *title=dlsym(handle,"_kLSDisplayNameKey"),*pid=dlsym(handle,"_kLSPIDKey");
    Owner((void *)get,2,true); Owner((void *)set,2,true); Owner((void *)copy,2,true); Owner((void *)title,2,false);
    Owner((void *)match,1,true); Owner((void *)item,1,true); Owner((void *)configure,1,true); Owner((void *)pid,1,false);
    Need(*title && *pid && CFGetTypeID(*title)==CFStringGetTypeID() && CFGetTypeID(*pid)==CFStringGetTypeID() &&
        CFEqual(*title,CFSTR("LSDisplayName")) && CFEqual(*pid,CFSTR("pid")), "real CFString constant slots");
    CFTypeRef own=get(); Need(own && CFGetTypeID(own)==CFDictionaryGetTypeID() && get()==own, "real stable borrowed own process identity");
    CFStringRef text=CFStringCreateWithCString(NULL,"private client services \xe7\x9c\x9f\xe5\xae\x9e title",kCFStringEncodingUTF8);
    Need(text && !set(-2,own,*title,text,NULL), "actual immutable title store");
    CFStringRef returned=copy(); Need(returned && CFGetTypeID(returned)==CFStringGetTypeID() && CFEqual(returned,text), "actual retained title readback");
    CFRelease(returned); CFRelease(text);
    errno=0; Need(set(-2,(CFTypeRef)(uintptr_t)1,*title,CFSTR("bad"),NULL)==-50 && errno==EINVAL, "unknown own identity fails before dereference");
    struct { uint64_t before; CFTypeRef output; uint64_t after; } guarded={0x1122334455667788ULL,(CFTypeRef)(uintptr_t)1,0x8877665544332211ULL};
    errno=0; Need(set(-2,own,*title,CFSTR("bad"),&guarded.output)==-50 && errno==EINVAL &&
        guarded.before==0x1122334455667788ULL && guarded.output==(CFTypeRef)(uintptr_t)1 && guarded.after==0x8877665544332211ULL,
        "unsupported output rejected without any writes");
    pid_t foreign=getpid()==INT32_MAX?getpid()-1:getpid()+1; CFNumberRef number=CFNumberCreate(NULL,kCFNumberIntType,&foreign);
    Need(number!=NULL,"actual foreign PID CFNumber"); CFStringRef keys[]={*pid}; CFTypeRef values[]={number};
    errno=0; Need(!match(-2,1,keys,values) && errno==ENOENT, "unregistered foreign client is not own title"); CFRelease(number);
    errno=0; Need(!item(-2,(CFTypeRef)(uintptr_t)1,*title) && errno==ENOENT, "unknown client identity fails before CF access");
    Need(configure(getpid(),"0000000000000000000000000000000000000000",1)==EINVAL, "own process cannot impersonate foreign client");
    StockXPCInventory();
    printf("{\"record\":\"Summary\",\"schema\":\"private-client-services-self-consumer-v1\",\"scope\":\"%s\",\"PID\":%d,\"UID\":%u,\"EUID\":%u,\"GID\":%u,\"EGID\":%u,\"checks\":%u,\"headerChecks\":%u,\"fileChecks\":%u,\"scopeChecks\":%u,\"inventoryChecks\":%u,\"xpcConnectionGetPIDSymbolPresent\":%s,\"xpcProviderUUID\":\"%s\",\"xpcProviderLoadCommands\":%u,\"xpcFunctionCalled\":false,\"xpcReplacementProvided\":false,\"selfSHA256\":\"%s\",\"aggregateSHA256\":\"%s\",\"bridgeSHA256\":\"%s\",\"titleSHA256\":\"%s\",\"aggregateUUID\":\"%s\",\"bridgeUUID\":\"%s\",\"titleUUID\":\"%s\",\"providersLoaded\":3,\"originalFunctionsResolved\":4,\"constantSlotsResolved\":2,\"auxiliaryFunctionsResolved\":2,\"realTitleStores\":1,\"realTitleReadbacks\":1,\"callerRetainedObjectsReleased\":3,\"unconfiguredMatchingRejected\":true,\"unknownIdentityRejected\":true,\"ownAsClientRejected\":true,\"unsupportedOutputUnchanged\":true,\"hostGlobalLSRegistry\":false,\"originalVMMExecuted\":false,\"nativeCPUCalls\":0,\"nativeVMCalls\":0,\"nativeGPUCalls\":0,\"full27Backend\":false}\n",
        TARGET_OS_IPHONE?"native-ios":"own-mac-private-helper",getpid(),getuid(),geteuid(),getgid(),getegid(),Checks,HeaderChecks,FileChecks,ScopeChecks,InventoryChecks,
        XPCPIDSymbolPresent?"true":"false",XPCUUID,XPCCommandCount,SelfSHA,Hashes[0],Hashes[1],Hashes[2],UUIDs[0],UUIDs[1],UUIDs[2]);
    /* The two providers retain immutable state for process lifetime. Keep the
     * load handle until this process exits; no borrowed CF identity is freed. */
    return 0;
}
