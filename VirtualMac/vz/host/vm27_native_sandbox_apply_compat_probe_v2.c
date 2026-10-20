/* One self-only compatibility experiment. This does not run VMM Main.
 * The 24B diagnostic wrapper below is permitted only for the fixed, genuine
 * compiler blob. Production must pass the genuine compiler-owned object. */
#include "vm27_native_sandbox_apply_abi_v1.h"
#include <TargetConditionals.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#if TARGET_OS_OSX
#include <mach/mach_vm.h>
#else
/* Actual libSystem MIG ABI. The iOS SDK excludes mach_vm.h. */
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
#endif
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define PROBE_ROOT "/private/var/mobile/Library/VirtualMacIndependent27SandboxProbe-v2"
#define PROBE_EXECUTABLE PROBE_ROOT "/sandbox-apply-compat-probe-v1"
#define PROBE_WITNESS PROBE_ROOT "/deny-witness.txt"
#define BLOB_SIZE 13696U
#define BLOB_SHA "2b7ad4d1be09203d49af1dafa560dfdb9b3ddcd5953c7ee061713a5fb34e898b"
#define WITNESS_SHA "9d1c584f2eea228394d820de217ea6190a14ce7894eaa063d985429810ed4ad2"

/* Apple WebKit SandboxSPI.h: NONE=0, PATH=1; actual current export RVA19b4.
 * Use the real native function once per observation; do not infer its result. */
typedef int (*CheckFunction)(pid_t, const char *, int, ...);
typedef struct {
    int check[4], checkErrno[4];
    int metadata, metadataErrno, nullOpen, nullErrno, nullRead, nullReadErrno;
    int readOpen, readErrno, writeOpen, writeErrno;
} Observation;

static bool Digest(const void *bytes, size_t count, const char *expected) {
    if (count > UINT32_MAX || strlen(expected) != 64) return false;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (!CC_SHA256(bytes, (CC_LONG)count, digest)) return false;
#pragma clang diagnostic pop
    char hex[65];
    for (size_t i = 0; i < sizeof(digest); ++i) snprintf(hex + i*2, 3, "%02x", digest[i]);
    return strcmp(hex, expected) == 0;
}

static bool SafeRead(uintptr_t address, void *out, size_t count) {
    mach_vm_size_t actual = 0;
    return address && count && address <= UINTPTR_MAX-count &&
        mach_vm_read_overwrite(mach_task_self(), address, count,
                               (mach_vm_address_t)out, &actual) == KERN_SUCCESS && actual == count;
}

static bool ImageUUID(uintptr_t base, const char *expected) {
    struct mach_header_64 h;
    if (!SafeRead(base, &h, sizeof(h)) || h.magic != MH_MAGIC_64 ||
        h.ncmds > 1024 || h.sizeofcmds < sizeof(struct uuid_command) || h.sizeofcmds > 65536) return false;
    unsigned char *commands = malloc(h.sizeofcmds);
    if (!commands) return false;
    bool valid = SafeRead(base + sizeof(h), commands, h.sizeofcmds);
    size_t offset = 0; unsigned matches = 0;
    char uuid[33] = {0};
    for (uint32_t i = 0; valid && i < h.ncmds; ++i) {
        struct load_command c;
        if (offset > h.sizeofcmds || h.sizeofcmds-offset < sizeof(c)) { valid=false; break; }
        memcpy(&c, commands+offset, sizeof(c));
        if (c.cmdsize < sizeof(c) || c.cmdsize % 8 || c.cmdsize > h.sizeofcmds-offset) { valid=false; break; }
        if (c.cmd == LC_UUID) {
            struct uuid_command u;
            if (c.cmdsize != sizeof(u)) { valid=false; break; }
            memcpy(&u, commands+offset, sizeof(u)); ++matches;
            for (size_t j=0; j<sizeof(u.uuid); ++j) snprintf(uuid+j*2,3,"%02x",u.uuid[j]);
        }
        offset += c.cmdsize;
    }
    valid = valid && offset == h.sizeofcmds && matches == 1 && strcmp(uuid,expected)==0;
    free(commands); return valid;
}

static void *Native(void **handle, const char *path, const char *name,
                    const char *uuid, uintptr_t rva, uintptr_t codeRVA,
                    size_t codeSize, const char *codeSHA) {
    *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!*handle) return NULL;
    void *symbol = dlsym(*handle, name);
    if (!symbol) return NULL;
    void *address = symbol;
#if __has_feature(ptrauth_calls)
    address = ptrauth_strip(symbol, ptrauth_key_function_pointer);
#endif
    Dl_info info = {0};
    if (!dladdr(address, &info) || !info.dli_fname || strcmp(info.dli_fname,path) ||
        !info.dli_fbase || (uintptr_t)address != (uintptr_t)info.dli_fbase+rva ||
        !ImageUUID((uintptr_t)info.dli_fbase,uuid) || codeSize > 256) return NULL;
    unsigned char code[256];
    if (!SafeRead((uintptr_t)info.dli_fbase+codeRVA,code,codeSize) || !Digest(code,codeSize,codeSHA)) return NULL;
    printf("NATIVE_IDENTITY name=%s uuid=%s rva=%lx codeSHA=%s validated=1\n",name,uuid,(unsigned long)rva,codeSHA);
    return symbol;
}

static bool FileShape(const struct stat *s, size_t count, mode_t mode) {
    return S_ISREG(s->st_mode) && s->st_uid==501 && (s->st_mode & 07777)==mode &&
        s->st_nlink==1 && s->st_size>=0 && (uint64_t)s->st_size==count;
}

static bool SameFile(const struct stat *a, const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_uid==b->st_uid &&
        a->st_mode==b->st_mode && a->st_nlink==b->st_nlink && a->st_size==b->st_size &&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}

static bool ReadPinnedAt(int directory, const char *name, size_t count, const char *hash, void *bytes) {
    if (!name || !*name || strchr(name,'/') || !count || count>BLOB_SIZE) return false;
    int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    struct stat before,after,pathStat;
    bool ok=fstat(fd,&before)==0 && FileShape(&before,count,0600);
    size_t done=0;
    while (ok && done<count) {
        ssize_t n=read(fd,(unsigned char *)bytes+done,count-done);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { ok=false; break; }
        done+=(size_t)n;
    }
    ok=ok && fstat(fd,&after)==0 && SameFile(&before,&after) &&
        fstatat(directory,name,&pathStat,AT_SYMLINK_NOFOLLOW)==0 && SameFile(&before,&pathStat) && Digest(bytes,count,hash);
    int closeResult=close(fd);
    return ok && closeResult==0;
}

static int PinnedDirectory(void) {
    char resolved[PATH_MAX]; struct stat s;
    if (!realpath(PROBE_ROOT,resolved) || strcmp(resolved,PROBE_ROOT)) return -1;
    int fd=open(PROBE_ROOT,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    if (fstat(fd,&s) || !S_ISDIR(s.st_mode) || s.st_uid!=501 || (s.st_mode&07777)!=0700) { close(fd); return -1; }
    return fd;
}

static bool ActualExecutable(void) {
    char path[PATH_MAX]={0},resolved[PATH_MAX]; uint32_t capacity=sizeof(path); struct stat s;
    if (_NSGetExecutablePath(path,&capacity) || !memchr(path,0,sizeof(path)) ||
        !realpath(path,resolved) || strcmp(resolved,PROBE_EXECUTABLE) || lstat(resolved,&s)) return false;
    return S_ISREG(s.st_mode) && s.st_uid==501 && (s.st_mode&07777)==0700 && s.st_nlink==1 &&
        s.st_size>0 && s.st_size<=1048576;
}

static int FreshOpen(const char *path, int access, int *savedErrno) {
    errno=0; int fd=open(path,access|O_NOFOLLOW|O_CLOEXEC); *savedErrno=errno;
    if (fd<0) return -1;
    if (close(fd)) { *savedErrno=errno; return -2; }
    return 0;
}

static Observation Observe(CheckFunction check, pid_t pid, const char *phase) {
    Observation o={0};
    const char *operations[4]={"file-read-metadata","file-read-data","file-read-data","file-write-data"};
    const char *paths[4]={"/usr","/dev/null",PROBE_WITNESS,PROBE_WITNESS};
    for (unsigned i=0;i<4;++i) {
        errno=0; o.check[i]=check(pid,operations[i],1,paths[i]); o.checkErrno[i]=errno;
        printf("CHECK phase=%s operation=%s path=%s result=%d errno=%d\n",phase,operations[i],paths[i],o.check[i],o.checkErrno[i]);
    }
    struct stat s;
    errno=0; o.metadata=stat("/usr",&s); o.metadataErrno=errno;
    if (o.metadata==0 && !S_ISDIR(s.st_mode)) o.metadata=-2;
    errno=0; int fd=open("/dev/null",O_RDONLY|O_NOFOLLOW|O_CLOEXEC); o.nullErrno=errno; o.nullOpen=fd<0?-1:0;
    o.nullRead=-2;
    if (fd>=0) { unsigned char byte; errno=0; o.nullRead=(int)read(fd,&byte,1); o.nullReadErrno=errno; if (close(fd)) o.nullOpen=-2; }
    o.readOpen=FreshOpen(PROBE_WITNESS,O_RDONLY,&o.readErrno);
    o.writeOpen=FreshOpen(PROBE_WITNESS,O_WRONLY,&o.writeErrno);
    printf("FILES phase=%s usrStat=%d usrErrno=%d nullOpen=%d nullErrno=%d nullRead=%d nullReadErrno=%d denyRead=%d denyReadErrno=%d denyWrite=%d denyWriteErrno=%d\n",
        phase,o.metadata,o.metadataErrno,o.nullOpen,o.nullErrno,o.nullRead,o.nullReadErrno,o.readOpen,o.readErrno,o.writeOpen,o.writeErrno);
    return o;
}

static bool Baseline(const Observation *o) {
    return o->metadata==0 && o->nullOpen==0 && o->nullRead==0 && o->readOpen==0 && o->writeOpen==0 &&
        o->check[0]==0 && o->check[1]==0 && o->check[2]==0 && o->check[3]==0;
}
static bool Denied(int result,int err) { return result==-1 && (err==EPERM || err==EACCES); }
static bool LocalOracle(const Observation *o) {
    return o->metadata==0 && o->nullOpen==0 && o->nullRead==0 && o->check[0]==0 && o->check[1]==0 &&
        o->check[2]>0 && o->check[3]>0 && Denied(o->readOpen,o->readErrno) && Denied(o->writeOpen,o->writeErrno);
}

int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0); setvbuf(stderr,NULL,_IONBF,0);
    if (argc!=2 || strcmp(argv[1],"--self-apply-once-compiled27-v1")) return 64;
    if (getuid()!=501 || geteuid()!=501 || getpid()<=1 || getppid()<=1) return 65;
    struct rlimit cpu={5,5},core={0,0},observed;
    if (setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core) ||
        getrlimit(RLIMIT_CPU,&observed) || observed.rlim_cur!=5 || observed.rlim_max!=5 ||
        getrlimit(RLIMIT_CORE,&observed) || observed.rlim_cur || observed.rlim_max) return 66;
    printf("IDENTITY pid=%d ppid=%d uid=%u euid=%u cpuLimit=5 coreLimit=0 applyCount=0\n",getpid(),getppid(),getuid(),geteuid());
    if (!ActualExecutable()) return 67;
    int directory=PinnedDirectory(); if (directory<0) return 68;
    unsigned char *blob=malloc(BLOB_SIZE); unsigned char witness[29];
    if (!blob || !ReadPinnedAt(directory,"compiled-profile.bin",BLOB_SIZE,BLOB_SHA,blob) ||
        !ReadPinnedAt(directory,"deny-witness.txt",sizeof(witness),WITNESS_SHA,witness)) { free(blob); close(directory); return 69; }
    if (close(directory)) { free(blob); return 69; }
    void *applyHandle=NULL,*checkHandle=NULL;
    void *applySymbol=Native(&applyHandle,"/usr/lib/libsandbox.1.dylib","sandbox_apply",
        "41a96a45b5c23f928f64816ba6daa693",0x2590,0x24fc,156,"ffa55cebf510dc908c8cf12d27deb8e891e15d7216d061a57a6b152eb1c67cd2");
    void *checkSymbol=Native(&checkHandle,"/usr/lib/system/libsystem_sandbox.dylib","sandbox_check",
        "140cc26b91e932f4ad75096c4e104eb0",0x19b4,0x19b4,112,"1cecf5e729b300f2cbf283a37a452c4de7c82590748ccac7df157cb768281340");
    if (!applySymbol || !checkSymbol) { free(blob); return 70; }
    VM27NativeSandboxApplyFunctionV1 apply=(VM27NativeSandboxApplyFunctionV1)applySymbol;
    CheckFunction check=(CheckFunction)checkSymbol;
    Observation before=Observe(check,getpid(),"before");
    if (!Baseline(&before) || !Digest(blob,BLOB_SIZE,BLOB_SHA)) { free(blob); return 71; }
    VM27NativeSandboxApplyProfilePrefixV1 diagnosticOnly={NULL,blob,BLOB_SIZE};
    printf("APPLY_BEGIN count=1 builtinNULL=1 blobBytes=%u blobSHA=%s productionOpaqueObject=0\n",BLOB_SIZE,BLOB_SHA);
    errno=0; int result=apply(&diagnosticOnly); int applyErrno=errno;
    printf("APPLY_RESULT count=1 return=%d errno=%d\n",result,applyErrno);
    if (result!=0) { free(blob); printf("COMPAT_RESULT nativeAccepted=0 localWitnessPassed=0 fullPolicyEquivalent=0 fullVM=0\n"); return 72; }
    Observation after=Observe(check,getpid(),"after");
    bool passed=LocalOracle(&after); free(blob);
    printf("COMPAT_RESULT nativeAccepted=1 localWitnessPassed=%d fullPolicyEquivalent=0 fullVM=0\n",passed?1:0);
    return passed?0:73;
}
