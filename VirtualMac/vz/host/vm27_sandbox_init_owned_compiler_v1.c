#include "vm27_sandbox_init_owned_compiler_v1.h"
#include "vm27_actual_executable_image_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if TARGET_OS_OSX
#include <mach/mach_vm.h>
#else
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t,mach_vm_address_t,
    mach_vm_size_t,mach_vm_address_t,mach_vm_size_t *);
#endif
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#if defined(VM27_SANDBOX_OWNED_ADAPTER_TESTING) && TARGET_OS_IPHONE
#error "Mock adapter hooks are forbidden in iOS products"
#endif

#define FLAT "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat"
#define CHILD FLAT "/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents"
#define RESOURCES CHILD "/Resources"
#define ORIGINAL_PROFILE RESOURCES "/com.apple.Virtualization.VirtualMachine.sb"
#define IMPORTS RESOURCES "/SandboxProfiles27"
#define COMPILER FLAT "/VM27GenuineSandboxCompiler27.dylib"
#define ORIGINAL_EXECUTABLE CHILD "/MacOS/com.apple.Virtualization.VirtualMachine"
#define COMPILED_BYTES 13696U
#define COMPILED_SHA "2b7ad4d1be09203d49af1dafa560dfdb9b3ddcd5953c7ee061713a5fb34e898b"

typedef void *(*CreateParams)(void);
typedef int (*SetParam)(void *,const char *,const char *);
typedef void *(*CompileFile)(const char *,void *,char **);
typedef void (*FreeOpaque)(void *);
typedef int (*NativeApply)(const void *);
typedef int (*NativeInit)(const char *,uint64_t,const char *const[],char **);
typedef struct {
    CreateParams create;
    SetParam set;
    CompileFile compile;
    FreeOpaque freeParams,freeProfile;
    NativeApply apply;
} Operations;
static atomic_flag ownedAttempt=ATOMIC_FLAG_INIT;

static bool SHA(const void *bytes,size_t count,const char *expected) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; char hex[65];
    if (count>UINT32_MAX) return false;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (!CC_SHA256(bytes,(CC_LONG)count,hash)) return false;
#pragma clang diagnostic pop
    for (size_t i=0;i<sizeof(hash);++i) snprintf(hex+i*2,3,"%02x",hash[i]);
    return strcmp(hex,expected)==0;
}
static bool CopySelf(uintptr_t source,void *out,size_t size) {
    mach_vm_size_t copied=0;
    return source && size && source<=UINTPTR_MAX-size &&
        mach_vm_read_overwrite(mach_task_self(),source,size,(mach_vm_address_t)(uintptr_t)out,&copied)==KERN_SUCCESS && copied==size;
}
static void Error(char **out,int err,const char *stage) {
    if (out && !*out) {
        char *message=NULL;
        if (asprintf(&message,"Owned sandbox %s failed (%d): %s",stage,err,strerror(err))>=0) *out=message;
    }
    errno=err;
}
static void CalleeFailure(char **out,int result,int rawErrno,const char *stage) {
    if (out && !*out) {
        char *message=NULL;
        if (asprintf(&message,"Owned sandbox %s returned %d (errno=%d)",stage,result,rawErrno)>=0) *out=message;
    }
    errno=rawErrno;
}

#if !defined(VM27_SANDBOX_OWNED_ADAPTER_TESTING)
static bool UUID(uintptr_t base,const char *expected) {
    struct mach_header_64 header; char text[33]={0};
    if (!CopySelf(base,&header,sizeof(header)) || header.magic!=MH_MAGIC_64 ||
        header.ncmds>1024 || !header.sizeofcmds || header.sizeofcmds>65536) return false;
    unsigned char *commands=malloc(header.sizeofcmds);
    if (!commands) return false;
    bool ok=CopySelf(base+sizeof(header),commands,header.sizeofcmds);
    size_t offset=0;unsigned matches=0;
    for (uint32_t i=0;ok && i<header.ncmds;++i) {
        struct load_command c;
        if (offset>header.sizeofcmds || header.sizeofcmds-offset<sizeof(c)) { ok=false;break; }
        memcpy(&c,commands+offset,sizeof(c));
        if (c.cmdsize<sizeof(c) || c.cmdsize%8 || c.cmdsize>header.sizeofcmds-offset) { ok=false;break; }
        if (c.cmd==LC_UUID) {
            struct uuid_command u;
            if (c.cmdsize!=sizeof(u)) { ok=false;break; }
            memcpy(&u,commands+offset,sizeof(u));++matches;
            for (size_t j=0;j<sizeof(u.uuid);++j) snprintf(text+j*2,3,"%02x",u.uuid[j]);
        }
        offset+=c.cmdsize;
    }
    free(commands);
    return ok && offset==header.sizeofcmds && matches==1 && strcmp(text,expected)==0;
}
static void *Symbol(void *handle,const char *path,const char *uuid,const char *name,
                    uintptr_t rva,uintptr_t codeRVA,size_t size,const char *codeSHA) {
    void *symbol=dlsym(handle,name),*address=symbol; Dl_info info={0};
#if __has_feature(ptrauth_calls)
    address=ptrauth_strip(symbol,ptrauth_key_function_pointer);
#endif
    if (!symbol || !dladdr(address,&info) || !info.dli_fname || strcmp(path,info.dli_fname) ||
        !info.dli_fbase || (uintptr_t)address!=(uintptr_t)info.dli_fbase+rva ||
        !UUID((uintptr_t)info.dli_fbase,uuid) || size>1024) return NULL;
    unsigned char code[1024];
    if (!CopySelf((uintptr_t)info.dli_fbase+codeRVA,code,size) || !SHA(code,size,codeSHA)) return NULL;
    return symbol;
}
static NativeInit OriginalInit(void) {
    const char *path="/usr/lib/system/libsystem_sandbox.dylib";
    void *handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if (!handle) return NULL;
    return (NativeInit)Symbol(handle,path,"140cc26b91e932f4ad75096c4e104eb0","sandbox_init_with_parameters",
        0x227c,0x227c,828,"2a809360277cfcc4769862d9cded3e20a5caf6d65486e4fd09d455f0ee8822e2");
}
static bool Resolve(Operations *ops) {
    memset(ops,0,sizeof(*ops));
    void *compiler=dlopen(COMPILER,RTLD_NOW|RTLD_LOCAL);
    void *native=dlopen("/usr/lib/libsandbox.1.dylib",RTLD_NOW|RTLD_LOCAL);
    if (!compiler || !native) return false;
    const char *uuid="648b6ec9b80a3673ac47f6f7806bb158";
    ops->create=(CreateParams)Symbol(compiler,COMPILER,uuid,"sandbox_create_params",0x848,0x848,16,
        "38bcb13f72f538f64686dd080e835e7dfab4c04de7543c2757b61bfd06282b87");
    ops->set=(SetParam)Symbol(compiler,COMPILER,uuid,"sandbox_set_param",0x8c4,0x8c4,16,
        "5866c207ee5c34b37a3f5b878b27d826b84ef8d25ad0ae8151c87e49c4f45d33");
    ops->compile=(CompileFile)Symbol(compiler,COMPILER,uuid,"sandbox_compile_file",0xa88,0xa88,16,
        "c4e11376bc9c0584d29f248a5ab0fc96bd80ee0b1ae8302d7afc9af697e65c91");
    ops->freeProfile=(FreeOpaque)Symbol(compiler,COMPILER,uuid,"sandbox_free_profile",0x1f0dc,0x1f0dc,16,
        "f0e47579ecf6bf9e741b661f6412a8a5f8e3166872b0c3e62261d6d4a7fb9fdd");
    ops->freeParams=(FreeOpaque)Symbol(compiler,COMPILER,uuid,"sandbox_free_params",0x1f128,0x1f128,16,
        "6ce717956e0f4cdfe1c9d558bf98ee4df63d1e3b3a239d50c7232c2aa843edd8");
    ops->apply=(NativeApply)Symbol(native,"/usr/lib/libsandbox.1.dylib","41a96a45b5c23f928f64816ba6daa693",
        "sandbox_apply",0x2590,0x24fc,156,"ffa55cebf510dc908c8cf12d27deb8e891e15d7216d061a57a6b152eb1c67cd2");
    return ops->create && ops->set && ops->compile && ops->freeProfile && ops->freeParams && ops->apply;
}
static bool Role(void) {
    VM27ActualExecutableImageV1 image;
    const uint8_t uuid[16]={0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};
    return getuid()==501 && geteuid()==501 && getpid()>1 &&
        VM27ActualExecutableImageFindV1(ORIGINAL_EXECUTABLE,&image)==0 && !memcmp(image.uuid,uuid,sizeof(uuid));
}
static bool Same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode &&
        a->st_uid==b->st_uid && a->st_size==b->st_size && a->st_nlink==b->st_nlink &&
        a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static bool Resource(const char *path,size_t count,const char *sha) {
    char resolved[PATH_MAX];struct stat a,b,p;
    if (!realpath(path,resolved) || strcmp(path,resolved)) return false;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return false;
    bool ok=fstat(fd,&a)==0 && S_ISREG(a.st_mode) && a.st_uid==501 &&
        (a.st_mode&07777)==0600 && a.st_nlink==1 && a.st_size==(off_t)count;
    unsigned char *bytes=ok?malloc(count):NULL;
    if (!bytes) ok=false;
    size_t done=0;
    while (ok && done<count) {
        ssize_t n=read(fd,bytes+done,count-done);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { ok=false;break; }
        done+=(size_t)n;
    }
    ok=ok && fstat(fd,&b)==0 && lstat(path,&p)==0 && Same(&a,&b) && Same(&a,&p) && SHA(bytes,count,sha);
    free(bytes);int rc=close(fd);return ok && rc==0;
}
static bool Resources(void) {
    return Resource(ORIGINAL_PROFILE,32301,"59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504") &&
        Resource(IMPORTS "/system.sb",12041,"180a0356611b5de7a7db84b800ed47a1d2f15ec884d0fb960445366ededac7c8") &&
        Resource(IMPORTS "/dyld-support.sb",3152,"bdfc2354c683c8fb95a39e63fbc8610e9739b0256c89ab880564edefbe73a5ce");
}
#else
/* Defined only by the HOST fixture; compilation for iOS is forbidden above. */
static bool Resolve(Operations *);
static NativeInit OriginalInit(void);
static bool Role(void);
static bool Resources(void);
#endif

static bool GenuineProfile(void *opaque) {
    struct { const char *builtin;const unsigned char *data;uint64_t size; } prefix;
    if (!opaque || !CopySelf((uintptr_t)opaque,&prefix,sizeof(prefix)) || prefix.builtin ||
        !prefix.data || prefix.size!=COMPILED_BYTES) return false;
    unsigned char *bytes=malloc(COMPILED_BYTES);
    if (!bytes) return false;
    bool ok=CopySelf((uintptr_t)prefix.data,bytes,COMPILED_BYTES) && SHA(bytes,COMPILED_BYTES,COMPILED_SHA);
    free(bytes);return ok;
}

int VM27SandboxInitWithOwnedCompilerV1(const char *profile,uint64_t flags,
    const char *const parameters[],char **errorbuf) {
    char *localError=NULL;char **out=errorbuf?errorbuf:&localError;*out=NULL;
    if (flags!=3) {
        NativeInit original=OriginalInit();
        if (!original) { Error(out,ENOTSUP,"native identity");free(localError);return -1; }
        int rc=original(profile,flags,parameters,out),saved=errno;
        free(localError);errno=saved;return rc;
    }
    if (!profile || strcmp(profile,ORIGINAL_PROFILE) || parameters) {
        Error(out,ENOTSUP,"flags3 scope");free(localError);return -1;
    }
    if (atomic_flag_test_and_set_explicit(&ownedAttempt,memory_order_acq_rel)) {
        Error(out,EALREADY,"once gate");free(localError);return -1;
    }
    int rc=-1,saved=EACCES;void *params=NULL,*actualProfile=NULL;Operations ops;
    if (!Role() || !Resources()) { Error(out,saved,"role or resource identity");goto done; }
    if (!Resolve(&ops)) { saved=ENOTSUP;Error(out,saved,"compiler/native identity");goto done; }
    errno=0;params=ops.create();saved=errno;
    if (!params) { CalleeFailure(out,0,saved,"create params NULL");goto cleanup; }
    errno=0;int paramResult=ops.set(params,"IMPORT_DIR",IMPORTS);saved=errno;
    if (paramResult) { CalleeFailure(out,paramResult,saved,"IMPORT_DIR");goto cleanup; }
    errno=0;actualProfile=ops.compile(profile,params,out);saved=errno;
    dprintf(STDERR_FILENO,"VM27 sandbox compile returnedObject=%d errno=%d actualError=%d\n",actualProfile!=NULL,saved,*out!=NULL);
    if (!actualProfile) { CalleeFailure(out,0,saved,"compile_file NULL");goto cleanup; }
    if (*out || !GenuineProfile(actualProfile) || !Resources()) { saved=EINVAL;Error(out,saved,"produced profile identity");goto cleanup; }
    /* Preserve the producer's actual opaque pointer. Never fabricate a 24B
     * replacement, replay stored bytecode, or call Mac apply/notify here. */
    errno=0;rc=ops.apply(actualProfile);saved=errno;
    if (rc!=0) CalleeFailure(out,rc,saved,"native apply");
    dprintf(STDERR_FILENO,"VM27 sandbox native apply return=%d errno=%d realOpaque=1\n",rc,saved);
cleanup:
    if (actualProfile) ops.freeProfile(actualProfile);
    if (params) ops.freeParams(params);
done:
    free(localError);errno=saved;return rc;
}
