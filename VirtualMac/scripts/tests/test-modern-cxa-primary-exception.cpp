// Real native allocation/init/refcount/rethrow/factory/destruction oracle.
// No Hypervisor, VM, GPU, disk workload, injection or system modification.
#include <CommonCrypto/CommonDigest.h>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <dlfcn.h>
#include <exception>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <new>
#include <ptrauth.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unwind.h>
#include "modern_cxa_primary_exception_compat.h"
#include "cxa-provider-pins.h"
extern void *Initialize(void*,std::type_info*,void(*)(void*)) noexcept
    __asm("___cxa_init_primary_exception");
extern std::exception_ptr Factory(void*) noexcept
    __asm("__ZNSt13exception_ptr31__from_native_exception_pointerEPv");
using Cleanup=void(*)(_Unwind_Reason_Code,_Unwind_Exception*);
static std::atomic<unsigned> Checks{0},Failures{0},Created{0},Destroyed{0},
    FailedConstructions{0},InvalidDestructors{0},Rethrows{0},CleanupCalls{0};
static void Check(bool ok,const char *name) {
    unsigned n=Checks.fetch_add(1)+1;
    if(!ok) Failures.fetch_add(1);
    std::printf("{\"record\":\"check\",\"id\":%u,\"name\":\"%s\",\"passed\":%s}\n",
        n,name,ok?"true":"false");
    if(!ok) std::fflush(stdout);
}
static void Need(bool ok,const char *name) {Check(ok,name);if(!ok) _exit(1);}
static bool File(const char *path,const char *expected,size_t bytes) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;
    struct stat a={},b={};
    bool ok=!fstat(fd,&a)&&S_ISREG(a.st_mode)&&a.st_nlink==1&&
        a.st_uid==getuid()&&!(a.st_mode&0022)&&size_t(a.st_size)==bytes;
    CC_SHA256_CTX sha;unsigned char block[4096],digest[32];size_t count=0;
    ok=ok&&CC_SHA256_Init(&sha);
    while(ok) {
        ssize_t n=read(fd,block,sizeof(block));if(n<0&&errno==EINTR)continue;
        if(n<0){ok=false;break;}if(!n)break;
        if(size_t(n)>bytes-count){ok=false;break;}
        count+=size_t(n);ok=CC_SHA256_Update(&sha,block,CC_LONG(n));
    }
    ok=ok&&count==bytes&&!fstat(fd,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&
        a.st_size==b.st_size&&a.st_mode==b.st_mode&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&
        a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&
        a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
    if(close(fd))ok=false;char hex[65]={};
    if(ok){ok=CC_SHA256_Final(digest,&sha);for(unsigned i=0;i<32;++i)std::snprintf(hex+2*i,3,"%02x",digest[i]);}
    std::printf("{\"record\":\"file\",\"path\":\"%s\",\"SHA256\":\"%s\",\"bytes\":%zu,\"exact\":%s}\n",path,hex,count,ok&&!std::strcmp(hex,expected)?"true":"false");
    return ok&&!std::strcmp(hex,expected);
}
static bool UUID(const void *base,const unsigned char *expected) {
    const auto *header=static_cast<const mach_header_64*>(base);
    if(!header||header->magic!=MH_MAGIC_64||header->filetype!=MH_DYLIB||
        header->ncmds>128||header->sizeofcmds>16384)return false;
    auto *commands=reinterpret_cast<const unsigned char*>(header+1);unsigned at=0,found=0;bool ok=false;
    for(unsigned i=0;i<header->ncmds;++i){
        if(at>header->sizeofcmds||header->sizeofcmds-at<8)return false;
        load_command c;std::memcpy(&c,commands+at,8);
        if(c.cmdsize<8||c.cmdsize&7||c.cmdsize>header->sizeofcmds-at)return false;
        if(c.cmd==LC_UUID){if(c.cmdsize!=24)return false;++found;ok=!std::memcmp(commands+at+8,expected,16);}
        at+=c.cmdsize;
    }return found==1&&ok&&at==header->sizeofcmds;
}
static void Identity(bool before) {
    for(const auto& file:PrivateFiles) Need(File(file.path,file.sha256,file.bytes),before?"private file before":"private file after");
    void *raw=ptrauth_strip(reinterpret_cast<void*>(&Initialize),ptrauth_key_function_pointer);Dl_info d={};
    Need(dladdr(raw,&d)&&d.dli_fname&&d.dli_fbase,"strong init dladdr");
    struct stat a={},b={};Need(!stat(d.dli_fname,&a)&&!stat(PrivateFiles[0].path,&b)&&
        a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&UUID(d.dli_fbase,ProviderUUID),"same exact mapped provider UUID/inode");
    Need(reinterpret_cast<uintptr_t>(raw)-reinterpret_cast<uintptr_t>(d.dli_fbase)==ProviderInitRVA,"strong init RVA");
    std::printf("{\"record\":\"provider\",\"phase\":\"%s\",\"UUID\":\"%s\",\"RVA\":%llu,\"strongImport\":true}\n",
        before?"before":"after",ProviderUUIDString,(unsigned long long)ProviderInitRVA);
    unsigned forbidden=0;for(unsigned i=0;i<_dyld_image_count();++i){
        const char *name=_dyld_get_image_name(i);if(!name)continue;
        if(std::strstr(name,"Virtualization.framework")||std::strstr(name,"Hypervisor.framework")||
            std::strstr(name,"VirtualMachine.framework")||std::strstr(name,"ParavirtualizedGraphics.framework"))++forbidden;
    }
    Need(!forbidden,"no VM/HV/VMM/PVG images");
}
static uint64_t Ref(void *object){uint64_t n=0;std::memcpy(&n,static_cast<unsigned char*>(object)-120,8);return n;}
struct alignas(16) Payload final {
    uint64_t magic=0x817c0ffee;
    int value;
    explicit Payload(int x):value(x){Created.fetch_add(1);}
    ~Payload()noexcept{Need(magic==0x817c0ffee,"real destructor intact payload");Destroyed.fetch_add(1);}
};
static void Destroy(void *object){static_cast<Payload*>(object)->~Payload();}
static void* Make(int value) {
    void *object=__cxxabiv1::__cxa_allocate_exception(sizeof(Payload));
    Need(object&&!(reinterpret_cast<uintptr_t>(object)&15),"genuine native allocation alignment");
    int uncaught=std::uncaught_exceptions();
    void *header=Initialize(object,const_cast<std::type_info*>(&typeid(Payload)),Destroy);
    Need(header==static_cast<unsigned char*>(object)-128&&Ref(object)==0,"init returns real header with zero references");
    Need(std::uncaught_exceptions()==uncaught,"init does not begin unwinding");
    new(object) Payload(value);return object;
}
static void Rethrow(void *object,int value) {
    bool caught=false;
    try{__cxxabiv1::__cxa_rethrow_primary_exception(object);}
    catch(const Payload& p){
        caught=true;Need(&p==object&&p.value==value,"native rethrow same primary pointer/RTTI/data");
        void *retained=__cxxabiv1::__cxa_current_primary_exception();
        Need(retained==object,"native current_primary real retained identity");
        __cxxabiv1::__cxa_decrement_exception_refcount(retained);
        Rethrows.fetch_add(1);
    }catch(...){Need(false,"wrong rethrow type");}
    Need(caught,"native dependent exception reached catch");
}
static void HeaderPreservation() {
    void *object=__cxxabiv1::__cxa_allocate_exception(16);auto *header=static_cast<unsigned char*>(object)-128;
    for(unsigned i=0;i<128;++i)header[i]=static_cast<unsigned char>(i*17+3);
    unsigned char before[128];std::memcpy(before,header,128);
    int uncaught=std::uncaught_exceptions();
    Need(Initialize(object,const_cast<std::type_info*>(&typeid(Payload)),Destroy)==header,"opaque header return contract");
    for(unsigned i=0;i<128;++i){bool changed=(i>=8&&i<48)||(i>=96&&i<112);
        if(!changed)Need(header[i]==before[i],"initializer preserves non-init header fields");}
    Need(Ref(object)==0&&std::uncaught_exceptions()==uncaught,"reset references with no unwind side effects");
    uint64_t cls=0;std::memcpy(&cls,header+96,8);Need(cls==0x434c4e47432b2b00ull,"exact genuine primary exception class");
    __cxxabiv1::__cxa_free_exception(object);Need(!Created.load()&&!Destroyed.load(),"unconstructed allocation freed without destructor");
}
static void NativeOwnership() {
    unsigned before=Destroyed.load();void *object=Make(817);
    __cxxabiv1::__cxa_increment_exception_refcount(object);Need(Ref(object)==1,"native retain 0 to 1");
    __cxxabiv1::__cxa_increment_exception_refcount(object);Need(Ref(object)==2,"native retain 1 to 2");
    __cxxabiv1::__cxa_decrement_exception_refcount(object);Need(Ref(object)==1&&Destroyed.load()==before,"native release preserves surviving owner");
    Rethrow(object,817);Need(Ref(object)==1&&Destroyed.load()==before,"dependent rethrow restores reference ownership");
    __cxxabiv1::__cxa_decrement_exception_refcount(object);Need(Destroyed.load()==before+1,"final native release invokes one destructor");
}
static void FactoryOwnership(int value) {
    void *object=Make(value);auto retained=Factory(object);Need(bool(retained)&&Ref(object)==1,"genuine factory retains initialized primary");
    auto copy=retained;Need(Ref(object)==2,"native exception_ptr copy retains");retained=nullptr;
    Need(Ref(object)==1,"native exception_ptr first owner release");
    bool caught=false;try{std::rethrow_exception(copy);}catch(const Payload& p){
        caught=true;Need(&p==object&&p.value==value,"std::rethrow_exception retains exact initialized object");Rethrows.fetch_add(1);
    }catch(...){Need(false,"wrong factory exception type");}
    Need(caught&&Ref(object)==1,"factory rethrow preserves last reference");copy=nullptr;
}
static void CleanupOwnership() {
    unsigned before=Destroyed.load();void *object=Make(222);
    __cxxabiv1::__cxa_increment_exception_refcount(object);__cxxabiv1::__cxa_increment_exception_refcount(object);
    auto *unwind=reinterpret_cast<_Unwind_Exception*>(static_cast<unsigned char*>(object)-32);
    auto cleanup=unwind->exception_cleanup;
    Need(reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(cleanup),ptrauth_key_function_pointer))==
        VM27PrimaryExceptionNativeCleanupAddress(),"exact code-pinned genuine cleanup pointer");
    cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT,unwind);CleanupCalls.fetch_add(1);
    Need(Ref(object)==1&&Destroyed.load()==before,"native unwind cleanup preserves dependent surviving reference");
    __cxxabiv1::__cxa_decrement_exception_refcount(object);Need(Destroyed.load()==before+1,"cleanup owner final release destroys exactly once");
    object=Make(223);unwind=reinterpret_cast<_Unwind_Exception*>(static_cast<unsigned char*>(object)-32);
    __cxxabiv1::__cxa_increment_exception_refcount(object);
    unwind->exception_cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT,unwind);CleanupCalls.fetch_add(1);
    Need(Destroyed.load()==before+2,"last unwind cleanup destroys exactly once");
}
struct ConstructionFailure {int value;};
struct Failable {
    Failable(){FailedConstructions.fetch_add(1);throw ConstructionFailure{817};}
    ~Failable()noexcept{InvalidDestructors.fetch_add(1);}
};
static void DestroyFailable(void *object){static_cast<Failable*>(object)->~Failable();}
static void ConstructionNegative() {
    void *object=__cxxabiv1::__cxa_allocate_exception(sizeof(Failable));
    Initialize(object,const_cast<std::type_info*>(&typeid(Failable)),DestroyFailable);
    bool caught=false;try{new(object) Failable;}catch(const ConstructionFailure& failure){
        caught=true;Need(failure.value==817,"real constructor failure is caught");
        void *primary=__cxxabiv1::__cxa_current_primary_exception();
        Need(primary&&primary!=object,"constructor failure has distinct genuine primary");
        __cxxabiv1::__cxa_decrement_exception_refcount(primary);
    }catch(...){Need(false,"wrong constructor failure type");}
    Need(caught&&!InvalidDestructors.load()&&Ref(object)==0,"failed constructor owns no primary reference or destructor");
    __cxxabiv1::__cxa_free_exception(object);
    Need(!InvalidDestructors.load(),"free after failed construction does not invoke invalid destructor");
}
static void *Worker(void *value){for(unsigned i=0;i<16;++i)FactoryOwnership(int(reinterpret_cast<uintptr_t>(value)*100+i));return nullptr;}
static void SavedTerminate(){std::puts("{\"record\":\"saved-terminate\",\"expectedExit\":79,\"passed\":true}");std::fflush(stdout);_exit(79);}
static void WrongTerminate(){_exit(80);}
int main(int argc,char **argv) {
    setbuf(stdout,nullptr);std::printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"VMCalls\":0,\"GPUCalls\":0}\n",getpid(),getuid());
    rlimit cpu={4,4},core={0,0};Need(!setrlimit(RLIMIT_CPU,&cpu)&&!setrlimit(RLIMIT_CORE,&core),"bounded CPU/core");alarm(10);
    Need(argc==3||argc==4,"signed self hash and exact mode");
#if defined(VM27_PRIMARY_EXCEPTION_IOS)
    Need(getuid()==0&&geteuid()==0,"private Root diagnostic");
#endif
    char self[4096];uint32_t bytes=sizeof(self);Need(!_NSGetExecutablePath(self,&bytes),"actual self path");
    char *canonical=realpath(self,nullptr);Need(canonical!=nullptr,"canonical self");
    Need(File(canonical,argv[1],std::strtoull(argv[2],nullptr,10)),"signed self exact bytes");std::free(canonical);
    Identity(true);Need(VM27PrimaryExceptionNativeABIStatus()==1,"all genuine system UUID/RVA/function/cleanup code pins");
    if(argc==4){
        Need(!std::strcmp(argv[3],"--terminate-control"),"explicit terminate control only");
        std::set_terminate(SavedTerminate);void *object=Make(79);std::set_terminate(WrongTerminate);
        __cxxabiv1::__cxa_increment_exception_refcount(object);
        auto *unwind=reinterpret_cast<_Unwind_Exception*>(static_cast<unsigned char*>(object)-32);
        std::puts("{\"record\":\"terminate-control\",\"expectedSavedHandlerExit\":79,\"wrongCurrentHandlerExit\":80}");
        unwind->exception_cleanup(_URC_FATAL_PHASE2_ERROR,unwind);_exit(81);
    }
    HeaderPreservation();NativeOwnership();FactoryOwnership(818);CleanupOwnership();ConstructionNegative();
    unsigned live=Created.load()-Destroyed.load();Need(!live,"serial cases all payload lifetimes closed");
    pthread_t workers[4];for(unsigned i=0;i<4;++i)Need(!pthread_create(&workers[i],nullptr,Worker,reinterpret_cast<void*>(uintptr_t(i+1))),"create bounded real exception worker");
    for(auto& thread:workers)Need(!pthread_join(thread,nullptr),"join real exception worker");
    Need(Created.load()==Destroyed.load()&&!InvalidDestructors.load(),"all concurrent real exception objects destroyed once");
    Need(FailedConstructions.load()==1&&CleanupCalls.load()==2&&Rethrows.load()==66,"exact real positive and construction-negative workload");
    Need(VM27PrimaryExceptionInitializeCalls()==70,"all 70 initializer calls reached actual candidate");
    Identity(false);alarm(0);
    std::printf("{\"record\":\"summary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"initialized\":%llu,\"created\":%u,\"destroyed\":%u,\"rethrows\":%u,\"nativeCleanupCalls\":%u,\"failedConstructions\":%u,\"invalidDestructors\":%u,\"workers\":4,\"VMCalls\":0,\"GPUCalls\":0,\"full27Backend\":false}\n",getpid(),Checks.load(),Failures.load(),(unsigned long long)VM27PrimaryExceptionInitializeCalls(),Created.load(),Destroyed.load(),Rethrows.load(),CleanupCalls.load(),FailedConstructions.load(),InvalidDestructors.load());
    return Failures.load()?1:0;
}
