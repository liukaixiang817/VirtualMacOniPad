// Real strong-import semantics and exact loaded identity, no HV/GPU work.
#include <CommonCrypto/CommonDigest.h>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <malloc/malloc.h>
#include <new>
#include <ptrauth.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vmm-cxx-closure-pins.h"

using Result = std::to_chars_result;
using Format = std::chars_format;
extern Result FloatPlain(char*,char*,float) __asm("__ZNSt3__18to_charsEPcS0_f");
extern Result FloatFormat(char*,char*,float,Format) __asm("__ZNSt3__18to_charsEPcS0_fNS_12chars_formatE");
extern Result FloatPrecision(char*,char*,float,Format,int) __asm("__ZNSt3__18to_charsEPcS0_fNS_12chars_formatEi");
extern Result DoublePlain(char*,char*,double) __asm("__ZNSt3__18to_charsEPcS0_d");
extern Result DoubleFormat(char*,char*,double,Format) __asm("__ZNSt3__18to_charsEPcS0_dNS_12chars_formatE");
extern Result DoublePrecision(char*,char*,double,Format,int) __asm("__ZNSt3__18to_charsEPcS0_dNS_12chars_formatEi");
extern Result LongPlain(char*,char*,long double) __asm("__ZNSt3__18to_charsEPcS0_e");
extern Result LongFormat(char*,char*,long double,Format) __asm("__ZNSt3__18to_charsEPcS0_eNS_12chars_formatE");
extern Result LongPrecision(char*,char*,long double,Format,int) __asm("__ZNSt3__18to_charsEPcS0_eNS_12chars_formatEi");
extern void *TypedNew(size_t,uint64_t) __asm("__ZnwmSt19__type_descriptor_t");
extern void *TypedNewArray(size_t,uint64_t) __asm("__ZnamSt19__type_descriptor_t");
extern void TypedDelete(void*,uint64_t) noexcept __asm("__ZdlPvSt19__type_descriptor_t");
extern void TypedDeleteArray(void*,uint64_t) noexcept __asm("__ZdaPvSt19__type_descriptor_t");
static_assert(sizeof(long double)==8 && sizeof(void*)==8,
    "Audited Darwin arm64 long-double and pointer ABI");

static unsigned Checks, Failures, Calls[13], Created, Released;
static const char *Case = "identity";
static void Check(bool passed, const char *name) {
    ++Checks; if (!passed) ++Failures;
    std::printf("{\"record\":\"check\",\"id\":%u,\"case\":\"%s\",\"name\":\"%s\",\"passed\":%s}\n",
        Checks,Case,name,passed?"true":"false");
}

static struct stat FirstStat;
static bool SameStat(const struct stat& a,const struct stat& b) {
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size &&
        a.st_uid==b.st_uid && a.st_gid==b.st_gid && a.st_mode==b.st_mode &&
        a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec &&
        a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec &&
        a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
}
static bool FileIdentity(bool first) {
    int fd=open(PinPath,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0) return false;
    struct stat before={},after={};
    bool pass=fstat(fd,&before)==0 && S_ISREG(before.st_mode) && before.st_nlink==1 &&
        before.st_uid==geteuid() && !(before.st_mode&0022) && before.st_size==(off_t)PinBytes;
    CC_SHA256_CTX sha; unsigned char block[4096],digest[32];size_t total=0;
    pass=pass && CC_SHA256_Init(&sha);
    while(pass) {
        ssize_t n=read(fd,block,sizeof(block));
        if(n<0 && errno==EINTR) continue;
        if(n<0) {pass=false;break;} if(!n) break;
        if(total>PinBytes || size_t(n)>PinBytes-total) {pass=false;break;}
        total+=size_t(n);pass=CC_SHA256_Update(&sha,block,CC_LONG(n));
    }
    pass=pass && total==PinBytes && fstat(fd,&after)==0 && SameStat(before,after);
    if(close(fd)) pass=false;
    char hex[65]={};
    if(pass) {
        pass=CC_SHA256_Final(digest,&sha);
        for(unsigned i=0;i<32;++i) std::snprintf(hex+2*i,3,"%02x",digest[i]);
        pass=pass && !std::strcmp(hex,PinSHA);
    }
    if(first && pass) FirstStat=before;
    if(!first) pass=pass && SameStat(FirstStat,before);
    std::printf("{\"record\":\"file\",\"phase\":\"%s\",\"sha256\":\"%s\",\"bytes\":%zu,\"exact\":%s}\n",
        first?"before":"after",hex,total,pass?"true":"false");
    return pass;
}
static bool HeaderIdentity(const void *base) {
    const auto *h=static_cast<const mach_header_64*>(base);
    if(!h || h->magic!=MH_MAGIC_64 || uint32_t(h->cputype)!=0x100000c ||
        uint32_t(h->cpusubtype)!=PinSubtype || h->filetype!=MH_DYLIB ||
        h->ncmds>128 || h->sizeofcmds>16384) return false;
    const auto *p=reinterpret_cast<const unsigned char*>(h+1);
    unsigned at=0,uuids=0,builds=0;bool uuid=false,build=false;
    for(unsigned i=0;i<h->ncmds;++i) {
        if(at>h->sizeofcmds || h->sizeofcmds-at<8) return false;
        load_command c; std::memcpy(&c,p+at,8);
        if(c.cmdsize<8 || (c.cmdsize&7) || c.cmdsize>h->sizeofcmds-at) return false;
        if(c.cmd==LC_UUID) {
            if(c.cmdsize!=24) return false;
            ++uuids;uuid=!std::memcmp(p+at+8,PinUUID,16);
        }
        if(c.cmd==LC_BUILD_VERSION) {
            if(c.cmdsize<24) return false;
            build_version_command b;std::memcpy(&b,p+at,sizeof(b));++builds;
            build=b.platform==PinPlatform && b.minos==PinMinOS && b.sdk==PinSDK;
        }
        at+=c.cmdsize;
    }
    return at==h->sizeofcmds && uuids==1 && builds==1 && uuid && build;
}
static bool Identity(const char *phase) {
    void *entries[13]={(void*)&FloatPlain,(void*)&FloatFormat,(void*)&FloatPrecision,
        (void*)&DoublePlain,(void*)&DoubleFormat,(void*)&DoublePrecision,
        (void*)&LongPlain,(void*)&LongFormat,(void*)&LongPrecision,
        (void*)&TypedNew,(void*)&TypedNewArray,(void*)&TypedDelete,(void*)&TypedDeleteArray};
    bool all=true;const void *base=nullptr;
    for(unsigned i=0;i<13;++i) {
        auto *entry=ptrauth_strip(entries[i],ptrauth_key_function_pointer);
        Dl_info d={};struct stat s={};
        bool pass=dladdr(entry,&d) && d.dli_fbase && d.dli_fname &&
            stat(d.dli_fname,&s)==0 && SameStat(s,FirstStat) && HeaderIdentity(d.dli_fbase) &&
            uintptr_t(entry)>=uintptr_t(d.dli_fbase) &&
            uintptr_t(entry)-uintptr_t(d.dli_fbase)==PinRVAs[i];
        if(base && base!=d.dli_fbase) pass=false;
        if(pass) base=d.dli_fbase;
        std::printf("{\"record\":\"binding\",\"phase\":\"%s\",\"index\":%u,\"rva\":%llu,\"UUID\":\"%s\",\"exact\":%s}\n",
            phase,i,(unsigned long long)(d.dli_fbase?uintptr_t(entry)-uintptr_t(d.dli_fbase):0),
            PinUUIDHex,pass?"true":"false");
        all=all && pass;
    }
    uint32_t count=_dyld_image_count();unsigned providerCount=0,forbidden=0;
    if(count>4096) return false;
    for(uint32_t i=0;i<count;++i) {
        const char *name=_dyld_get_image_name(i);if(!name) return false;
        if((const void*)_dyld_get_image_header(i)==base) ++providerCount;
        // A passive public Metal mapping from system dependencies is recorded
        // by the parent runner; this CPU probe calls no Metal or GPU entrypoint.
        if(std::strstr(name,"Virtualization.framework") || std::strstr(name,"Hypervisor.framework") ||
            std::strstr(name,"VirtualMachine") || std::strstr(name,"ParavirtualizedGraphics")) ++forbidden;
    }
    all=all && providerCount==1 && !forbidden;
    std::printf("{\"record\":\"census\",\"phase\":\"%s\",\"imageCount\":%u,\"forbidden\":%u,\"privateProviderCount\":%u,\"exact\":%s}\n",
        phase,count,forbidden,providerCount,all?"true":"false");
    return all;
}

template<class T> struct Entries {
    Result (*plain)(char*,char*,T);
    Result (*format)(char*,char*,T,Format);
    Result (*precision)(char*,char*,T,Format,int);
    unsigned start;
};
template<class T> static void Conversions(const Entries<T>& e) {
    T values[]={T(0),T(-0.0),T(1.25),std::numeric_limits<T>::min(),
        std::numeric_limits<T>::max(),std::numeric_limits<T>::denorm_min()};
    for(T value:values) {
        for(unsigned form=0;form<2;++form) {
            Case=form?"general-roundtrip":"plain-roundtrip";
            char b[256];std::memset(b,0x5a,sizeof(b));
            ++Calls[e.start+form];
            Result r=form?e.format(b+1,b+255,value,Format::general):e.plain(b+1,b+255,value);
            Check(r.ec==std::errc{} && r.ptr>=b+1 && r.ptr<b+255,"successfulBoundedWrite");
            Check(b[0]==0x5a && b[255]==0x5a,"outsideBufferCanaries");
            if(r.ec!=std::errc{} || r.ptr<b+1 || r.ptr>=b+255) continue;
            *r.ptr=0;char *end=nullptr;T decoded;
            if(sizeof(T)==4) decoded=T(std::strtof(b+1,&end));
            else decoded=T(std::strtod(b+1,&end));
            Check(end==r.ptr && !std::memcmp(&decoded,&value,sizeof(T)),"independentParserExactRoundtrip");
        }
    }
    for(unsigned form=0;form<3;++form) {
        Case="exhausted-buffer";char b[4]={0x5a,0x5a,0x5a,0x5a};
        ++Calls[e.start+form];
        Result r=form==0?e.plain(b+1,b+2,T(1.25)):form==1?e.format(b+1,b+2,T(1.25),Format::general):
            e.precision(b+1,b+2,T(1.25),Format::fixed,3);
        Check(r.ec==std::errc::value_too_large && r.ptr==b+2,"requiredRangeErrorAndEndPointer");
        Check(b[0]==0x5a && b[2]==0x5a && b[3]==0x5a,"failureOutsideBufferCanaries");
    }
    const Format formats[]={Format::fixed,Format::scientific,Format::hex};
    const char *expected[]={"1.250","1.250e+00","1.400p+0"};
    for(unsigned i=0;i<3;++i) {
        Case="precision-exact-text";char b[64]={};++Calls[e.start+2];
        Result r=e.precision(b,b+63,T(1.25),formats[i],3);
        Check(r.ec==std::errc{} && r.ptr>=b && r.ptr<b+63,"precisionSuccessfulWrite");
        if(r.ec==std::errc{} && r.ptr>=b && r.ptr<b+63) {*r.ptr=0;Check(!std::strcmp(b,expected[i]),"independentExpectedText");}
    }
    for(T value:{std::numeric_limits<T>::infinity(),std::numeric_limits<T>::quiet_NaN()}) {
        Case="special-values";char b[32]={};++Calls[e.start];Result r=e.plain(b,b+31,value);
        bool bounded=r.ec==std::errc{} && r.ptr>=b && r.ptr<b+31;
        Check(bounded,"specialSuccessfulWrite");
        if(bounded) {*r.ptr=0;Check(!std::strcmp(b,std::isnan(value)?"nan":"inf"),"specialExpectedText");}
    }
}
static void Allocations() {
    const uint64_t descriptors[]={0,0xfedcba9876543210ULL};
    for(uint64_t descriptor:descriptors) for(unsigned array=0;array<2;++array) {
        Case="typed-new-pattern-free";++Calls[9+array];
        void *p=array?TypedNewArray(257,descriptor):TypedNew(257,descriptor);
        Check(p && malloc_zone_from_ptr(p) && malloc_size(p)>=257,"realNativeAllocation");
        if(p) {
            ++Created;auto *bytes=static_cast<unsigned char*>(p);
            for(unsigned i=0;i<257;++i) bytes[i]=static_cast<unsigned char>(i*29+7);
            bool same=true;for(unsigned i=0;i<257;++i) same=same && bytes[i]==static_cast<unsigned char>(i*29+7);
            Check(same,"allRequestedBytesPreserved");++Calls[11+array];
            if(array) TypedDeleteArray(p,descriptor);else TypedDelete(p,descriptor);++Released;
        }
        Case="typed-delete-null";++Calls[11+array];
        if(array) TypedDeleteArray(nullptr,descriptor);else TypedDelete(nullptr,descriptor);
        Check(true,"nullDeleteReturned");
        Case="typed-new-zero";++Calls[9+array];
        p=array?TypedNewArray(0,descriptor):TypedNew(0,descriptor);
        Check(p && malloc_zone_from_ptr(p),"zeroSizeNativeOwner");
        if(p) {++Created;++Calls[11+array];if(array) TypedDeleteArray(p,descriptor);else TypedDelete(p,descriptor);++Released;}
        Case="typed-new-overflow-throws";bool threw=false;++Calls[9+array];
        volatile size_t maximum=SIZE_MAX;
        try {
            p=array?TypedNewArray(maximum,descriptor):TypedNew(maximum,descriptor);
            if(p) {++Created;++Calls[11+array];if(array) TypedDeleteArray(p,descriptor);else TypedDelete(p,descriptor);++Released;}
        } catch(const std::bad_alloc&) {threw=true;} catch(...) {}
        Check(threw,"nativeBadAllocCaught");
    }
}
int main() {
    std::setbuf(stdout,nullptr);rlimit cpu={5,5},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core)) return 78;
    alarm(10);
    std::printf("{\"record\":\"start\",\"pid\":%d,\"uid\":%u,\"cpuLimitSeconds\":5,\"wallLimitSeconds\":10,\"VMCalls\":0,\"GPUCalls\":0}\n",getpid(),getuid());
    bool before=FileIdentity(true) && Identity("before");Check(before,"beforeIdentity");
    if(!before) return 78;
    Conversions(Entries<float>{FloatPlain,FloatFormat,FloatPrecision,0});
    Conversions(Entries<double>{DoublePlain,DoubleFormat,DoublePrecision,3});
    Conversions(Entries<long double>{LongPlain,LongFormat,LongPrecision,6});
    Allocations();Case="lifecycle";Check(Created==Released,"allOwnAllocationsReleased");
    Check(FileIdentity(false) && Identity("after"),"afterIdentity");
    bool covered=true;for(unsigned n:Calls) covered=covered && n>0;Check(covered,"allThirteenStrongAPIsCalled");
    std::printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"created\":%u,\"released\":%u,\"calls\":[",
        Checks,Failures,Created,Released);
    for(unsigned i=0;i<13;++i) std::printf("%s%u",i?",":"",Calls[i]);
    std::printf("],\"passed\":%s}\n",Failures?"false":"true");
    alarm(0);return Failures?83:0;
}
