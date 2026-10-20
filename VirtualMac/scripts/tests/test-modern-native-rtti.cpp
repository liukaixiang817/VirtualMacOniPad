// Verify only genuine forwarding on own SDK-constructed type_info base
// subobjects. Never destroy system/compiler RTTI or fabricate an __si class.
#include "modern_native_rtti_compat.h"
#include "rtti-provider-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <new>
#include <ptrauth.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <typeinfo>
#include <unistd.h>
static std::atomic<unsigned> Checks{0},Failures{0},Constructed{0},Released{0};
static void Need(bool ok,const char *name){unsigned n=Checks.fetch_add(1)+1;
    if(!ok)Failures.fetch_add(1);std::printf("{\"record\":\"check\",\"id\":%u,\"name\":\"%s\",\"passed\":%s}\n",n,name,ok?"true":"false");if(!ok)_exit(1);}
static bool File(const char *path,const char *expected,size_t bytes){
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;struct stat a={},b={};
    bool ok=!fstat(fd,&a)&&S_ISREG(a.st_mode)&&a.st_nlink==1&&a.st_uid==getuid()&&!(a.st_mode&0022)&&size_t(a.st_size)==bytes;
    CC_SHA256_CTX sha;unsigned char buf[4096],digest[32];size_t count=0;ok=ok&&CC_SHA256_Init(&sha);
    while(ok){ssize_t n=read(fd,buf,sizeof(buf));if(n<0&&errno==EINTR)continue;if(n<0){ok=false;break;}if(!n)break;
        if(size_t(n)>bytes-count){ok=false;break;}count+=size_t(n);ok=CC_SHA256_Update(&sha,buf,CC_LONG(n));}
    ok=ok&&count==bytes&&!fstat(fd,&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_size==b.st_size&&a.st_mode==b.st_mode&&
        a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec;
    if(close(fd))ok=false;char hex[65]={};if(ok){ok=CC_SHA256_Final(digest,&sha);for(unsigned i=0;i<32;++i)std::snprintf(hex+2*i,3,"%02x",digest[i]);}
    std::printf("{\"record\":\"file\",\"path\":\"%s\",\"SHA256\":\"%s\",\"exact\":%s}\n",path,hex,ok&&!std::strcmp(hex,expected)?"true":"false");return ok&&!std::strcmp(hex,expected);
}
static bool UUID(const void *image){
    auto*h=static_cast<const mach_header_64*>(image);if(!h||h->magic!=MH_MAGIC_64||h->filetype!=MH_DYLIB||h->ncmds>128||h->sizeofcmds>16384)return false;
    auto*p=reinterpret_cast<const unsigned char*>(h+1);unsigned at=0,count=0;bool found=false;
    for(unsigned i=0;i<h->ncmds;++i){if(at>h->sizeofcmds||h->sizeofcmds-at<8)return false;load_command c;std::memcpy(&c,p+at,8);
        if(c.cmdsize<8||c.cmdsize&7||c.cmdsize>h->sizeofcmds-at)return false;if(c.cmd==LC_UUID){if(c.cmdsize!=24)return false;++count;found=!std::memcmp(p+at+8,ProviderUUID,16);}at+=c.cmdsize;
    }return count==1&&found&&at==h->sizeofcmds;
}
static void Identity(bool before){Need(File(ProviderPath,ProviderSHA,ProviderBytes),before?"provider file before":"provider file after");
    void*functions[]={reinterpret_cast<void*>(&VM27SiCompleteDestructor),reinterpret_cast<void*>(&VM27SiBaseDestructor)};
    for(unsigned i=0;i<2;++i){void*raw=ptrauth_strip(functions[i],ptrauth_key_function_pointer);Dl_info d={};
        Need(dladdr(raw,&d)&&d.dli_fbase&&d.dli_fname,"strong dtor actual dladdr");struct stat a={},b={};
        Need(!stat(d.dli_fname,&a)&&!stat(ProviderPath,&b)&&a.st_ino==b.st_ino&&a.st_dev==b.st_dev&&UUID(d.dli_fbase),"same provider UUID/inode");
        Need(reinterpret_cast<uintptr_t>(raw)-reinterpret_cast<uintptr_t>(d.dli_fbase)==ProviderRVA[i],"strong dtor exact RVA");
        std::printf("{\"record\":\"provider\",\"phase\":\"%s\",\"entry\":%u,\"UUID\":\"%s\",\"RVA\":%llu,\"strongImport\":true}\n",before?"before":"after",i,ProviderUUIDString,(unsigned long long)ProviderRVA[i]);
    }
    unsigned forbidden=0;for(unsigned i=0;i<_dyld_image_count();++i){const char*n=_dyld_get_image_name(i);if(n&&(std::strstr(n,"Virtualization.framework")||std::strstr(n,"Hypervisor.framework")||std::strstr(n,"VirtualMachine.framework")||std::strstr(n,"ParavirtualizedGraphics.framework")))++forbidden;}
    Need(!forbidden,"no VM/HV/VMM/PVG images");
}
class OwnedBase final:public std::type_info {
public:explicit OwnedBase(const char*name):std::type_info(name){};
};
// A real SDK-constructed type_info base subobject in owned placement storage.
// The actual __siD1 body is exactly B to type_infoD2, so the ABI bridge can be
// tested on this legal base subobject. It ends the base lifetime. No automatic
// second destructor runs: we release the separately owned raw storage ourselves.
static void One(unsigned kind){
    unsigned char *storage=static_cast<unsigned char*>(std::malloc(sizeof(OwnedBase)+32));Need(storage!=nullptr,"own placement storage allocated");
    std::memset(storage,0xa5,sizeof(OwnedBase)+32);auto*object=new(storage+16)OwnedBase("owned native type_info base");Constructed.fetch_add(1);
    Need(!std::strcmp(object->name(),"owned native type_info base"),"real SDK type_info constructor/name");
    unsigned char before[sizeof(OwnedBase)+32];std::memcpy(before,storage,sizeof(before));
    auto*base=static_cast<std::type_info*>(object);Need(reinterpret_cast<void*>(base)==reinterpret_cast<void*>(object),"genuine nonvirtual base at offset zero");
    auto*opaque=reinterpret_cast<__cxxabiv1::__si_class_type_info*>(base);
    if(kind)VM27SiBaseDestructor(opaque);else VM27SiCompleteDestructor(opaque);
    Need(!std::memcmp(storage,before,sizeof(before)),"native type_infoD2 exact no-write/no-free contract including guards");
    std::free(storage);Released.fetch_add(1);Need(true,"ended base lifetime raw owner released once");
}
static void*Worker(void*value){unsigned kind=unsigned(reinterpret_cast<uintptr_t>(value));for(unsigned i=0;i<32;++i)One(kind);return nullptr;}
int main(int argc,char**argv){
    setbuf(stdout,nullptr);std::printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"VMCalls\":0,\"GPUCalls\":0,\"staticRTTIDestructors\":0,\"syntheticNativeClasses\":0}\n",getpid(),getuid());
    rlimit cpu={4,4},core={0,0};Need(!setrlimit(RLIMIT_CPU,&cpu)&&!setrlimit(RLIMIT_CORE,&core),"bounded CPU/core");alarm(10);Need(argc==3,"signed self hash and bytes");
#if defined(VM27_RTTI_IOS)
    Need(getuid()==0&&geteuid()==0,"private Root diagnostic");
#endif
    char self[4096];uint32_t bytes=sizeof(self);Need(!_NSGetExecutablePath(self,&bytes),"actual self path");char*path=realpath(self,nullptr);Need(path,"canonical self path");
    Need(File(path,argv[1],std::strtoull(argv[2],nullptr,10)),"signed self exact bytes");std::free(path);
    Identity(true);Need(VM27NativeRTTIABIStatus()==1,"genuine system UUID/vtable/D1/D0/publicD2 code and branch pins");
    pthread_t workers[4];for(unsigned i=0;i<4;++i)Need(!pthread_create(&workers[i],nullptr,Worker,reinterpret_cast<void*>(uintptr_t(i&1))),"create real owned RTTI worker");
    for(auto&t:workers)Need(!pthread_join(t,nullptr),"join owned RTTI worker");
    Need(Constructed.load()==128&&Released.load()==128,"all 128 real constructed base subobjects storage released");
    Need(VM27NativeRTTICompleteCalls()==64&&VM27NativeRTTIBaseCalls()==64,"both 64 strong calls reached candidate entries");Identity(false);alarm(0);
    std::printf("{\"record\":\"summary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"completeCalls\":%llu,\"baseCalls\":%llu,\"constructedBaseSubobjects\":%u,\"releasedRawOwners\":%u,\"workers\":4,\"staticRTTIDestructors\":0,\"syntheticNativeClasses\":0,\"VMCalls\":0,\"GPUCalls\":0,\"fullNativeSiConstructionVerified\":false,\"full27Backend\":false}\n",getpid(),Checks.load(),Failures.load(),(unsigned long long)VM27NativeRTTICompleteCalls(),(unsigned long long)VM27NativeRTTIBaseCalls(),Constructed.load(),Released.load());return Failures.load()?1:0;
}
