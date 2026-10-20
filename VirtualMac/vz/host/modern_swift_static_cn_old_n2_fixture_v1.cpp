// Ordinary owned-class registration fixture. No original StaticCN is loaded.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <sys/resource.h>
#include <unistd.h>

struct MetadataResponse { void *metadata; uintptr_t state; };
extern "C" MetadataResponse __attribute__((swiftcall)) ownMetadata(uintptr_t)
    __asm__("_$s14VM27OldN2Model16OwnStaticStorageCMa");
extern "C" unsigned char ownCN[] __asm__("_$s14VM27OldN2Model16OwnStaticStorageCN");
extern "C" unsigned char ownCMn[] __asm__("_$s14VM27OldN2Model16OwnStaticStorageCMn");
extern "C" unsigned char baseCN[] __asm__("_$ss28__ContiguousArrayStorageBaseCN");
extern "C" unsigned char baseCMn[] __asm__("_$ss28__ContiguousArrayStorageBaseCMn");
extern "C" void *swift_allocObject(void *, size_t, size_t);
extern "C" void *swift_retain(void *);
extern "C" void swift_release(void *);
extern "C" bool VM27OldN2ClassName(const void *);
extern "C" void *VM27OldN2UInt64Metadata();
extern "C" bool VM27OldN2NilUInt64(const void *);
extern "C" void VM27StaticCNVerbatimNil(
    void * __attribute__((swift_indirect_result)), void *, void *, void *,
    void * __attribute__((swift_context)), void ** __attribute__((swift_error_result)))
    __attribute__((swiftcall));
using CanStore = bool __attribute__((swiftcall))(
    void *, void * __attribute__((swift_context)));
static unsigned checks = 0, destroyed = 0;
static void check(bool value, const char *what) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL %s\n", what); std::abort(); }
}
extern "C" void VM27OldN2OwnDestroyed(void *object) {
    check(object != nullptr, "deallocator actual own object"); ++destroyed;
}
static uint32_t u32(const void *p) { uint32_t v; std::memcpy(&v,p,4); return v; }
static uint64_t u64(const void *p) { uint64_t v; std::memcpy(&v,p,8); return v; }
static void *dataAt(void *address, uintptr_t discriminator) {
    return ptrauth_auth_data(*static_cast<void **>(address), ptrauth_key_asda,
                            ptrauth_blend_discriminator(address,discriminator));
}
static void *exactOldCoreOwner(const void *symbol) {
    Dl_info info{};
    check(dladdr(symbol,&info)!=0 && info.dli_fbase && info.dli_fname,
          "actual stock symbol owner");
    check(std::strcmp(info.dli_fname,"/usr/lib/swift/libswiftCore.dylib")==0,
          "actual old Core owner path");
    const auto *header=static_cast<const mach_header_64 *>(info.dli_fbase);
    check(header->magic==MH_MAGIC_64 && header->cputype==CPU_TYPE_ARM64 &&
          header->ncmds<=256 && header->sizeofcmds<=65536,"bounded live Core header");
    const unsigned char *commands=reinterpret_cast<const unsigned char *>(header+1);
    const unsigned char expectedUUID[16]={0xf8,0x96,0xd1,0x45,0xe0,0x25,0x39,0xd6,
                                         0xaf,0xd3,0xbc,0x0a,0x2a,0xd4,0xf8,0x39};
    uint32_t at=0,uuidCount=0;
    for (uint32_t i=0;i<header->ncmds;++i) {
        check(at<=header->sizeofcmds && header->sizeofcmds-at>=sizeof(load_command),
              "live Core command bounds");
        load_command command; std::memcpy(&command,commands+at,sizeof(command));
        check(command.cmdsize>=sizeof(command) && command.cmdsize<=header->sizeofcmds-at,
              "live Core command size");
        if (command.cmd==LC_UUID) {
            check(command.cmdsize==sizeof(uuid_command),"exact live UUID command width");
            check(std::memcmp(commands+at+8,expectedUUID,16)==0,"exact actual old Core UUID");
            ++uuidCount;
        }
        at+=command.cmdsize;
    }
    check(at==header->sizeofcmds && uuidCount==1,"whole live Core commands and one UUID");
    return info.dli_fbase;
}
int main() {
    std::setvbuf(stdout,nullptr,_IONBF,0);
    std::printf("OWN_N2_STATIC_MAIN pid=%d originalIdentity=0 nativeCPU=0 nativeVM=0\n",getpid());
    const rlimit cpu{5,5},core{0,0};
    check(setrlimit(RLIMIT_CPU,&cpu)==0 && setrlimit(RLIMIT_CORE,&core)==0,
          "own bounded CPU5 core0");
    rlimit observedCPU{},observedCore{};
    check(getrlimit(RLIMIT_CPU,&observedCPU)==0 && observedCPU.rlim_cur==5 &&
          observedCPU.rlim_max==5 && getrlimit(RLIMIT_CORE,&observedCore)==0 &&
          observedCore.rlim_cur==0 && observedCore.rlim_max==0,"actual own limits");
    void *baseOwner=exactOldCoreOwner(baseCN);
    check(exactOldCoreOwner(baseCMn)==baseOwner,"actual Base CN and CMn same old Core");
    check(u32(baseCMn+24)==2 && u32(baseCMn+28)==18 &&
          u32(baseCN+56)==160 && u32(baseCN+60)==16,"actual old Base N2 P18 160 AP16");
    check(u32(baseCN+48)==32 && u64(baseCN+96)==16,"actual old Base instance32 field16");
    const auto metadata=ownMetadata(0);
    check(metadata.metadata==ownCN && metadata.state==0,"real CMa own CN state0");
    check(VM27OldN2ClassName(ownCN),"real Swift distinct own name");
    check(u32(ownCN+40)==2 && u32(ownCN+48)==32 && u32(ownCN+56)==176 &&
          u32(ownCN+60)==24 && u64(ownCN+96)==16 && u32(ownCMn+24)==3 &&
          u32(ownCMn+28)==19,"real own176 AP24 N3 P19 fields");
    check(dataAt(ownCN+8,0xb5ab)==baseCN,"own authenticated actual old Base parent");
    check(dataAt(ownCN+64,0xae86)==ownCMn,"own authenticated actual descriptor");
    Dl_info ownInfo{};
    check(dladdr(ownCN,&ownInfo)!=0 && ownInfo.dli_fbase && ownInfo.dli_fbase!=baseOwner,
          "own data belongs to separate fixture image");
    const auto cls=reinterpret_cast<Class>(ownCN);
    check(objc_getClass("_TtC14VM27OldN2Model16OwnStaticStorage")==cls,"real own ObjC registration");
    check(class_getSuperclass(cls)==reinterpret_cast<Class>(baseCN),"runtime actual old Base identity");
    check(class_getInstanceSize(cls)==32,"runtime actual own instance32");
    void *uintMetadata=VM27OldN2UInt64Metadata();
    for (unsigned i=0;i<128;++i) {
        void *object=swift_allocObject(ownCN,32,7);
        check(object!=nullptr,"real own class allocation");
        check(dataAt(object,0x6ae1)==ownCN,"actual own object ISA authentication");
        const uint64_t first=UINT64_C(0x8170000000000000)+i;
        const uint64_t second=UINT64_C(0xd0c0000000000000)+i;
        std::memcpy(static_cast<unsigned char *>(object)+16,&first,sizeof(first));
        std::memcpy(static_cast<unsigned char *>(object)+24,&second,sizeof(second));
        check(u64(static_cast<unsigned char *>(object)+16)==first &&
              u64(static_cast<unsigned char *>(object)+24)==second,"actual inherited own field bytes");
        auto rawCanStore=*reinterpret_cast<CanStore **>(ownCN+128);
        auto canStore=ptrauth_auth_and_resign(rawCanStore,ptrauth_key_asia,
            ptrauth_blend_discriminator(ownCN+128,0x4d6c),ptrauth_key_function_pointer,0);
        check(!canStore(uintMetadata,object),"actual authenticated typed own canStore method");
        alignas(16) unsigned char nilStorage[16]; std::memset(nilStorage,0xa7,sizeof(nilStorage)); void *error=nullptr;
        VM27StaticCNVerbatimNil(nilStorage,nullptr,nullptr,uintMetadata,object,&error);
        check(error==nullptr && VM27OldN2NilUInt64(nilStorage),"actual UInt64 optional nil witness");
        check(swift_retain(object)==object,"actual own Swift retain");
        swift_release(object); check(destroyed==i,"retained own object alive");
        swift_release(object); check(destroyed==i+1,"own deallocator exactly once");
    }
    std::printf("OWN_N2_STATIC_SUMMARY checks=%u created=128 destroyed=%u oldN2=1 ownN3=1 originalIdentity=0 nativeCPU=0 nativeVM=0\n",checks,destroyed);
    return 0;
}
