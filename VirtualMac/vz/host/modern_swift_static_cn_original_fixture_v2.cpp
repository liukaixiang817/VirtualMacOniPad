// Ordinary original-namespace class identity/lifetime leaf only.
// No original HID/framework caller, factory alias or VM/CPU API.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <sys/resource.h>
#include <unistd.h>

struct MetadataResponse { void *metadata; uintptr_t state; };
extern "C" MetadataResponse __attribute__((swiftcall)) originalMetadata(uintptr_t)
    __asm__("_$ss20__StaticArrayStorageCMa");
extern "C" unsigned char originalCN[] __asm__("_$ss20__StaticArrayStorageCN");
extern "C" unsigned char originalCMn[] __asm__("_$ss20__StaticArrayStorageCMn");
extern "C" unsigned char baseCN[] __asm__("_$ss28__ContiguousArrayStorageBaseCN");
extern "C" unsigned char baseCMn[] __asm__("_$ss28__ContiguousArrayStorageBaseCMn");
extern "C" void VM27StaticCNDeallocator(void * __attribute__((swift_context)))
    __attribute__((swiftcall));
extern "C" void *swift_allocObject(void *, size_t, size_t);
extern "C" void *swift_retain(void *);
extern "C" void swift_release(void *);
extern "C" bool VM27OriginalCNClassName(const void *);
static unsigned checks = 0, completedFinalReleases = 0;
static void check(bool value, const char *what) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL %s\n", what); std::abort(); }
}
static uint32_t u32(const void *p) { uint32_t v; std::memcpy(&v,p,4); return v; }
static uint64_t u64(const void *p) { uint64_t v; std::memcpy(&v,p,8); return v; }
static const unsigned char *relative(const unsigned char *p) {
    int32_t offset; std::memcpy(&offset,p,4); return p + offset;
}
static void *dataAt(void *address, uintptr_t discriminator) {
    return ptrauth_auth_data(*static_cast<void **>(address), ptrauth_key_asda,
        ptrauth_blend_discriminator(address,discriminator));
}
static void imageCensus(const char *phase) {
    const uint32_t count = _dyld_image_count();
    check(count > 0 && count <= 256, "bounded actual image census");
    unsigned forbidden = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        check(name && _dyld_get_image_header(i), "actual loaded image identity");
        const bool denied = std::strstr(name,"/Hypervisor.framework/") ||
            std::strstr(name,"/Virtualization.framework/") ||
            std::strstr(name,"/VirtualMachineMonitor.framework/") ||
            std::strstr(name,"/libHypervisor") ||
            std::strstr(name,"/libVirtualMachineMonitor") ||
            (std::strstr(name,"VM27") && std::strstr(name,".dylib"));
        forbidden += denied;
        std::printf("ORIGINAL_CN_IMAGE phase=%s index=%u denied=%u header=%p path=%s\n",
            phase,i,unsigned(denied),_dyld_get_image_header(i),name);
    }
    std::printf("ORIGINAL_CN_CENSUS phase=%s count=%u forbidden=%u\n",phase,count,forbidden);
    check(forbidden == 0, "no VM CPU or custom provider images");
}
static const void *exactOldCoreOwner(const void *symbol) {
    Dl_info info{};
    check(dladdr(symbol,&info)!=0 && info.dli_fbase && info.dli_fname,
        "actual stock symbol owner");
    check(std::strcmp(info.dli_fname,"/usr/lib/swift/libswiftCore.dylib")==0,
        "actual old Core owner path");
    const auto *header = static_cast<const mach_header_64 *>(info.dli_fbase);
    check(header->magic==MH_MAGIC_64 && header->cputype==CPU_TYPE_ARM64 &&
        header->ncmds<=256 && header->sizeofcmds<=65536, "bounded live Core header");
    const unsigned char expected[16] = {0xf8,0x96,0xd1,0x45,0xe0,0x25,0x39,0xd6,
        0xaf,0xd3,0xbc,0x0a,0x2a,0xd4,0xf8,0x39};
    const auto *commands = reinterpret_cast<const unsigned char *>(header+1);
    uint32_t at=0, uuidCount=0;
    for (uint32_t i=0; i<header->ncmds; ++i) {
        check(at<=header->sizeofcmds && header->sizeofcmds-at>=sizeof(load_command),
            "live Core command bounds");
        load_command c; std::memcpy(&c,commands+at,sizeof(c));
        check(c.cmdsize>=sizeof(c) && c.cmdsize<=header->sizeofcmds-at,
            "live Core command size");
        if (c.cmd==LC_UUID) {
            check(c.cmdsize==sizeof(uuid_command) && std::memcmp(commands+at+8,expected,16)==0,
                "actual old Core exact UUID"); ++uuidCount;
        }
        at += c.cmdsize;
    }
    check(at==header->sizeofcmds && uuidCount==1, "whole live Core commands");
    std::printf("ORIGINAL_CN_CORE symbol=%p header=%p uuid=",symbol,info.dli_fbase);
    at=0;
    for (uint32_t i=0; i<header->ncmds; ++i) {
        load_command c; std::memcpy(&c,commands+at,sizeof(c));
        if (c.cmd==LC_UUID) for (unsigned j=0;j<16;++j) std::printf("%02x",commands[at+8+j]);
        at += c.cmdsize;
    }
    std::printf(" path=%s\n",info.dli_fname);
    return info.dli_fbase;
}
int main() {
    std::setvbuf(stdout,nullptr,_IONBF,0);
    std::printf("ORIGINAL_CN_MAIN pid=%d nativeCPU=0 nativeVM=0 fullAppleGraph=0\n",getpid());
    const rlimit cpu{5,5}, core{0,0};
    check(setrlimit(RLIMIT_CPU,&cpu)==0 && setrlimit(RLIMIT_CORE,&core)==0,
        "own bounded CPU5 core0");
    rlimit observedCPU{},observedCore{};
    check(getrlimit(RLIMIT_CPU,&observedCPU)==0 && observedCPU.rlim_cur==5 &&
        observedCPU.rlim_max==5 && getrlimit(RLIMIT_CORE,&observedCore)==0 &&
        observedCore.rlim_cur==0 && observedCore.rlim_max==0, "actual limits");
    std::printf("ORIGINAL_CN_LIMITS cpu=%llu core=%llu\n",
        static_cast<unsigned long long>(observedCPU.rlim_cur),
        static_cast<unsigned long long>(observedCore.rlim_cur));
    imageCensus("before");
    const void *baseOwner = exactOldCoreOwner(baseCN);
    check(exactOldCoreOwner(baseCMn)==baseOwner, "actual old Base CN/CMn same Core");
    check(u32(baseCMn+24)==2 && u32(baseCMn+28)==18 && u32(baseCN+56)==160 &&
        u32(baseCN+60)==16 && u32(baseCN+48)==32 && u64(baseCN+96)==16,
        "actual old Base N2 P18 bytes160 AP16 instance32 field16");
    std::printf("ORIGINAL_CN_BASE cn=%p descriptor=%p N=%u P=%u bytes=%u AP=%u\n",
        baseCN,baseCMn,u32(baseCMn+24),u32(baseCMn+28),u32(baseCN+56),u32(baseCN+60));
    // MAIN and census precede CMa; ObjC classlist registration may be pre-MAIN.
    Dl_info own{},caller{},accessor{},descriptor{},deallocator{};
    const void *callerPC = reinterpret_cast<const void *>(ptrauth_strip(&main,ptrauth_key_function_pointer));
    const void *accessorPC = reinterpret_cast<const void *>(ptrauth_strip(&originalMetadata,ptrauth_key_function_pointer));
    const void *deallocatorPC = reinterpret_cast<const void *>(ptrauth_strip(&VM27StaticCNDeallocator,ptrauth_key_function_pointer));
    check(dladdr(originalCN,&own)!=0 && own.dli_fbase && own.dli_fname && own.dli_fbase!=baseOwner,
        "actual original namespace CN owned by distinct helper image");
    check(dladdr(callerPC,&caller)!=0 && caller.dli_fbase==own.dli_fbase &&
        dladdr(accessorPC,&accessor)!=0 && accessor.dli_fbase==own.dli_fbase &&
        dladdr(originalCMn,&descriptor)!=0 && descriptor.dli_fbase==own.dli_fbase &&
        dladdr(deallocatorPC,&deallocator)!=0 && deallocator.dli_fbase==own.dli_fbase,
        "main CMa CMn and corrected CfD belong to exact new helper image");
    check(dlsym(RTLD_DEFAULT,"$ss20__StaticArrayStorageCN")==originalCN &&
        dlsym(RTLD_DEFAULT,"$ss20__StaticArrayStorageCMn")==originalCMn &&
        ptrauth_strip(dlsym(RTLD_DEFAULT,"$ss20__StaticArrayStorageCMa"),ptrauth_key_function_pointer)==accessorPC,
        "true dynamic symbols resolve exact own data and CMa rather than foreign same names");
    const auto cls = reinterpret_cast<Class>(originalCN);
    check(objc_getClass("_TtCs20__StaticArrayStorage")==cls &&
        std::strcmp(class_getName(cls),"_TtCs20__StaticArrayStorage")==0,
        "same-name lookup must equal actual linked CN and actual class name");
    const auto response = originalMetadata(0);
    check(response.metadata==originalCN && response.state==0, "original CMa returns exact own CN state0");
    check(VM27OriginalCNClassName(originalCN), "actual Swift qualified type name");
    check(dataAt(originalCN+8,0xb5ab)==baseCN && dataAt(originalCN+64,0xae86)==originalCMn,
        "actual CN parent and descriptor address-diverse authentication");
    check(u32(originalCN+40)==2 && u32(originalCN+48)==32 && u32(originalCN+56)==176 &&
        u32(originalCN+60)==24 && u64(originalCN+96)==16 &&
        u32(originalCMn)==0xc0000050 && u32(originalCMn+24)==3 && u32(originalCMn+28)==19,
        "actual original176 AP24 N3 P19 scalar fields");
    check(relative(originalCMn+12)==static_cast<const unsigned char *>(accessorPC),
        "true descriptor relative CMa target");
    check(std::strcmp(reinterpret_cast<const char *>(relative(originalCMn+8)),"__StaticArrayStorage")==0,
        "actual type descriptor name");
    const auto *module = relative(originalCMn+4);
    check(u64(module)==0 && std::strcmp(reinterpret_cast<const char *>(relative(module+8)),"Swift")==0,
        "actual Swift module descriptor");
    const auto *field = relative(originalCMn+16);
    const auto *selfref = relative(field);
    check(u32(field+12)==0 && *selfref==1 && relative(selfref+1)==originalCMn,
        "true zero-field descriptor symbolic self points to own CMn");
    check(class_getSuperclass(cls)==reinterpret_cast<Class>(baseCN) && class_getInstanceSize(cls)==32,
        "runtime superclass and instance size identity");
    auto rawCfD = *reinterpret_cast<void **>(originalCN-16);
    const auto actualCfD = ptrauth_auth_and_resign(rawCfD,ptrauth_key_asia,
        ptrauth_blend_discriminator(originalCN-16,0xbbbf),ptrauth_key_function_pointer,0);
    check(ptrauth_strip(actualCfD,ptrauth_key_function_pointer)==deallocatorPC,
        "actual authenticated CN-16 equals corrected product CfD");
    std::printf("ORIGINAL_CN_IDENTITY cn=%p descriptor=%p CMa=%p CfD=%p callerPC=%p header=%p path=%s N=%u P=%u bytes=%u AP=%u sameNameExactOwn=1 priorNameAbsence=0\n",
        originalCN,originalCMn,accessorPC,deallocatorPC,callerPC,own.dli_fbase,own.dli_fname,
        u32(originalCMn+24),u32(originalCMn+28),u32(originalCN+56),u32(originalCN+60));
    for (unsigned i=0; i<128; ++i) {
        void *object = swift_allocObject(originalCN,32,7);
        check(object!=nullptr, "actual original namespace heap allocation");
        check(dataAt(object,0x6ae1)==originalCN, "actual object ISA PAC equals exact new CN");
        const uint64_t a=UINT64_C(0x8170000000000000)+i, b=UINT64_C(0xd0c0000000000000)+i;
        std::memcpy(static_cast<unsigned char *>(object)+16,&a,8);
        std::memcpy(static_cast<unsigned char *>(object)+24,&b,8);
        check(u64(static_cast<unsigned char *>(object)+16)==a &&
            u64(static_cast<unsigned char *>(object)+24)==b, "actual own inherited field values");
        check(swift_retain(object)==object, "actual retain identity");
        swift_release(object);
        check(dataAt(object,0x6ae1)==originalCN && u64(static_cast<unsigned char *>(object)+16)==a,
            "retained object remains valid after first release");
        swift_release(object); ++completedFinalReleases;
        // The freed pointer is never read. Completion follows verified CfD ABI.
    }
    imageCensus("after");
    std::printf("ORIGINAL_CN_SUMMARY checks=%u allocated=128 completedFinalReleases=%u oldN2=1 ownOriginalNamespaceN3=1 sameNameExactOwn=1 priorNameAbsence=0 fullAppleGraph=0 nativeCPU=0 nativeVM=0\n",
        checks,completedFinalReleases);
    return 0;
}
