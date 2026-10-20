// Private CPU-only genuine DIKit metadata caller after audited bootstrap. No disk, attach, VM or GPU API.
#include "modern_swift_static_array_bootstrap.h"
#include "diskimagekit_genuine_di2_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
extern "C" int VM27FoundationDI2LoadOnly(int, char **);
#define main VM27UnusedOriginalMetadataProbeMain
#define Identity VM27OriginalMetadataIdentity
#include "modern_diskimagekit_native_metadata_probe.cpp"
#undef Identity
#undef main
namespace {
bool FilePin(const ClosurePin &pin) {
    int fd=open(pin.path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
    struct stat status{};bool ok=fstat(fd,&status)==0&&S_ISREG(status.st_mode)&&status.st_size==off_t(pin.bytes);
    CC_SHA256_CTX context{};CC_SHA256_Init(&context);unsigned char buffer[16384]{};off_t cursor=0;
    while(ok&&cursor<status.st_size){size_t count=size_t(status.st_size-cursor);if(count>sizeof(buffer))count=sizeof(buffer);
        ssize_t got=pread(fd,buffer,count,cursor);if(got!=ssize_t(count)){ok=false;break;}
        CC_SHA256_Update(&context,buffer,(CC_LONG)count);cursor+=got;}
    unsigned char digest[32]{};CC_SHA256_Final(digest,&context);ok=close(fd)==0&&ok;
    return ok&&!std::memcmp(digest,pin.sha,32);
}
bool Identity(const void *entry,const ClosurePin &pin) {
    Dl_info owner{};char actual[PATH_MAX]{},expected[PATH_MAX]{},uuid[33]{};
    if(!entry||!dladdr(entry,&owner)||!owner.dli_fbase||!realpath(pin.path,expected)||!realpath(owner.dli_fname,actual)||std::strcmp(actual,expected))return false;
    const auto *header=(const mach_header_64 *)owner.dli_fbase;
    if(header->magic!=MH_MAGIC_64||header->filetype!=MH_DYLIB||header->ncmds>256||header->sizeofcmds>32768)return false;
    const auto *at=(const unsigned char *)(header+1),*end=at+header->sizeofcmds;unsigned found=0;
    for(unsigned i=0;i<header->ncmds;++i){if(end-at<8)return false;const auto *command=(const load_command *)at;
        if(command->cmdsize<8||command->cmdsize%8||command->cmdsize>size_t(end-at))return false;
        if(command->cmd==LC_UUID){if(command->cmdsize!=sizeof(uuid_command))return false;
            for(unsigned j=0;j<16;++j)std::snprintf(uuid+j*2,3,"%02x",at[8+j]);++found;}at+=command->cmdsize;}
    uintptr_t rva=(uintptr_t)entry-(uintptr_t)header;
    if(at!=end||found!=1||!rva||std::strcmp(uuid,pin.uuid))return false;
    std::printf("{\"record\":\"DIKitClosureIdentity\",\"UUID\":\"%s\",\"path\":\"%s\",\"RVA\":\"0x%llx\"}\n",uuid,actual,(unsigned long long)rva);return true;
}
bool AbsoluteExport(void *image) {
    void *provider=dlopen(AbsolutePath,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!provider)return false;
    dlerror();void *own=dlsym(provider,"_swiftImmortalRefCount");const char *ownError=dlerror();
    dlerror();void *visible=dlsym(image,"_swiftImmortalRefCount");const char *visibleError=dlerror();
    bool values=!ownError&&!visibleError&&(uintptr_t)own==UINT64_C(0x80000004ffffffff)&&(uintptr_t)visible==(uintptr_t)own;
    char expected[PATH_MAX]{},actual[PATH_MAX]{},uuid[33]{};bool identity=false;
    if(values&&realpath(AbsolutePath,expected))for(uint32_t i=0;i<_dyld_image_count();++i){
        const char *path=_dyld_get_image_name(i);if(!path||!realpath(path,actual)||std::strcmp(actual,expected))continue;
        const auto *header=(const mach_header_64 *)_dyld_get_image_header(i);
        if(!header||header->magic!=MH_MAGIC_64||header->filetype!=MH_DYLIB||header->ncmds>256||header->sizeofcmds>32768)break;
        const auto *at=(const unsigned char *)(header+1),*end=at+header->sizeofcmds;unsigned found=0;
        for(unsigned j=0;j<header->ncmds;++j){if(end-at<8)break;const auto *command=(const load_command *)at;
            if(command->cmdsize<8||command->cmdsize%8||command->cmdsize>size_t(end-at))break;
            if(command->cmd==LC_UUID){if(command->cmdsize!=sizeof(uuid_command))break;
                for(unsigned k=0;k<16;++k)std::snprintf(uuid+k*2,3,"%02x",at[8+k]);++found;}at+=command->cmdsize;}
        identity=at==end&&found==1&&!std::strcmp(uuid,AbsoluteUUID);break;
    }
    if(identity)std::printf("{\"record\":\"DIKitAbsoluteExport\",\"UUID\":\"%s\",\"path\":\"%s\",\"symbol\":\"_swiftImmortalRefCount\",\"providerValue\":\"0x%llx\",\"DIKitDiscoveryValue\":\"0x%llx\",\"dataDereferences\":0}\n",uuid,actual,(unsigned long long)(uintptr_t)own,(unsigned long long)(uintptr_t)visible);
    dlclose(provider);return identity;
}
bool GenuineHostMetadata(void *image,const uint64_t sizes[5],const uint64_t strides[5]) {
    auto identity=dlsym(image,Accessors[3]);if(!Check(Own(ptrauth_strip(identity,ptrauth_key_function_pointer),&SelectedImage),"genuine DIKit27 UUID"))return false;
    auto provider=dlopen(ClosureImages[0].path,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!provider)return false;
    auto query=(Query)dlsym(provider,"VM27DIKCVWQuery");if(!Check(query!=nullptr,"scoped query exists")||!Identity(ptrauth_strip((void *)query,ptrauth_key_function_pointer),ClosureImages[0]))return false;
    const void *values[9]{};
    for(unsigned type=0;type<9;++type){const void *target=nullptr;
        if(Accessors[type])target=ptrauth_strip(dlsym(image,Accessors[type]),ptrauth_key_function_pointer);
        else {auto parent=Descriptor(values[3]);if(!Check(parent&&Selected(parent),"private metadata parent identity"))return false;
            auto descriptor=parent+(type==4?0x44:0x264);int32_t rel=0;
            if(!Check(Named(descriptor,type)&&Read(descriptor+12,&rel,4),"private descriptor schema and name"))return false;target=descriptor+12+rel;}
        if(!Check(Selected(target),"metadata accessor selected image"))return false;
        auto result=Function(target)(0);++MetadataCalls;
        if(!Check(result.value&&result.state==0&&Selected(result.value)&&Named(Descriptor(result.value),type),"complete named metadata"))return false;
        values[type]=result.value;VM27DIKCVWInfo info{};
        int queryStatus=query(result.value,&info);
        unsigned runtimeFlags=0x10007u|(info.size>24?0x20000u:0u);bool publicMatch=true;
        if(type<4)publicMatch=info.size==sizes[type+1]&&info.stride==strides[type+1];
        bool legacy=info.size==Sizes[type]&&info.stride==Strides[type]&&(info.flags&0xffffff)==Flags[type];
        std::printf("{\"record\":\"DIKitHostMetadata\",\"typeIndex\":%u,\"typeName\":\"%s\",\"originalMetadataCall\":%u,\"queryStatus\":%d,\"type\":%u,\"size\":%llu,\"stride\":%llu,\"flags\":%u,\"extraInhabitants\":%u,\"matchesRealSDKPublicDimensions\":%s,\"matchesOriginalMacGolden\":%s}\n",type,Names[type],MetadataCalls,queryStatus,info.type,(unsigned long long)info.size,(unsigned long long)info.stride,info.flags,info.extraInhabitants,publicMatch?"true":"false",legacy?"true":"false");
        if(!Check(queryStatus==1&&info.type==type+1&&info.size>0&&info.size<=256&&info.stride==((info.size+7)&~size_t(7))&&(info.flags&0xffffff)==runtimeFlags&&info.extraInhabitants==0x7fffffff&&publicMatch,"real SDK host-layout ownership metadata after semantic fixture"))return false;
    }
    dlclose(provider);
    std::printf("{\"record\":\"DIKitGenuineHostMetadata\",\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"checks\":%u,\"failures\":%u,\"metadataCalls\":%u,\"scopedCVWQueries\":9,\"diskVMGPUCalls\":0}\n",Checks,Failures,MetadataCalls);
    return Checks==33&&Failures==0&&MetadataCalls==9;
}
uint64_t Clock(clockid_t which) {timespec value{};if(clock_gettime(which,&value)||value.tv_sec<0||value.tv_nsec<0||value.tv_nsec>=1000000000)return 0;return uint64_t(value.tv_sec)*UINT64_C(1000000000)+uint64_t(value.tv_nsec);}
uint32_t BoundaryRecords=0;
void Boundary(const char *section,const char *stage) {
    ++BoundaryRecords;
    std::printf("{\"record\":\"DIKitSDK128CallBoundary\",\"boundary\":%u,\"section\":\"%s\",\"stage\":\"%s\",\"processCPUNanoseconds\":%llu,\"monotonicNanoseconds\":%llu}\n",BoundaryRecords,section,stage,(unsigned long long)Clock(CLOCK_PROCESS_CPUTIME_ID),(unsigned long long)Clock(CLOCK_MONOTONIC));
}
bool PrimitiveCacheStatus(const char *phase) {
    void *provider=dlopen(ClosureImages[0].path,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!provider)return false;
    using Status=uint64_t (*)(void);auto status=(Status)dlsym(provider,"VM27DIKCVWPrimitiveIdentityCacheStatus");
    uint64_t result=status?status():0;
    if(!status||!Identity(ptrauth_strip((void *)status,ptrauth_key_function_pointer),ClosureImages[0])||result!=UINT64_C(0x100000001)){dlclose(provider);return false;}
    std::printf("{\"record\":\"DIKitPrimitiveCacheStatus\",\"phase\":\"%s\",\"cachedProvider\":true,\"counterAvailable\":true,\"initializerRuns\":%u,\"nineFixedBindingsValid\":true,\"dynamicMetadataLayoutCached\":false}\n",phase,uint32_t(result>>32));
    dlclose(provider);return true;
}
bool SDKSemantics(uint64_t sizes[5],uint64_t strides[5]) {
    if(!FilePin(SDKFixtureImage))return false;
    void *fixture=dlopen(SDKFixtureImage.path,RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);if(!fixture){std::fprintf(stderr,"original SDK fixture load: %s\n",dlerror());return false;}
    using Dimensions=uint64_t (*)(uint32_t);using Run=uint64_t (*)(void);
    auto dimension=(Dimensions)dlsym(fixture,"VM27DIKitHostLayoutDimensions");auto semantic=(Run)dlsym(fixture,"VM27DIKitHostLayoutSemanticFixture");auto ownership=(Run)dlsym(fixture,"VM27DIKitHostLayoutOwnershipFixture");
    if(!dimension||!semantic||!ownership||!Identity(ptrauth_strip((void *)dimension,ptrauth_key_function_pointer),SDKFixtureImage)||!Identity(ptrauth_strip((void *)semantic,ptrauth_key_function_pointer),SDKFixtureImage)||!Identity(ptrauth_strip((void *)ownership,ptrauth_key_function_pointer),SDKFixtureImage))return false;
    for(uint32_t type=0;type<5;++type){uint64_t result=dimension(type);sizes[type]=result>>32;strides[type]=uint32_t(result);
        std::printf("{\"record\":\"DIKitRealSDKHostDimension\",\"typeIndex\":%u,\"size\":%llu,\"stride\":%llu}\n",type,(unsigned long long)sizes[type],(unsigned long long)strides[type]);
        if(!sizes[type]||sizes[type]>256||strides[type]<sizes[type]||strides[type]>256)return false;}
    uint64_t cpuStart=Clock(CLOCK_PROCESS_CPUTIME_ID),wallStart=Clock(CLOCK_MONOTONIC);if(!cpuStart||!wallStart)return false;
    Boundary("semantic","begin");
    uint64_t semanticResult=semantic();
    Boundary("semantic","end");uint32_t semanticChecks=semanticResult>>32,semanticFailures=uint32_t(semanticResult);
    std::printf("{\"record\":\"DIKitRealSDKConfigurationSemantics\",\"checks\":%u,\"failures\":%u,\"iterations\":128,\"originalConfigurationFactories\":896,\"SDKImplicitMetadataAndGetterCallsUncounted\":true,\"diskAPICalls\":0}\n",semanticChecks,semanticFailures);
    if(semanticChecks!=1536||semanticFailures)return false;
    Boundary("ownership","begin");
    uint64_t ownershipResult=ownership();
    Boundary("ownership","end");uint32_t ownershipChecks=ownershipResult>>32,ownershipFailures=uint32_t(ownershipResult);
    std::printf("{\"record\":\"DIKitRealSDKURLOwnership\",\"checks\":%u,\"failures\":%u,\"iterations\":128,\"originalConfigurationFactories\":128,\"weakObjectLifecycleChecksPassed\":%s,\"diskAPICalls\":0}\n",ownershipChecks,ownershipFailures,(ownershipChecks==384&&!ownershipFailures)?"true":"false");
    if(ownershipChecks!=384||ownershipFailures)return false;
    uint64_t cpuEnd=Clock(CLOCK_PROCESS_CPUTIME_ID),wallEnd=Clock(CLOCK_MONOTONIC);if(cpuEnd<cpuStart||wallEnd<wallStart)return false;
    std::printf("{\"record\":\"DIKitSDK128PerformanceTiming\",\"iterationsPerSection\":128,\"originalConfigurationFactories\":1024,\"CPUStartNanoseconds\":%llu,\"CPUEndNanoseconds\":%llu,\"wallStartNanoseconds\":%llu,\"wallEndNanoseconds\":%llu,\"CPUElapsedNanoseconds\":%llu,\"wallElapsedNanoseconds\":%llu,\"boundaryRecords\":%u,\"originalSDKFixtureBytesUnchanged\":true}\n",(unsigned long long)cpuStart,(unsigned long long)cpuEnd,(unsigned long long)wallStart,(unsigned long long)wallEnd,(unsigned long long)(cpuEnd-cpuStart),(unsigned long long)(wallEnd-wallStart),BoundaryRecords);
    if(BoundaryRecords!=4)return false;
    // The fixture has registered a local Swift class; its mapping belongs to this child lifecycle.
    return true;
}
bool SecurityZero(const char *phase) {
    void *image=dlopen(SecurityPath,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!image)return false;
    using Counter=uint64_t (*)(uint32_t);auto counter=(Counter)dlsym(image,"VM27DI2SecurityCallCount");if(!counter){dlclose(image);return false;}
    bool ok=true;for(uint32_t i=0;i<10;++i){uint64_t calls=counter(i);
        std::printf("{\"record\":\"DIKitSecurityCounter\",\"phase\":\"%s\",\"entry\":%u,\"calls\":%llu}\n",phase,i,(unsigned long long)calls);if(calls)ok=false;}
    dlclose(image);return ok;
}
}
int main(int argc,char **argv) {
    if(argc!=2||std::strcmp(argv[1],"--host-regression128"))return 64;
    std::setvbuf(stdout,nullptr,_IONBF,0);rlimit cpu{3,4};if(setrlimit(RLIMIT_CPU,&cpu))return 64;alarm(10);
    std::printf("{\"record\":\"DIKitClosureStart\",\"PID\":%d,\"DIKitAPICalls\":0,\"DI2APICalls\":0}\n",getpid());
    for(uint32_t i=0;i<_dyld_image_count();++i){const char *path=_dyld_get_image_name(i);if(path&&std::strstr(path,"DiskImageKit"))return 65;}
    for(const auto &pin:ClosureImages)if(!FilePin(pin))return 66;
    if(!FilePin(AbsoluteImage))return 66;
    char loadFlag[]="--load-only";char *loadArguments[]={argv[0],loadFlag,nullptr};
    int di2=VM27FoundationDI2LoadOnly(2,loadArguments);if(di2)return di2;
    if(!SecurityZero("before"))return 68;
    VM27StaticArrayBootstrapReport report{};void *image=nullptr;
    int result=VM27StaticArrayBootstrapLoad(DIKitPath,FactoryPath,0,&report,&image);
    std::printf("{\"record\":\"DIKitBootstrap\",\"status\":%d,\"checks\":%u,\"requiredImports\":%u,\"factoryCalls\":%u,\"requirementBindingsAuthenticated\":%u,\"authenticatedBefore\":%u,\"authenticatedAfter\":%u,\"rollbackAuthenticated\":%u,\"pageProtectionBefore\":%u,\"pageMaximumBefore\":%u,\"pageProtectionAfter\":%u,\"pageMaximumAfter\":%u,\"pagesChanged\":%u,\"rolledBack\":%u,\"protectionRestored\":%u,\"handlePublished\":%u,\"failureStage\":%u,\"DIKitAPICalls\":0,\"diskVMGPUCalls\":0}\n",result,report.checks,report.requiredImports,report.factoryCalls,report.requirementBindingsAuthenticated,report.authenticatedBefore,report.authenticatedAfter,report.rollbackAuthenticated,report.pageProtectionBefore,report.pageMaximumBefore,report.pageProtectionAfter,report.pageMaximumAfter,report.pagesChanged,report.rolledBack,report.protectionRestored,report.handlePublished,report.failureStage);
    if(result||!image||report.authenticatedBefore!=3||report.authenticatedAfter!=3||report.requirementBindingsAuthenticated!=20||report.factoryCalls!=1||!report.protectionRestored||!report.handlePublished)return result?result:79;
    for(const auto &pin:ClosureImages){void *owner=dlopen(pin.path,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!owner)return 80;
        void *entry=dlsym(owner,pin.symbol);if(!pin.data)entry=ptrauth_strip(entry,ptrauth_key_function_pointer);
        bool correct=Identity(entry,pin);dlclose(owner);if(!correct)return 80;}
    if(!AbsoluteExport(image))return 82;
    if(!PrimitiveCacheStatus("before"))return 85;
    uint64_t sizes[5]{},strides[5]{};if(!SDKSemantics(sizes,strides))return 84;
    if(!PrimitiveCacheStatus("after"))return 85;
    if(!GenuineHostMetadata(image,sizes,strides))return 83;
    if(!SecurityZero("after"))return 81;
    std::printf("{\"record\":\"DIKitClosureSummary\",\"PID\":%d,\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"genuineDI2UUID\":\"a456d4a4d6ab3549965d0400f3552de3\",\"privateAdditionalImages\":6,\"originalExplicitMetadataCalls\":9,\"knownOriginalConfigurationFactoryCalls\":1024,\"SDKImplicitMetadataAndGetterCallsUncounted\":true,\"DI2APICalls\":0,\"originalMacGoldenPassClaimed\":false,\"diskVMGPUCalls\":0,\"fileWrites\":0,\"passed\":true,\"full27Backend\":false}\n",getpid());
    // Registered ObjC/Swift types keep their image mappings. Process exit is
    // the lifecycle boundary for this isolated transaction; no handle escapes.
    return 0;
}
