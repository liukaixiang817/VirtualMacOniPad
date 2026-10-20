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
uint32_t StepRecords=0;
extern "C" void StepCheckpoint(uint32_t operation,uint32_t stage,uint32_t childIndex,uint32_t checks,uint32_t failures) {
    ++StepRecords;
    std::printf("{\"record\":\"DIKitSDKCheckpoint\",\"checkpoint\":%u,\"operation\":%u,\"stage\":%u,\"childIndex\":%u,\"checks\":%u,\"failures\":%u}\n",StepRecords,operation,stage,childIndex,checks,failures);
}
bool SDKSteps() {
    if(!FilePin(SDKFixtureImage))return false;
    void *fixture=dlopen(SDKFixtureImage.path,RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);if(!fixture){std::fprintf(stderr,"original SDK fixture load: %s\n",dlerror());return false;}
    using Dimensions=uint64_t (*)(uint32_t);
    using Callback=void (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
    using Run=uint64_t (*)(Callback);
    auto dimension=(Dimensions)dlsym(fixture,"VM27DIKitHostLayoutDimensions");auto semantic=(Run)dlsym(fixture,"VM27DIKitHostLayoutStepFixture");auto ownership=(Run)dlsym(fixture,"VM27DIKitHostLayoutStepOwnershipFixture");
    if(!dimension||!semantic||!ownership||!Identity(ptrauth_strip((void *)dimension,ptrauth_key_function_pointer),SDKFixtureImage)||!Identity(ptrauth_strip((void *)semantic,ptrauth_key_function_pointer),SDKFixtureImage)||!Identity(ptrauth_strip((void *)ownership,ptrauth_key_function_pointer),SDKFixtureImage))return false;
    for(uint32_t type=0;type<5;++type){uint64_t result=dimension(type);uint64_t size=result>>32,stride=uint32_t(result);
        std::printf("{\"record\":\"DIKitRealSDKHostDimension\",\"typeIndex\":%u,\"size\":%llu,\"stride\":%llu}\n",type,(unsigned long long)size,(unsigned long long)stride);
        if(!size||size>256||stride<size||stride>256)return false;}
    void *genuine=dlopen(DIKitPath,RTLD_NOW|RTLD_NOLOAD|RTLD_LOCAL|RTLD_FIRST);if(!genuine)return false;
    const char *methods[]={
        "$s12DiskImageKit0aB0C21CreationConfigurationPA2A012ASIFCreationE0VRszrlE4asif3url10blockCount0I4SizeAG10Foundation3URLV_SiAC05BlockK0OtFZ",
        "$s12DiskImageKit0aB0C21CreationConfigurationPA2A011RAWCreationE0VRszrlE3raw3url10blockCountAG10Foundation3URLV_SitFZ",
        "$s12DiskImageKit25ASIFCreationConfigurationV5layer3url4typeAA017ASIFLayerCreationE0V10Foundation3URLV_AA0aB0C9LayerTypeVtFZ",
        "$s12DiskImageKit17OpenConfigurationV3url4modeAC10Foundation3URLV_AC4ModeOtcfC",
        "$s12DiskImageKit17OpenConfigurationV3url10Foundation3URLVvg",
        "$s12DiskImageKit17OpenConfigurationV4modeAC4ModeOvg",
        "$s12DiskImageKit0aB0C9BlockSizeO8rawValueSivg"};
    for(uint32_t index=0;index<7;++index){void *method=ptrauth_strip(dlsym(genuine,methods[index]),ptrauth_key_function_pointer);
        if(!Identity(method,ClosureImages[4]))return false;
        std::printf("{\"record\":\"DIKitOriginalSDKMethodIdentity\",\"methodIndex\":%u,\"symbol\":\"%s\",\"callsAtObservation\":0}\n",index,methods[index]);}
    dlclose(genuine);
    uint64_t semanticResult=semantic(StepCheckpoint);uint32_t semanticChecks=semanticResult>>32,semanticFailures=uint32_t(semanticResult);
    std::printf("{\"record\":\"DIKitRealSDKConfigurationStepSemantics\",\"checks\":%u,\"failures\":%u,\"iterations\":1,\"originalConfigurationFactories\":7,\"SDKImplicitMetadataAndGetterCallsUncounted\":true,\"diskAPICalls\":0}\n",semanticChecks,semanticFailures);
    if(semanticChecks!=12||semanticFailures)return false;
    uint64_t ownershipResult=ownership(StepCheckpoint);uint32_t ownershipChecks=ownershipResult>>32,ownershipFailures=uint32_t(ownershipResult);
    std::printf("{\"record\":\"DIKitRealSDKURLStepOwnership\",\"checks\":%u,\"failures\":%u,\"iterations\":1,\"originalConfigurationFactories\":1,\"weakObjectLifecycleChecksPassed\":%s,\"diskAPICalls\":0}\n",ownershipChecks,ownershipFailures,(ownershipChecks==3&&!ownershipFailures)?"true":"false");
    if(ownershipChecks!=3||ownershipFailures)return false;
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
    if(argc!=2||std::strcmp(argv[1],"--host-step-diagnostic"))return 64;
    std::setvbuf(stdout,nullptr,_IONBF,0);rlimit cpu{5,6};if(setrlimit(RLIMIT_CPU,&cpu))return 64;alarm(10);
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
    if(!SDKSteps())return 84;
    if(!SecurityZero("after"))return 81;
    std::printf("{\"record\":\"DIKitClosureSummary\",\"PID\":%d,\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"genuineDI2UUID\":\"a456d4a4d6ab3549965d0400f3552de3\",\"privateAdditionalImages\":6,\"originalExplicitMetadataCalls\":0,\"knownOriginalConfigurationFactoryCalls\":8,\"SDKImplicitMetadataAndGetterCallsUncounted\":true,\"DI2APICalls\":0,\"originalMacGoldenPassClaimed\":false,\"diskVMGPUCalls\":0,\"fileWrites\":0,\"passed\":true,\"full27Backend\":false}\n",getpid());
    // Registered ObjC/Swift types keep their image mappings. Process exit is
    // the lifecycle boundary for this isolated transaction; no handle escapes.
    return 0;
}
