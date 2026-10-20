// Private CPU-only genuine DIKit metadata observer after audited bootstrap. No disk, attach, VM or GPU API.
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
void MetadataObservation(const void *metadata,unsigned type,int queryStatus,const VM27DIKCVWInfo &info) {
    uint64_t kind=UINT64_MAX,size=UINT64_MAX,stride=UINT64_MAX;uint32_t flags=UINT32_MAX,extra=UINT32_MAX;
    const void *tableWord=nullptr,*layoutWord=nullptr;const unsigned char *table=nullptr,*layout=nullptr;
    bool kindRead=Read(metadata,&kind,8),tableSlot=Read((const unsigned char *)metadata-8,&tableWord,8),layoutSlot=Read((const unsigned char *)metadata-16,&layoutWord,8);
    if(tableSlot&&tableWord)table=(const unsigned char *)ptrauth_auth_data(tableWord,ptrauth_key_process_independent_data,ptrauth_blend_discriminator((const unsigned char *)metadata-8,0x2e3f));
    if(layoutSlot&&layoutWord)layout=(const unsigned char *)((uintptr_t)ptrauth_auth_data(layoutWord,ptrauth_key_process_independent_data,ptrauth_blend_discriminator((const unsigned char *)metadata-16,0x8b65))&~uintptr_t(1));
    bool tableOwned=Selected(table),tableRead=table&&Read(table+64,&size,8)&&Read(table+72,&stride,8)&&Read(table+80,&flags,4)&&Read(table+84,&extra,4);
    uint64_t header[2]={UINT64_MAX,UINT64_MAX},words[13]{};bool headerRead=layout&&Read(layout,header,16),wordsRead=false;size_t count=0;
    if(headerRead&&header[1]<=80&&header[1]%8==0){count=header[1]/8+1;wordsRead=Read(layout+16,words,count*8);}
    const unsigned char *descriptor=Descriptor(metadata);uint32_t descriptorFlags=UINT32_MAX,fields=UINT32_MAX,vector=UINT32_MAX;
    bool descriptorRead=descriptor&&Selected(descriptor)&&Read(descriptor,&descriptorFlags,4)&&Read(descriptor+20,&fields,4)&&Read(descriptor+24,&vector,4);
    std::printf("{\"record\":\"DIKitMetadataObservation\",\"typeIndex\":%u,\"typeName\":\"%s\",\"metadataCall\":%u,\"queryStatus\":%d,\"prefillSentinel\":\"0xdeadbeefdeadbeef/0xdeadbeef\",\"queryType\":%u,\"querySize\":%llu,\"queryStride\":%llu,\"queryFlags\":%u,\"queryExtraInhabitants\":%u,\"expectedType\":%u,\"expectedSize\":%u,\"expectedStride\":%u,\"expectedLowFlags\":%u,\"expectedExtraInhabitants\":2147483647,\"kindRead\":%s,\"metadataKind\":%llu,\"tableSlotRead\":%s,\"tableOwnedByDIKit\":%s,\"tableRead\":%s,\"tableSize\":%llu,\"tableStride\":%llu,\"tableFlags\":%u,\"tableExtraInhabitants\":%u,\"descriptorRead\":%s,\"descriptorFlags\":%u,\"descriptorFieldCount\":%u,\"descriptorOffsetVector\":%u,\"layoutSlotRead\":%s,\"layoutOwnedByDIKit\":%s,\"layoutHeaderRead\":%s,\"layoutHeader0\":%llu,\"layoutHeader1\":%llu,\"layoutWordsRead\":%s,\"layoutWords\":[",type,Names[type],MetadataCalls,queryStatus,info.type,(unsigned long long)info.size,(unsigned long long)info.stride,info.flags,info.extraInhabitants,type+1,(unsigned)Sizes[type],(unsigned)Strides[type],Flags[type],kindRead?"true":"false",(unsigned long long)kind,tableSlot?"true":"false",tableOwned?"true":"false",tableRead?"true":"false",(unsigned long long)size,(unsigned long long)stride,flags,extra,descriptorRead?"true":"false",descriptorFlags,fields,vector,layoutSlot?"true":"false",Selected(layout)?"true":"false",headerRead?"true":"false",(unsigned long long)header[0],(unsigned long long)header[1],wordsRead?"true":"false");
    if(wordsRead)for(size_t index=0;index<count;++index)std::printf("%s\"0x%016llx\"",index?",":"",(unsigned long long)words[index]);
    std::printf("]}\n");
}
bool GenuineMetadata(void *image) {
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
        bool selected=result.value&&Selected(result.value),named=selected&&Named(Descriptor(result.value),type);
        std::printf("{\"record\":\"DIKitMetadataResponse\",\"typeIndex\":%u,\"typeName\":\"%s\",\"metadataCall\":%u,\"state\":%llu,\"selectedGenuineImage\":%s,\"namedDescriptor\":%s}\n",type,Names[type],MetadataCalls,(unsigned long long)result.state,selected?"true":"false",named?"true":"false");
        if(!Check(result.value&&result.state==0&&selected&&named,"complete named metadata"))return false;
        values[type]=result.value;VM27DIKCVWInfo info{UINT64_C(0xdeadbeefdeadbeef),UINT64_C(0xdeadbeefdeadbeef),0xdeadbeef,0xdeadbeef,0xdeadbeef};
        int queryStatus=query(result.value,&info);MetadataObservation(result.value,type,queryStatus,info);
        if(!Check(queryStatus==1&&info.type==type+1&&info.size==Sizes[type]&&info.stride==Strides[type]&&(info.flags&0xffffff)==Flags[type]&&info.extraInhabitants==0x7fffffff,"exact scoped ownership metadata"))return false;
    }
    dlclose(provider);
    std::printf("{\"record\":\"DIKitGenuineMetadata\",\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"checks\":%u,\"failures\":%u,\"metadataCalls\":%u,\"scopedCVWQueries\":9,\"diskVMGPUCalls\":0}\n",Checks,Failures,MetadataCalls);
    return Checks==33&&Failures==0&&MetadataCalls==9;
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
    if(argc!=2||std::strcmp(argv[1],"--metadata"))return 64;
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
    if(!GenuineMetadata(image))return 83;
    if(!SecurityZero("after"))return 81;
    std::printf("{\"record\":\"DIKitClosureSummary\",\"PID\":%d,\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"genuineDI2UUID\":\"a456d4a4d6ab3549965d0400f3552de3\",\"privateAdditionalImages\":6,\"DIKitAPICalls\":9,\"DI2APICalls\":0,\"originalMetadataCalls\":9,\"diskVMGPUCalls\":0,\"fileWrites\":0,\"passed\":true,\"full27Backend\":false}\n",getpid());
    // Registered ObjC/Swift types keep their image mappings. Process exit is
    // the lifecycle boundary for this isolated transaction; no handle escapes.
    return 0;
}
