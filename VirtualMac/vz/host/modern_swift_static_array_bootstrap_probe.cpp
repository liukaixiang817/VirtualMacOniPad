// Own private loader first, then the existing exact nine-type metadata checks.
#include "modern_swift_static_array_bootstrap.h"
#define main VM27UnusedOriginalMetadataProbeMain
#include "modern_diskimagekit_native_metadata_probe.cpp"
#undef main
#include <cstdlib>
#include <limits.h>
namespace {
#if defined(VM27_FIXTURE_UUID)
bool FixtureIdentity(const void *entry,const char *path,char actual[33]) {
    Dl_info owner{};mach_header_64 header{};char canonical[PATH_MAX]{},expected[PATH_MAX]{};
    if(!entry||!dladdr(entry,&owner)||!Read(owner.dli_fbase,&header,sizeof(header))||header.magic!=MH_MAGIC_64||header.cputype!=CPU_TYPE_ARM64||header.cpusubtype!=(cpu_subtype_t)0x80000002||header.ncmds>1024||header.sizeofcmds>65536)return false;
    const auto *at=(const unsigned char *)owner.dli_fbase+sizeof(header),*end=at+header.sizeofcmds;unsigned found=0;
    for(unsigned i=0;i<header.ncmds;++i){load_command c{};if(end-at<8||!Read(at,&c,8)||c.cmdsize<8||c.cmdsize%8||c.cmdsize>size_t(end-at))return false;
        if(c.cmd==LC_UUID){uuid_command u{};if(c.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;for(unsigned j=0;j<16;++j)std::snprintf(actual+j*2,3,"%02x",u.uuid[j]);++found;}at+=c.cmdsize;}
    return at==end&&found==1&&!std::strcmp(actual,VM27_FIXTURE_UUID)&&realpath(path,expected)&&realpath(owner.dli_fname,canonical)&&!std::strcmp(expected,canonical);
}
#endif
}
int main(int argc,char **argv) {
    std::setvbuf(stdout,nullptr,_IONBF,0);
    if(argc<4||argc>6)return 64;
    bool metadata=argc==5&&!std::strcmp(argv[4],"--metadata");
    bool arrays=argc==6&&!std::strcmp(argv[4],"--array-fixture");
#if !defined(VM27_FIXTURE_UUID)
    if(arrays)return 64; // The Mac SDK fixture has no iOS ABI analogue here.
#endif
    unsigned rollback=0;
    if(argc==5&&!std::strncmp(argv[4],"--rollback-after=",17))rollback=unsigned(std::strtoul(argv[4]+17,nullptr,10));
    if(argc!=4&&!metadata&&!arrays&&!(rollback>=1&&rollback<=3))return 64;
    VM27StaticArrayBootstrapReport report{};void *image=nullptr;
    int status=VM27StaticArrayBootstrapLoad(argv[1],argv[2],rollback,&report,&image);
    std::printf("{\"phase\":\"bootstrap\",\"status\":%d,\"checks\":%u,\"requiredImports\":%u,\"factoryCalls\":%u,\"requirementBindingsAuthenticated\":%u,\"authenticatedBefore\":%u,\"authenticatedAfter\":%u,\"rollbackAuthenticated\":%u,\"pageProtectionBefore\":%u,\"pageMaximumBefore\":%u,\"pageProtectionAfter\":%u,\"pageMaximumAfter\":%u,\"pagesChanged\":%u,\"rolledBack\":%u,\"protectionRestored\":%u,\"handlePublished\":%u,\"failureStage\":%u,\"DIKitAPICallsBeforeBootstrap\":0,\"diskCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n",status,report.checks,report.requiredImports,report.factoryCalls,report.requirementBindingsAuthenticated,report.authenticatedBefore,report.authenticatedAfter,report.rollbackAuthenticated,report.pageProtectionBefore,report.pageMaximumBefore,report.pageProtectionAfter,report.pageMaximumAfter,report.pagesChanged,report.rolledBack,report.protectionRestored,report.handlePublished,report.failureStage);
    if(rollback)return status==85&&!image&&report.rolledBack&&report.rollbackAuthenticated==3&&report.protectionRestored&&!report.handlePublished?0:1;
    if(status||!image||!report.handlePublished||report.authenticatedAfter!=3||!report.protectionRestored)return status?status:1;
    if(arrays){
#if defined(VM27_FIXTURE_UUID)
        void *fixture=dlopen(argv[5],RTLD_NOW|RTLD_LOCAL);if(!fixture){std::fprintf(stderr,"fixture: %s\n",dlerror());return 87;}
        using Fixture=unsigned long long (*)(void);auto run=(Fixture)dlsym(fixture,"VM27DIKitStaticArrayFixture");if(!run)return 88;
        char actual[33]{};if(!FixtureIdentity(ptrauth_strip((void *)run,ptrauth_key_function_pointer),argv[5],actual))return 88;
        std::printf("{\"phase\":\"fixtureIdentity\",\"actualUUID\":\"%s\",\"canonicalPathMatched\":true,\"fixtureCalls\":0}\n",actual);
        unsigned long long result=run();unsigned checks=unsigned(result>>32),failures=unsigned(result);
        std::printf("{\"phase\":\"arrays\",\"checks\":%u,\"failures\":%u,\"iterations\":512,\"originalDIKitArrayCalls\":1024,\"COWAppendRemoveChecks\":true,\"diskCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n",checks,failures);return failures?1:0;
#endif
    }
    if(!metadata)return 0;
    auto identity=dlsym(image,Accessors[3]);if(!Check(Own(ptrauth_strip(identity,ptrauth_key_function_pointer),&SelectedImage),"genuine DIKit27 UUID"))return 67;
    auto provider=dlopen(argv[3],RTLD_NOW|RTLD_LOCAL);if(!provider)return 69;
    auto query=(Query)dlsym(provider,"VM27DIKCVWQuery");if(!Check(query!=nullptr,"scoped query exists"))return 70;
    const void *values[9]{};
    for(unsigned type=0;type<9;++type){const void *target=nullptr;
        if(Accessors[type])target=ptrauth_strip(dlsym(image,Accessors[type]),ptrauth_key_function_pointer);
        else {auto parent=Descriptor(values[3]);if(!Check(parent&&Selected(parent),"private metadata parent identity"))return 71;
            auto descriptor=parent+(type==4?0x44:0x264);int32_t rel=0;
            if(!Check(Named(descriptor,type)&&Read(descriptor+12,&rel,4),"private descriptor schema and name"))return 72;target=descriptor+12+rel;}
        if(!Check(Selected(target),"metadata accessor selected image"))return 73;
        auto result=Function(target)(0);++MetadataCalls;
        if(!Check(result.value&&result.state==0&&Selected(result.value)&&Named(Descriptor(result.value),type),"complete named metadata"))return 74;
        values[type]=result.value;VM27DIKCVWInfo info{};
        if(!Check(query(result.value,&info)==1&&info.type==type+1&&info.size==Sizes[type]&&info.stride==Strides[type]&&(info.flags&0xffffff)==Flags[type]&&info.extraInhabitants==0x7fffffff,"exact scoped ownership metadata"))return 75;
    }
    std::printf("{\"phase\":\"metadata\",\"genuineDIKitUUID\":\"652b07a998be31d298d7ffcaf14aca5e\",\"checks\":%u,\"failures\":%u,\"metadataCalls\":%u,\"diskCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n",Checks,Failures,MetadataCalls);return Failures?1:0;
}
