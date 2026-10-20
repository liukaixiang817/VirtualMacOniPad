// Private CPU-only probe: actual DIKit27 identity and scoped metadata closure.
// No disk-image, attach, mount, VM, GPU, IOKit, or production-app operations.
#include "modern_swift_diskimagekit_cvw_compat.h"
#include "diskimagekit_required_imports.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace {
constexpr unsigned char Identity[16]={0x65,0x2b,0x07,0xa9,0x98,0xbe,0x31,0xd2,0x98,0xd7,0xff,0xca,0xf1,0x4a,0xca,0x5e};
constexpr const char *Names[]={"ASIFCreationConfiguration","ASIFLayerCreationConfiguration","RAWCreationConfiguration","OpenConfiguration","_ResolvedCreationConfiguration","DILogger","IncompatibleStackingError","CorruptedImageError","UnsupportedFormatError"};
constexpr const char *Accessors[]={"$s12DiskImageKit25ASIFCreationConfigurationVMa","$s12DiskImageKit30ASIFLayerCreationConfigurationVMa","$s12DiskImageKit24RAWCreationConfigurationVMa","$s12DiskImageKit17OpenConfigurationVMa",nullptr,nullptr,"$s12DiskImageKit25IncompatibleStackingErrorVMa","$s12DiskImageKit09CorruptedB5ErrorVMa","$s12DiskImageKit22UnsupportedFormatErrorVMa"};
constexpr size_t Sizes[]={25,58,25,17,48,24,16,8,8};
constexpr size_t Strides[]={32,64,32,24,48,24,16,8,8};
constexpr uint32_t Flags[]={0x30007,0x30007,0x30007,0x10007,0x30007,0x10007,0x10007,0x10007,0x10007};
struct Response { const void *value; uintptr_t state; };
using Accessor=Response (__attribute__((swiftcall)) *)(uintptr_t);
using Query=int (*)(const void *,VM27DIKCVWInfo *);
unsigned Checks=0,Failures=0,MetadataCalls=0;
const void *SelectedImage=nullptr;
bool Check(bool b,const char *why) { ++Checks;if(!b){++Failures;std::printf("FAIL %s\n",why);}return b; }
bool Read(const void *p,void *d,size_t n) { vm_size_t got=0;return p&&n<=4096&&vm_read_overwrite(mach_task_self(),(vm_address_t)p,n,(vm_address_t)d,&got)==KERN_SUCCESS&&got==n; }
bool Own(const void *p,const void **base=nullptr) {
    Dl_info d{};mach_header_64 h{};
    if(!p||!dladdr(p,&d)||!Read(d.dli_fbase,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.ncmds>1024||h.sizeofcmds>65536)return false;
    auto at=(const unsigned char *)d.dli_fbase+sizeof(h),end=at+h.sizeofcmds;unsigned found=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command l{};if(at>end||end-at<8||!Read(at,&l,8)||l.cmdsize<8||l.cmdsize%8||l.cmdsize>(size_t)(end-at))return false;
        if(l.cmd==LC_UUID){uuid_command u{};if(l.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u))||std::memcmp(u.uuid,Identity,16))return false;++found;}at+=l.cmdsize;}
    if(at!=end||found!=1)return false;if(base)*base=d.dli_fbase;return true;
}
bool Selected(const void *p) {const void *base=nullptr;return Own(p,&base)&&base==SelectedImage;}
Accessor Function(const void *p) {return (Accessor)ptrauth_sign_unauthenticated((void *)ptrauth_strip(p,ptrauth_key_function_pointer),ptrauth_key_function_pointer,0);}
const unsigned char *Descriptor(const void *m) {const void *p=nullptr;if(!Read((const unsigned char *)m+8,&p,8)||!p)return nullptr;return (const unsigned char *)ptrauth_auth_data(p,ptrauth_key_process_independent_data,ptrauth_blend_discriminator((const unsigned char *)m+8,0xae86));}
bool Named(const unsigned char *d,unsigned type) {uint32_t flags=0;int32_t rel=0;char name[64]{};return Selected(d)&&Read(d,&flags,4)&&(flags&31)==17&&Read(d+8,&rel,4)&&Read(d+8+rel,name,sizeof(name))&&std::memchr(name,0,sizeof(name))&&!std::strcmp(name,Names[type]);}
}
int main(int argc,char **argv) {
    std::setvbuf(stdout,nullptr,_IONBF,0);
    if(argc!=3&&argc!=4)return 64;bool metadata=argc==4&&!std::strcmp(argv[3],"--metadata");if(argc==4&&!metadata)return 64;
    auto image=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!image){std::printf("dlopen failed: %s\n",dlerror());return 66;}
    auto identity=dlsym(image,Accessors[3]);if(!Check(Own(ptrauth_strip(identity,ptrauth_key_function_pointer),&SelectedImage),"genuine DIKit27 UUID"))return 67;
    std::printf("genuineDIKitUUID=652b07a998be31d298d7ffcaf14aca5e\n");
    unsigned missing=0;for(auto name:RequiredImports){void *p=dlsym(image,name);if(!p){++missing;std::printf("MISSING %s\n",name);}}
    if(!Check(missing==0,"all original and reconstructed strong required imports present"))return 68;
    if(!metadata){std::printf("{\"loaded\":true,\"required\":%zu,\"checks\":%u,\"failed\":%u,\"metadataCalls\":0,\"diskCalls\":0}\n",sizeof(RequiredImports)/sizeof(*RequiredImports),Checks,Failures);return 0;}
    auto provider=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);if(!provider){std::printf("provider failed: %s\n",dlerror());return 69;}
    auto query=(Query)dlsym(provider,"VM27DIKCVWQuery");if(!Check(query!=nullptr,"scoped query exists"))return 70;
    const void *values[9]{};
    for(unsigned type=0;type<9;++type){const void *target=nullptr;
        if(Accessors[type])target=ptrauth_strip(dlsym(image,Accessors[type]),ptrauth_key_function_pointer);
        else {auto parent=Descriptor(values[3]);if(!Check(parent&&Selected(parent),"private metadata parent identity"))return 71;
            auto descriptor=parent+(type==4?0x44:0x264);int32_t rel=0;
            if(!Check(Named(descriptor,type)&&Read(descriptor+12,&rel,4),"private descriptor schema and name"))return 72;target=descriptor+12+rel;}
        if(!Check(Selected(target),"metadata accessor exact selected image identity"))return 73;
        auto result=Function(target)(0);++MetadataCalls;
        if(!Check(result.value&&result.state==0&&Selected(result.value)&&Named(Descriptor(result.value),type),"complete metadata response and selected-image named descriptor"))return 74;
        values[type]=result.value;VM27DIKCVWInfo info{};
        if(!Check(query(result.value,&info)==1&&info.type==type+1&&info.size==Sizes[type]&&info.stride==Strides[type]&&(info.flags&0xffffff)==Flags[type]&&info.extraInhabitants==0x7fffffff,"scoped compact ownership metadata exact size/stride/flags/extra"))return 75;
        std::printf("type=%s size=%zu stride=%zu flags=%08x extra=%08x\n",Names[type],info.size,info.stride,info.flags,info.extraInhabitants);
    }
    std::printf("{\"loaded\":true,\"required\":%zu,\"checks\":%u,\"failed\":%u,\"metadataCalls\":%u,\"diskCalls\":0}\n",sizeof(RequiredImports)/sizeof(*RequiredImports),Checks,Failures,MetadataCalls);return Failures?1:0;
}
