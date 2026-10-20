// Read-only native Swift class metadata and required-symbol inventory.
// No accessors, Swift witnesses, class methods, VM or disk operations invoked.
static const char *RequiredSwiftSymbols[]={
"$ss28__ContiguousArrayStorageBaseCMn",
"$ss28__ContiguousArrayStorageBaseC16canStoreElements13ofDynamicTypeSbypXp_tFTq",
"$ss28__ContiguousArrayStorageBaseC17staticElementTypeypXpvgTq",
"$ss28__ContiguousArrayStorageBaseC012_doNotCallMeD0AByt_tcfCTq",
"OBJC_METACLASS_$__TtCs28__ContiguousArrayStorageBase",
"OBJC_METACLASS_$_NSObject","swift_getSingletonMetadata","swift_initClassMetadata2",
"swift_deallocClassInstance","_swift_stdlib_reportUnimplementedInitializer",
"$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_SSAHSus6UInt32VtF",
"_objc_empty_cache"};
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
namespace {
bool Read(const void *p,void *d,size_t n){vm_size_t got=0;return p&&n<=4096&&vm_read_overwrite(mach_task_self(),(vm_address_t)p,n,(vm_address_t)d,&got)==KERN_SUCCESS&&got==n;}
bool Identity(const void *p,char uuid[33],const char **path,const char **symbol=nullptr) {
    Dl_info d{};mach_header_64 h{};if(!p||!dladdr(p,&d)||!Read(d.dli_fbase,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.ncmds>1024||h.sizeofcmds>65536)return false;
    auto at=(const unsigned char *)d.dli_fbase+sizeof(h),end=at+h.sizeofcmds;unsigned count=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command l{};if(at>end||end-at<8||!Read(at,&l,8)||l.cmdsize<8||l.cmdsize%8||l.cmdsize>(size_t)(end-at))return false;if(l.cmd==LC_UUID){uuid_command u{};if(l.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;for(unsigned j=0;j<16;++j)std::snprintf(uuid+j*2,3,"%02x",u.uuid[j]);++count;}at+=l.cmdsize;}
    if(at!=end||count!=1)return false;*path=d.dli_fname;if(symbol)*symbol=d.dli_sname;return true;
}
}
int main(int argc,char **argv){std::setvbuf(stdout,nullptr,_IONBF,0);if(argc!=2)return 64;auto image=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!image){std::printf("dlopen failed: %s\n",dlerror());return 66;}unsigned missing=0;
    for(auto name:RequiredSwiftSymbols){auto pointer=dlsym(image,name);char uuid[33]{};const char *path=nullptr;bool present=pointer&&Identity(ptrauth_strip(pointer,ptrauth_key_function_pointer),uuid,&path);if(!present)++missing;std::printf("SYMBOL %s present=%s ownerUUID=%s ownerPath=%s\n",name,present?"true":"false",present?uuid:"(missing)",path?path:"(missing)");}
    const char *classes[]={"$ss20__StaticArrayStorageCN","$ss28__ContiguousArrayStorageBaseCN","$ss19__EmptyArrayStorageCN"};
    for(auto name:classes){auto m=(const unsigned char *)dlsym(image,name);if(!m){std::printf("CLASS %s missing=true\n",name);continue;}char uuid[33]{};const char *path=nullptr;if(!Identity(m,uuid,&path))return 67;uint64_t data=0;uint32_t flags=0,instanceSize=0,classSize=0,addressPoint=0;uint16_t alignment=0;
        if(!Read(m+32,&data,8)||!Read(m+40,&flags,4)||!Read(m+48,&instanceSize,4)||!Read(m+52,&alignment,2)||!Read(m+56,&classSize,4)||!Read(m+60,&addressPoint,4)||addressPoint>classSize||classSize>4096)return 68;
        std::printf("CLASS %s name=%s ownerUUID=%s ownerPath=%s data=%016llx flags=%08x instanceSize=%u alignment=%u classSize=%u classAddressPoint=%u\n",name,class_getName((Class)m),uuid,path?path:"(missing)",(unsigned long long)data,flags,instanceSize,alignment,classSize,addressPoint);
        uint64_t prefix[3]{};if(addressPoint<=24&&Read(m-addressPoint,prefix,addressPoint))for(unsigned i=0;i<addressPoint/8;++i)std::printf("PREFIX %s %d raw=%016llx\n",name,int(i*8)-int(addressPoint),(unsigned long long)prefix[i]);
        size_t extent=classSize-addressPoint;size_t bytes=extent<512?extent:512;uint64_t words[64]{};if(!Read(m,words,bytes))return 69;
        for(unsigned i=0;i<bytes/8;++i){char own[33]{};const char *owner=nullptr,*symbol=nullptr;auto plain=ptrauth_strip((const void *)(uintptr_t)words[i],ptrauth_key_function_pointer);bool found=Identity(plain,own,&owner,&symbol);std::printf("WORD %s +%u raw=%016llx stripped=%016llx ownerUUID=%s ownerSymbol=%s\n",name,i*8,(unsigned long long)words[i],(unsigned long long)(uintptr_t)plain,found?own:"(none)",symbol?symbol:"(none)");}
        const void *description=nullptr;if(Read(m+64,&description,8)&&description){auto descriptor=(const unsigned char *)ptrauth_strip(description,ptrauth_key_process_independent_data);uint32_t descriptorFlags=0;int32_t rel=0;char descriptionName[128]{};if(Read(descriptor,&descriptorFlags,4)&&Read(descriptor+8,&rel,4)&&Read(descriptor+8+rel,descriptionName,sizeof(descriptionName))&&std::memchr(descriptionName,0,sizeof(descriptionName))){std::printf("DESCRIPTOR %s flags=%08x name=%s\n",name,descriptorFlags,descriptionName);uint32_t descriptorWords[40]{};if(Read(descriptor,descriptorWords,sizeof(descriptorWords)))for(unsigned i=0;i<40;++i){const void *target=descriptor+i*4+int32_t(descriptorWords[i]);char id[33]{};const char *own=nullptr,*sym=nullptr;bool found=Identity(target,id,&own,&sym);std::printf("DESCWORD %s +%u raw=%08x relativeTarget=%016llx ownerUUID=%s ownerSymbol=%s\n",name,i*4,descriptorWords[i],(unsigned long long)(uintptr_t)target,found?id:"(none)",sym?sym:"(none)");}}}
    }
    std::printf("{\"requiredSwiftSymbols\":%zu,\"missing\":%u,\"classCount\":3,\"accessorCalls\":0,\"actualMethodCalls\":0,\"diskCalls\":0,\"vmCalls\":0,\"gpuCalls\":0}\n",sizeof(RequiredSwiftSymbols)/sizeof(*RequiredSwiftSymbols),missing);return 0;
}
