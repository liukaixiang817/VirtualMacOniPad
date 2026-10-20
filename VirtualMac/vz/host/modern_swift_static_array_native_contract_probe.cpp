// Read-only native Swift class metadata and required-symbol inventory.
// No accessors, Swift witnesses, class methods, VM or disk operations invoked.
#include "static_array_required_swift_symbols.h"
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
        size_t extent=classSize-addressPoint;size_t bytes=extent<512?extent:512;uint64_t words[64]{};if(!Read(m,words,bytes))return 69;
        for(unsigned i=0;i<bytes/8;++i){char own[33]{};const char *owner=nullptr,*symbol=nullptr;auto plain=ptrauth_strip((const void *)(uintptr_t)words[i],ptrauth_key_function_pointer);bool found=Identity(plain,own,&owner,&symbol);std::printf("WORD %s +%u raw=%016llx stripped=%016llx ownerUUID=%s ownerSymbol=%s\n",name,i*8,(unsigned long long)words[i],(unsigned long long)(uintptr_t)plain,found?own:"(none)",symbol?symbol:"(none)");}
        const void *description=nullptr;if(Read(m+64,&description,8)&&description){auto descriptor=(const unsigned char *)ptrauth_strip(description,ptrauth_key_process_independent_data);uint32_t descriptorFlags=0;int32_t rel=0;char descriptionName[128]{};if(Read(descriptor,&descriptorFlags,4)&&Read(descriptor+8,&rel,4)&&Read(descriptor+8+rel,descriptionName,sizeof(descriptionName))&&std::memchr(descriptionName,0,sizeof(descriptionName)))std::printf("DESCRIPTOR %s flags=%08x name=%s\n",name,descriptorFlags,descriptionName);}
    }
    std::printf("{\"requiredSwiftSymbols\":%zu,\"missing\":%u,\"classCount\":3,\"accessorCalls\":0,\"actualMethodCalls\":0,\"diskCalls\":0,\"vmCalls\":0,\"gpuCalls\":0}\n",sizeof(RequiredSwiftSymbols)/sizeof(*RequiredSwiftSymbols),missing);return 0;
}
