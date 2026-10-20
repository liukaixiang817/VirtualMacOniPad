// Read-only Objective-C metadata comparison. No methods are invoked.
#include "diskimagekit_di2_required_methods.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <cstdio>
#include <cstring>

namespace {
bool Read(const void *p,void *d,size_t n) {vm_size_t copied=0;return p&&n<=4096&&vm_read_overwrite(mach_task_self(),(vm_address_t)p,n,(vm_address_t)d,&copied)==KERN_SUCCESS&&copied==n;}
bool Identity(const void *p,char uuid[33],const char **path) {
    Dl_info d{};mach_header_64 h{};if(!p||!dladdr(p,&d)||!Read(d.dli_fbase,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.ncmds>1024||h.sizeofcmds>65536)return false;
    auto at=(const unsigned char *)d.dli_fbase+sizeof(h),end=at+h.sizeofcmds;unsigned count=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command l{};if(at>end||end-at<8||!Read(at,&l,8)||l.cmdsize<8||l.cmdsize%8||l.cmdsize>(size_t)(end-at))return false;if(l.cmd==LC_UUID){uuid_command u{};if(l.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;for(unsigned j=0;j<16;++j)std::snprintf(uuid+j*2,3,"%02x",u.uuid[j]);++count;}at+=l.cmdsize;}
    if(at!=end||count!=1)return false;*path=d.dli_fname;return true;
}
}
int main(int argc,char **argv) {
    std::setvbuf(stdout,nullptr,_IONBF,0);if(argc!=2)return 64;
    auto image=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!image){std::printf("dlopen failed: %s\n",dlerror());return 66;}
    unsigned checks=0,failures=0;
    const char *classes[]={"DICreateASIFParams","DICreateRAWParams","DIDiskImageBridge","DIImageHandle","DIOpenParams"};
    for(auto name:classes){char symbol[128]{};std::snprintf(symbol,sizeof(symbol),"OBJC_CLASS_$_%s",name);auto exported=(Class)dlsym(image,symbol);auto actual=(Class)objc_getClass(name);char uuid[33]{};const char *path=nullptr;++checks;
        if(!actual||actual!=exported||!Identity((const void *)actual,uuid,&path)){++failures;std::printf("MISSING_CLASS %s\n",name);continue;}
        auto parent=class_getSuperclass(actual);std::printf("CLASS %s size=%zu super=%s ownerUUID=%s ownerPath=%s\n",name,class_getInstanceSize(actual),parent?class_getName(parent):"(nil)",uuid,path?path:"(nil)");}
    for(auto &row:RequiredMethods){auto c=(Class)objc_getClass(row.className);auto method=c?class_getInstanceMethod(c,sel_registerName(row.selector)):nullptr;auto actual=method?method_getTypeEncoding(method):nullptr;++checks;
        bool same=actual&&!std::strcmp(actual,row.encoding);if(!same)++failures;
        std::printf("METHOD %s %s match=%s expected=%s actual=%s\n",row.className,row.selector,same?"true":"false",row.encoding,actual?actual:"(missing)");}
    std::printf("{\"checks\":%u,\"failed\":%u,\"requiredMethods\":%zu,\"actualMethodCalls\":0,\"diskCalls\":0,\"vmCalls\":0,\"gpuCalls\":0,\"abiStringsOnly\":true}\n",checks,failures,sizeof(RequiredMethods)/sizeof(*RequiredMethods));return failures?1:0;
}
