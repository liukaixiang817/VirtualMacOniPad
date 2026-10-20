// Call the installed macOS27 libc++ directly. No private runtime loaded.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <initializer_list>
#include <mach-o/loader.h>
#include <ptrauth.h>
static void UUID(const void *base,char hex[33]) {
    const auto *h=static_cast<const mach_header_64*>(base);if(!h || h->magic!=MH_MAGIC_64) __builtin_trap();
    auto *p=reinterpret_cast<const unsigned char*>(h+1);unsigned at=0,n=0;
    for(unsigned i=0;i<h->ncmds;++i) {
        load_command c;std::memcpy(&c,p+at,8);
        if(c.cmdsize<8 || c.cmdsize>h->sizeofcmds-at) __builtin_trap();
        if(c.cmd==LC_UUID) {++n;for(unsigned j=0;j<16;++j) std::snprintf(hex+j*2,3,"%02x",p[at+8+j]);}
        at+=c.cmdsize;
    }
    if(n!=1 || at!=h->sizeofcmds) __builtin_trap();
}
int main() {
    void *handle=dlopen("/usr/lib/libc++.1.dylib",RTLD_NOW|RTLD_LOCAL);if(!handle) return 78;
    void *entry=dlsym(handle,"_ZNSt3__113__hash_memoryEPKvm");
    void *del=dlsym(handle,"_ZdlPv");Dl_info h={},d={};
    if(!entry || !del || !dladdr(ptrauth_strip(entry,ptrauth_key_function_pointer),&h) ||
        !dladdr(ptrauth_strip(del,ptrauth_key_function_pointer),&d)) return 78;
    if(std::strcmp(h.dli_fname,"/usr/lib/libc++.1.dylib") || std::strcmp(d.dli_fname,"/usr/lib/libc++abi.dylib")) return 78;
    char hu[33]={},du[33]={};UUID(h.dli_fbase,hu);UUID(d.dli_fbase,du);
    std::printf("{\"nativeHashUUID\":\"%s\",\"nativeHashRVA\":%llu,\"nativeDeletePath\":\"%s\",\"nativeDeleteUUID\":\"%s\",\"nativeDeleteRVA\":%llu,\"hashes\":[",
        hu,(unsigned long long)((uintptr_t)ptrauth_strip(entry,ptrauth_key_function_pointer)-(uintptr_t)h.dli_fbase),
        d.dli_fname,du,(unsigned long long)((uintptr_t)ptrauth_strip(del,ptrauth_key_function_pointer)-(uintptr_t)d.dli_fbase));
    auto hash=reinterpret_cast<size_t(*)(const void*,size_t)>(entry);unsigned char bytes[257];
    for(unsigned i=0;i<sizeof(bytes);++i) bytes[i]=static_cast<unsigned char>(i*37+11);
    unsigned count=0;
    for(unsigned offset:{0u,1u,7u}) for(unsigned size:{0u,1u,3u,7u,8u,15u,16u,17u,31u,32u,33u,63u,64u,65u,127u,128u,129u,250u})
        std::printf("%s{\"offset\":%u,\"length\":%u,\"value\":%llu}",count++?",":"",offset,size,(unsigned long long)hash(bytes+offset,size));
    std::printf("]}\n");dlclose(handle);return 0;
}
