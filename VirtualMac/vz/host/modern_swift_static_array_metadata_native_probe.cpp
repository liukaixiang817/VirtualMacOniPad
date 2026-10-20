// CPU-only completed-class-metadata probe. Never loads DIKit or edits a VM.
// No static array object, array element, witness or virtual method is invoked.
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <limits.h>
#include <initializer_list>
#ifndef VM27_STATIC_LIBRARY_UUID
#error "Builder must pin the exact completed-metadata provider UUID"
#endif
namespace {
bool Read(const void *p,void *d,size_t n){vm_size_t got=0;return p&&n<=65536&&vm_read_overwrite(mach_task_self(),(vm_address_t)p,n,(vm_address_t)d,&got)==KERN_SUCCESS&&got==n;}
bool UUID(const void *p,char uuid[33]){
 mach_header_64 h{};if(!Read(p,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.cputype!=CPU_TYPE_ARM64||h.cpusubtype!=(cpu_subtype_t)0x80000002||!h.ncmds||h.ncmds>1024||h.sizeofcmds>65536)return false;
 const auto *at=(const unsigned char *)p+sizeof(h),*end=at+h.sizeofcmds;unsigned count=0;
 for(unsigned i=0;i<h.ncmds;++i){load_command c{};if(end-at<8||!Read(at,&c,8)||c.cmdsize<8||c.cmdsize%8||c.cmdsize>size_t(end-at))return false;if(c.cmd==LC_UUID){uuid_command u{};if(c.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;for(unsigned j=0;j<16;++j)std::snprintf(uuid+j*2,3,"%02x",u.uuid[j]);++count;}at+=c.cmdsize;}
 return at==end&&count==1;
}
bool Owner(const void *p,const char *expected,const void **header=nullptr){Dl_info d{};char uuid[33]{};if(!p||!dladdr(p,&d)||!UUID(d.dli_fbase,uuid)||std::strcmp(uuid,expected))return false;if(header)*header=d.dli_fbase;return true;}
}
int main(int argc,char **argv){
 std::setvbuf(stdout,nullptr,_IONBF,0);if(argc!=2)return 64;
 auto core=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);if(!core)return 65;
 auto *base=(const unsigned char *)dlsym(core,"$ss28__ContiguousArrayStorageBaseCN");
 auto *description=(const unsigned char *)dlsym(core,"$ss28__ContiguousArrayStorageBaseCMn");
 Dl_info coreOwner{};char coreUUID[33]{};
 if(!base||!description||!dladdr(base,&coreOwner)||!UUID(coreOwner.dli_fbase,coreUUID))return 66;
 unsigned prefix=0;
 if(!std::strcmp(coreUUID,"f896d145e02539d6afd3bc0a2ad4f839"))prefix=16;
 else if(!std::strcmp(coreUUID,"c9b36da7bb3435afbc5d91ecbcaa9ed0"))prefix=24;
 else return 67;
 if(!Owner(description,coreUUID))return 68;
 unsigned checks=2;uint32_t words[23]{};
 if(!Read(description,words,sizeof(words))||words[0]!=0xc0000050||words[10]!=12||words[11]!=13||words[12]!=5||words[13]!=0x734f0001||words[15]!=0xb6080010||words[17]!=0x4a020010||words[19]!=0x4d6c0010||words[21]!=0xaa860012)return 69;checks+=9;
 // Stock schema and identity have passed before the private image is loaded.
 auto lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!lib){std::fprintf(stderr,"dlopen: %s\n",dlerror());return 70;}
 using Factory=const void *(*)(void);
 auto factory=(Factory)dlsym(lib,"VM27StaticArrayMetadataOracle");
 auto nilFunction=ptrauth_strip(dlsym(lib,"VM27StaticArrayVerbatimNil"),ptrauth_key_function_pointer);
 auto forbidden=ptrauth_strip(dlsym(lib,"VM27StaticArrayForbiddenBridge"),ptrauth_key_function_pointer);
 const void *providerHeader=nullptr;Dl_info loaded{};char expected[PATH_MAX]{},actual[PATH_MAX]{};
 if(!factory||!nilFunction||!forbidden||!Owner(ptrauth_strip((void *)factory,ptrauth_key_function_pointer),VM27_STATIC_LIBRARY_UUID,&providerHeader)||!Owner(nilFunction,VM27_STATIC_LIBRARY_UUID)||!Owner(forbidden,VM27_STATIC_LIBRARY_UUID)||!dladdr(nilFunction,&loaded)||!realpath(argv[1],expected)||!realpath(loaded.dli_fname,actual)||std::strcmp(expected,actual))return 71;checks+=4;
 auto *m=(const unsigned char *)factory();
 uint64_t metadata[19]{};
 if(!Read(m,metadata,sizeof(metadata)))return 72;
 const auto *desc=(const unsigned char *)ptrauth_auth_data((const void *)(uintptr_t)metadata[8],ptrauth_key_process_independent_data,ptrauth_blend_discriminator(m+64,0xae86));
 if(desc!=ptrauth_strip(desc,ptrauth_key_process_independent_data)||!Owner(desc,VM27_STATIC_LIBRARY_UUID))return 73;++checks;
 if(class_getSuperclass((Class)m)!=(Class)base)return 74;++checks;
 if(std::strcmp(class_getName((Class)m),"VM27StaticArray.VM27StaticArrayStorage"))return 75;++checks;
 for(unsigned i=0;i<100;++i){if(factory()!=m)return 76;++checks;}
 if((metadata[6]&0xffffffff)!=32||(metadata[6]>>32&0xffff)!=7||unsigned(metadata[7]>>32)!=prefix||unsigned(metadata[7])!=prefix+152)return 77;checks+=4;
 if(ptrauth_strip((void *)(uintptr_t)metadata[14],ptrauth_key_function_pointer)!=nilFunction||ptrauth_strip((void *)(uintptr_t)metadata[15],ptrauth_key_function_pointer)!=forbidden)return 78;checks+=2;
 for(unsigned index: {13u,14u,15u,16u,17u,18u}){if(!Owner(ptrauth_strip((void *)(uintptr_t)metadata[index],ptrauth_key_function_pointer),VM27_STATIC_LIBRARY_UUID))return 79;++checks;}
 std::printf("{\"checks\":%u,\"failures\":0,\"externalFactoryCalls\":101,\"coreUUID\":\"%s\",\"providerUUID\":\"%s\",\"className\":\"%s\",\"instanceSize\":32,\"alignment\":7,\"classAddressPoint\":%u,\"realSuperclass\":true,\"privateBridgeSlots\":2,\"actualVirtualMethodCalls\":0,\"staticArrayObjects\":0,\"diskCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n",checks,coreUUID,VM27_STATIC_LIBRARY_UUID,class_getName((Class)m),prefix);
 return 0;
}
