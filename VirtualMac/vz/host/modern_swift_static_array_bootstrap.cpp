// Private, bounded transaction for the exact DIKit27 three static-array ISAs.
// No DIKit accessor, array operation, disk, VM or GPU API is called here.
#include "modern_swift_static_array_bootstrap.h"
#include "diskimagekit_bootstrap_required_imports.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <ptrauth.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

#if !defined(VM27_DIKit_SHA) || !defined(VM27_FACTORY_SHA) || !defined(VM27_FACTORY_UUID)
#error "Build must pin exact audited image and real completed-metadata factory"
#endif
extern char **environ;
extern "C" alignas(16) const unsigned char VM27StaticArrayUninitializedISA[16] = {
    'V','M','2','7','-','N','O','T','-','M','E','T','A','D','A','T'
};
namespace {
constexpr uintptr_t Offsets[] = {0x181a0,0x183f8,0x18618};
constexpr uint64_t Counts[] = {2,2,1};
constexpr uint64_t Capacities[] = {4,4,2};
constexpr const char *DIKitUUID="652b07a998be31d298d7ffcaf14aca5e";
bool Read(const void *p,void *out,size_t bytes) {
    vm_size_t got=0;
    return p&&bytes<=65536&&vm_read_overwrite(mach_task_self(),(vm_address_t)p,bytes,(vm_address_t)out,&got)==KERN_SUCCESS&&got==bytes;
}
bool UUID(const void *header,char uuid[33]) {
    mach_header_64 h{};
    if(!Read(header,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.cputype!=CPU_TYPE_ARM64||h.cpusubtype!=(cpu_subtype_t)0x80000002||!h.ncmds||h.ncmds>1024||h.sizeofcmds>65536)return false;
    const auto *at=(const unsigned char *)header+sizeof(h),*end=at+h.sizeofcmds;
    unsigned found=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command c{};if(end-at<8||!Read(at,&c,8)||c.cmdsize<8||c.cmdsize%8||c.cmdsize>size_t(end-at))return false;
        if(c.cmd==LC_UUID){uuid_command u{};if(c.cmdsize!=sizeof(u)||!Read(at,&u,sizeof(u)))return false;for(unsigned j=0;j<16;++j)std::snprintf(uuid+j*2,3,"%02x",u.uuid[j]);++found;}at+=c.cmdsize;}
    return at==end&&found==1;
}
bool Owner(const void *pointer,const char *uuid,const char *path,const void **header=nullptr) {
    Dl_info info{};char actualUUID[33]{},canonical[PATH_MAX]{},expected[PATH_MAX]{};
    if(!pointer||!dladdr(pointer,&info)||!UUID(info.dli_fbase,actualUUID)||std::strcmp(actualUUID,uuid)||!realpath(path,expected)||!realpath(info.dli_fname,canonical)||std::strcmp(expected,canonical))return false;
    if(header)*header=info.dli_fbase;return true;
}
bool FilePin(const char *path,const char *expected) {
    int descriptor=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(descriptor<0)return false;
    struct stat s{};bool ok=fstat(descriptor,&s)==0&&S_ISREG(s.st_mode)&&s.st_size>=4096&&s.st_size<=4*1024*1024;
    CC_SHA256_CTX context{};CC_SHA256_Init(&context);unsigned char buffer[16384]{};
    off_t cursor=0;
    while(ok&&cursor<s.st_size){size_t n=size_t(s.st_size-cursor);if(n>sizeof(buffer))n=sizeof(buffer);ssize_t got=pread(descriptor,buffer,n,cursor);if(got!=ssize_t(n)){ok=false;break;}CC_SHA256_Update(&context,buffer,(CC_LONG)n);cursor+=got;}
    unsigned char digest[32]{};CC_SHA256_Final(digest,&context);close(descriptor);char hex[65]{};for(unsigned i=0;i<32;++i)std::snprintf(hex+i*2,3,"%02x",digest[i]);return ok&&!std::strcmp(hex,expected);
}
bool SingleThreaded() {
    if(!pthread_main_np())return false;
    thread_act_array_t threads=nullptr;mach_msg_type_number_t count=0;
    if(task_threads(mach_task_self(),&threads,&count)!=KERN_SUCCESS)return false;
    for(mach_msg_type_number_t i=0;i<count;++i)mach_port_deallocate(mach_task_self(),threads[i]);
    vm_deallocate(mach_task_self(),(vm_address_t)threads,count*sizeof(thread_t));return count==1;
}
bool CleanEnvironment() {
    for(char **p=environ;p&&*p;++p)if(!std::strncmp(*p,"OBJC_",5)||!std::strncmp(*p,"DYLD_",5))return false;
    return true;
}
bool ImageShape(const void *header) {
    mach_header_64 h{};if(!Read(header,&h,sizeof(h)))return false;
    const auto *at=(const unsigned char *)header+sizeof(h);unsigned owned=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command c{};if(!Read(at,&c,8))return false;
        if(c.cmd==LC_ROUTINES||c.cmd==LC_ROUTINES_64)return false;
        if(c.cmd==LC_SEGMENT_64){segment_command_64 g{};if(!Read(at,&g,sizeof(g))||c.cmdsize!=sizeof(g)+g.nsects*sizeof(section_64)||g.nsects>128)return false;
            for(unsigned j=0;j<g.nsects;++j){section_64 s{};if(!Read(at+sizeof(g)+j*sizeof(s),&s,sizeof(s)))return false;
                for(const char *name: {"__mod_init_func","__init_offsets","__objc_nlclslist","__objc_nlcatlist","__objc_catlist","__objc_catlist2","__objc_stublist","__swift5_replace","__swift5_replac2","__swift5_ac_func","__swift5_ac_p_fu"})if(s.size&&!std::strncmp(s.sectname,name,16))return false;
                if(!std::strncmp(g.segname,"__AUTH_CONST",16)&&!std::strncmp(s.sectname,"__const",16)){if(s.addr!=0x100018000||s.size<0x638||(g.initprot&VM_PROT_EXECUTE)||(g.maxprot&VM_PROT_EXECUTE))return false;++owned;}
            }}at+=c.cmdsize;
    }return owned==1;
}
// Both public SDKs declare these MIG routines with native vm_address_t. On
// these arm64e targets it must represent the complete 64-bit address/size.
static_assert(sizeof(vm_address_t)==8&&sizeof(vm_size_t)==8,"64-bit VM APIs required");
bool Protection(vm_address_t page,vm_size_t bytes,vm_prot_t *protection,vm_prot_t *maximum) {
    vm_address_t address=page;vm_size_t size=0;vm_region_basic_info_data_64_t info{};mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t object=MACH_PORT_NULL;
    kern_return_t status=vm_region_64(mach_task_self(),&address,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object);
    if(object)mach_port_deallocate(mach_task_self(),object);
    if(status!=KERN_SUCCESS||count!=VM_REGION_BASIC_INFO_COUNT_64||address>page||size<bytes||page-address>size-bytes)return false;
    *protection=info.protection;*maximum=info.max_protection;return true;
}
void *Authenticate(const void *signedPointer,const void *slot) {
    // Direct equality against the expected raw pointer follows real autda.
    // Stripping a pointer is deliberately not accepted as authentication.
    return ptrauth_auth_data((void *)signedPointer,ptrauth_key_process_independent_data,ptrauth_blend_discriminator(slot,0x6ae1));
}
[[noreturn]] void RecoveryFailure() {
    // A failed protection/ISA rollback cannot be reported as a reusable load.
    std::fprintf(stderr,"VM27 bootstrap recovery failed; terminating isolated process\n");_exit(90);
}
}
extern "C" int VM27StaticArrayBootstrapLoad(const char *imagePath,const char *factoryPath,unsigned failureAfterWrite,VM27StaticArrayBootstrapReport *out,void **publishedImage) {
    if(!out||!publishedImage)return 64;
    *out={};*publishedImage=nullptr;
    auto fail=[&](unsigned stage){out->failureStage=stage;return int(stage);};
    if(!imagePath||!factoryPath||failureAfterWrite>3||!CleanEnvironment()||!SingleThreaded())return fail(65);out->checks+=2;
    if(!FilePin(imagePath,VM27_DIKit_SHA)||!FilePin(factoryPath,VM27_FACTORY_SHA))return fail(66);out->checks+=2;
    if(void *already=dlopen(imagePath,RTLD_NOW|RTLD_LOCAL|RTLD_NOLOAD)){dlclose(already);return fail(67);}++out->checks;
    void *core=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);if(!core)return fail(68);
    const auto *base=(const unsigned char *)dlsym(core,"$ss28__ContiguousArrayStorageBaseCN");
    const auto *baseDescriptor=(const unsigned char *)dlsym(core,"$ss28__ContiguousArrayStorageBaseCMn");Dl_info coreOwner{};char coreUUID[33]{};
    if(!base||!baseDescriptor||!dladdr(base,&coreOwner)||!UUID(coreOwner.dli_fbase,coreUUID)||
       (std::strcmp(coreUUID,"f896d145e02539d6afd3bc0a2ad4f839")&&std::strcmp(coreUUID,"c9b36da7bb3435afbc5d91ecbcaa9ed0")))return fail(69);
    out->checks+=3;
    uint32_t descriptorWords[23]{};if(!Read(baseDescriptor,descriptorWords,sizeof(descriptorWords))||descriptorWords[0]!=0xc0000050||descriptorWords[10]!=12||descriptorWords[11]!=13||descriptorWords[12]!=5||descriptorWords[13]!=0x734f0001||descriptorWords[15]!=0xb6080010||descriptorWords[17]!=0x4a020010||descriptorWords[19]!=0x4d6c0010||descriptorWords[21]!=0xaa860012)return fail(70);out->checks+=9;
    void *factoryImage=dlopen(factoryPath,RTLD_NOW|RTLD_LOCAL);if(!factoryImage)return fail(71);
    using Factory=const void *(*)(void);auto factory=(Factory)dlsym(factoryImage,"VM27StaticArrayMetadataOracle");
    if(!factory||!Owner(ptrauth_strip((void *)factory,ptrauth_key_function_pointer),VM27_FACTORY_UUID,factoryPath))return fail(72);++out->checks;
    const auto *metadata=(const unsigned char *)factory();++out->factoryCalls;uint64_t words[19]{};
    if(!Read(metadata,words,sizeof(words))||class_getSuperclass((Class)metadata)!=(Class)base||std::strcmp(class_getName((Class)metadata),"VM27StaticArray.VM27StaticArrayStorage")||uint32_t(words[6])!=32||(words[6]>>32&65535)!=7)return fail(73);out->checks+=4;
    const void *actualDescriptor=ptrauth_auth_data((const void *)(uintptr_t)words[8],ptrauth_key_process_independent_data,ptrauth_blend_discriminator(metadata+64,0xae86));
    if(!Owner(actualDescriptor,VM27_FACTORY_UUID,factoryPath))return fail(74);++out->checks;
    if(!SingleThreaded())return fail(75);++out->checks;
    // No DIKit code has run. Its audited image has no eager initializer/load
    // paths. Do not enumerate or look up its classes while sentinels are bound.
    void *image=dlopen(imagePath,RTLD_NOW|RTLD_LOCAL);if(!image){std::fprintf(stderr,"DIKit dlopen: %s\n",dlerror());return fail(76);}
    auto identity=ptrauth_strip(dlsym(image,"$s12DiskImageKit17OpenConfigurationVMa"),ptrauth_key_function_pointer);const void *header=nullptr;
    if(!Owner(identity,DIKitUUID,imagePath,&header)||!ImageShape(header)){dlclose(image);return fail(77);}out->checks+=2;
    for(const char *name:RequiredImports){if(!dlsym(image,name)){std::fprintf(stderr,"Missing required import %s\n",name);dlclose(image);return fail(78);}++out->requiredImports;++out->checks;}
    // The exact original cache and compiler oracle distinguish these protocol
    // requirements from class MethodDescriptor pointers. Their DA discriminator
    // is 0x7d4c, not the class override's 0x675a and not a plain data pointer.
    for(const auto &binding:RequirementBindings){
        const auto *slot=(const unsigned char *)header+binding.offset;
        const void *signedPointer=nullptr;
        void *expected=dlsym(image,binding.symbol);
        if(!expected||!Read(slot,&signedPointer,sizeof(signedPointer))||
           ptrauth_auth_data(signedPointer,ptrauth_key_process_independent_data,
                             ptrauth_blend_discriminator(slot,0x7d4c))!=expected){dlclose(image);return fail(78);}
        ++out->requirementBindingsAuthenticated;++out->checks;
    }
    if(dlsym(image,"VM27StaticArrayUninitializedISA")!=(const void *)VM27StaticArrayUninitializedISA||!SingleThreaded()){dlclose(image);return fail(79);}out->checks+=2;
    uintptr_t original[3]{};void **slots[3]{};
    for(unsigned i=0;i<3;++i){slots[i]=(void **)((unsigned char *)header+Offsets[i]);uint64_t object[4]{};
        if(!Read(slots[i],object,sizeof(object))||object[1]!=0x80000004ffffffffull||object[2]!=Counts[i]||object[3]!=Capacities[i]||Authenticate((void *)(uintptr_t)object[0],slots[i])!=(void *)VM27StaticArrayUninitializedISA){dlclose(image);return fail(80);}original[i]=object[0];++out->authenticatedBefore;out->checks+=4;}
    vm_size_t pageSize=0;if(host_page_size(mach_host_self(),&pageSize)!=KERN_SUCCESS||pageSize!=16384){dlclose(image);return fail(81);}
    vm_address_t page=(vm_address_t)slots[0]&~(vm_address_t)(pageSize-1);
    if(((vm_address_t)slots[2]&~(vm_address_t)(pageSize-1))!=page){dlclose(image);return fail(82);}++out->checks;
    vm_prot_t before=0,maximum=0;
    if(!Protection(page,pageSize,&before,&maximum)){dlclose(image);return fail(83);}
    out->pageProtectionBefore=before;out->pageMaximumBefore=maximum;
    // VM regions may have an all-rights maximum despite the verified Mach-O
    // segment's non-executable maximum. Never add execute to current rights;
    // preserve the actual original maximum rather than guessing it from the LC.
    if((before&VM_PROT_EXECUTE)||!(before&VM_PROT_READ)||!(maximum&VM_PROT_WRITE)){dlclose(image);return fail(83);}
    ++out->checks;
    if(vm_protect(mach_task_self(),page,pageSize,FALSE,before|VM_PROT_WRITE)!=KERN_SUCCESS){dlclose(image);return fail(84);}out->pagesChanged=1;
    unsigned written=0;bool injected=false;
    for(unsigned i=0;i<3;++i){*slots[i]=ptrauth_sign_unauthenticated((void *)metadata,ptrauth_key_process_independent_data,ptrauth_blend_discriminator(slots[i],0x6ae1));++written;
        if(Authenticate(*slots[i],slots[i])!=(void *)metadata)break;++out->authenticatedAfter;++out->checks;
        if(failureAfterWrite==written){injected=true;break;}}
    vm_prot_t after=0,afterMax=0;
    bool complete=written==3&&out->authenticatedAfter==3&&!injected;
    bool restored=vm_protect(mach_task_self(),page,pageSize,FALSE,before)==KERN_SUCCESS&&Protection(page,pageSize,&after,&afterMax)&&after==before&&afterMax==maximum;
    if(!complete||!restored){
        if(!restored&&vm_protect(mach_task_self(),page,pageSize,FALSE,before|VM_PROT_WRITE)!=KERN_SUCCESS)RecoveryFailure();
        if(restored&&vm_protect(mach_task_self(),page,pageSize,FALSE,before|VM_PROT_WRITE)!=KERN_SUCCESS)RecoveryFailure();
        for(unsigned i=0;i<3;++i){*slots[i]=(void *)original[i];if(Authenticate(*slots[i],slots[i])!=(void *)VM27StaticArrayUninitializedISA)RecoveryFailure();++out->rollbackAuthenticated;}
        out->rolledBack=1;
        if(vm_protect(mach_task_self(),page,pageSize,FALSE,before)!=KERN_SUCCESS||!Protection(page,pageSize,&after,&afterMax)||after!=before||afterMax!=maximum)RecoveryFailure();
        out->protectionRestored=1;out->pageProtectionAfter=after;out->pageMaximumAfter=afterMax;dlclose(image);return fail(injected?85:86);
    }
    out->protectionRestored=1;out->pageProtectionAfter=after;out->pageMaximumAfter=afterMax;
    for(unsigned i=0;i<3;++i){uint64_t object[4]{};if(!Read(slots[i],object,sizeof(object))||Authenticate((void *)(uintptr_t)object[0],slots[i])!=(void *)metadata||object[1]!=0x80000004ffffffffull||object[2]!=Counts[i]||object[3]!=Capacities[i])RecoveryFailure();out->checks+=4;}
    // Genuine Swift metadata and the restored original protection now precede
    // handle publication. The provider/factory remain loaded for its lifetime.
    *publishedImage=image;out->handlePublished=1;return 0;
}
