// Owned RTTI/address-point and typed libc fixture. Never loads/calls VZ or a VM.
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <typeinfo>
#include <unistd.h>
#include "owner-pins.h"

struct Plain { virtual ~Plain() = default; };
struct Other { virtual ~Other() = default; };
struct Single : Plain {};
struct Multiple : Plain, Other {};
using Compare=int(*)(const char*,const char*);
static unsigned Checks=0;
static bool Check(bool result) {++Checks;return result;}
static bool Identity(const void *address,const char *path,const char *uuid,
                     uintptr_t originalBase=0,intptr_t *slide=nullptr) {
    Dl_info d{};
    if(!dladdr(address,&d)||!d.dli_fbase||!d.dli_fname||std::strcmp(d.dli_fname,path))return false;
    auto h=static_cast<const mach_header_64*>(d.dli_fbase);
    if(h->magic!=MH_MAGIC_64||h->sizeofcmds>0x100000||h->ncmds>4096)return false;
    auto at=reinterpret_cast<const unsigned char*>(h+1);auto end=at+h->sizeofcmds;bool found=false;
    for(uint32_t i=0;i<h->ncmds;++i){
        if(at+8>end)return false;auto lc=reinterpret_cast<const load_command*>(at);
        if(lc->cmdsize<8||at+lc->cmdsize>end)return false;
        if(lc->cmd==LC_UUID){if(lc->cmdsize!=24||found)return false;found=true;char actual[33]{};
            for(int k=0;k<16;++k)std::snprintf(actual+k*2,3,"%02x",at[8+k]);
            if(std::strcmp(actual,uuid))return false;
        }
        at+=lc->cmdsize;
    }
    if(at!=end||!found)return false;
    if(slide){if(!originalBase)return false;*slide=intptr_t(reinterpret_cast<uintptr_t>(h)-originalBase);}
    return true;
}
__attribute__((noinline)) static bool DynamicCastExercises(Plain *single,Plain *multi,Other *other,Plain *plain) {
    return Check(dynamic_cast<Single*>(single)!=nullptr)&&Check(dynamic_cast<Multiple*>(multi)!=nullptr)&&
        Check(dynamic_cast<Plain*>(other)==multi)&&Check(dynamic_cast<Single*>(other)==nullptr)&&
        Check(dynamic_cast<Multiple*>(plain)==nullptr)&&Check(typeid(*multi)==typeid(Multiple));
}
static int Sign(int x){return (x>0)-(x<0);}
int main(){
    alarm(10);std::setbuf(stdout,nullptr);
    struct Row{const char *symbol;const std::type_info *type;};
    Row rows[]={{"_ZTVN10__cxxabiv117__class_type_infoE",&typeid(Plain)},
                {"_ZTVN10__cxxabiv120__si_class_type_infoE",&typeid(Single)},
                {"_ZTVN10__cxxabiv121__vmi_class_type_infoE",&typeid(Multiple)},
                {"_ZTVN10__cxxabiv123__fundamental_type_infoE",&typeid(int)}};
    void *owner=dlopen("/usr/lib/libc++abi.dylib",RTLD_NOLOAD|RTLD_LAZY);if(!Check(owner!=nullptr))return 70;
    for(const auto &row:rows){
        void *table=dlsym(owner,row.symbol);if(!Check(table!=nullptr)||!Check(Identity(table,"/usr/lib/libc++abi.dylib",CPP_OWNER_UUID)))return 71;
        uintptr_t vptr=0;std::memcpy(&vptr,static_cast<const void*>(row.type),sizeof(vptr));
        uintptr_t stripped=reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(vptr),ptrauth_key_asda));
        uintptr_t authenticated=reinterpret_cast<uintptr_t>(ptrauth_auth_data(reinterpret_cast<void*>(vptr),ptrauth_key_asda,0));
        uintptr_t expected=reinterpret_cast<uintptr_t>(table)+16;
        if(!Check(stripped==expected)||!Check(authenticated==expected)||!Check(stripped!=reinterpret_cast<uintptr_t>(table))||!Check(row.type->name()[0]!=0))return 72;
        std::printf("{\"record\":\"ownedTypeInfo\",\"symbol\":\"%s\",\"addend\":16,\"DA0Authenticated\":true,\"nativeTypeIdentityPreserved\":true}\n",row.symbol);
    }
    Single single;Multiple multiple;Plain plain;
    if(!DynamicCastExercises(&single,&multiple,&multiple,&plain))return 73;
    const char empty[]="";if(!Check(empty[0]==0)||!Check(std::strlen(empty)==0))return 74;
    auto runtime=reinterpret_cast<Compare>(std::strcmp);
    void *platform=dlopen("/usr/lib/system/libsystem_platform.dylib",RTLD_NOLOAD|RTLD_LAZY);
    if(!Check(platform!=nullptr))return 75;
    void *named=dlsym(platform,"_platform_strcmp");if(!Check(named!=nullptr))return 76;
    auto raw=ptrauth_strip(named,ptrauth_key_function_pointer);
#ifndef VM27_FIXTURE_IOS
    intptr_t platformSlide=0;
    bool physicalIdentity=Check(Identity(raw,"/usr/lib/system/libsystem_platform.dylib",PLATFORM_OWNER_UUID,PLATFORM_OWNER_BASE,&platformSlide));
    bool exactTarget=physicalIdentity&&Check(reinterpret_cast<uintptr_t>(raw)==PLATFORM_FINAL_TARGET+uintptr_t(platformSlide));
    Dl_info actualOwner{};int ownerFound=dladdr(raw,&actualOwner);
    std::printf("{\"record\":\"strcmpTargetGate\",\"ownerIdentityMatches\":%s,\"namedTarget\":%llu,\"expectedSlidTarget\":%llu,\"slide\":%lld,\"exactTargetMatches\":%s,\"dladdrFound\":%s,\"symbolAddress\":%llu,\"actualVZCalls\":0,\"originalVZConsumerExecuted\":false,\"full27\":false}\n",
        physicalIdentity?"true":"false",static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(raw)),
        static_cast<unsigned long long>(PLATFORM_FINAL_TARGET+uintptr_t(platformSlide)),static_cast<long long>(platformSlide),
        exactTarget?"true":"false",ownerFound?"true":"false",static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(actualOwner.dli_saddr)));
    if(!exactTarget)return 77;
#endif
    auto exact=reinterpret_cast<Compare>(ptrauth_sign_unauthenticated(raw,ptrauth_key_function_pointer,0));
    unsigned comparisons=0;
    for(unsigned length=0;length<32;++length){
        char a[34]{},b[34]{};
        for(unsigned k=0;k<length;++k)a[k]=b[k]=char(1+(k*31+length*17)%255);
        if(!Check(exact(a,b)==0)||!Check(runtime(a,b)==0))return 78;comparisons+=2;
        b[length]=char(1+length);
        if(!Check(Sign(exact(a,b))<0)||!Check(Sign(runtime(a,b))<0)||!Check(Sign(exact(b,a))>0))return 79;comparisons+=3;
        if(length){b[length]=0;auto av=static_cast<unsigned char>(a[0]);auto bv=static_cast<unsigned char>(b[0]);b[0]=char(bv==255?1:bv+1);
            int expectedSign=av<static_cast<unsigned char>(b[0])?-1:1;
            if(!Check(Sign(exact(a,b))==expectedSign)||!Check(Sign(runtime(a,b))==expectedSign))return 80;comparisons+=2;
        }
    }
    dlclose(platform);dlclose(owner);
    std::printf("{\"record\":\"summary\",\"PID\":%d,\"checks\":%u,\"ownedRTTITypes\":4,\"ownedDynamicCastExercises\":6,\"typedStrcmpComparisons\":%u,\"nativeOriginalStrcmpFinalTargetVerified\":%s,\"originalVZConsumerExecuted\":false,\"actualVZCalls\":0,\"originalVMMExecuted\":false,\"guestInstructions\":0,\"full27\":false,\"passed\":true}\n",getpid(),Checks,comparisons,
#ifndef VM27_FIXTURE_IOS
        "true"
#else
        "false"
#endif
    );alarm(0);return 0;
}
