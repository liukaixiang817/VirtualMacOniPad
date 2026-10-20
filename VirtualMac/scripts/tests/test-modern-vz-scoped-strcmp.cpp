// Only this fixture's strings call the app-private provider. Never loads VZ.
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <unistd.h>
#include "provider-pins.h"

using Compare=int(*)(const char*,const char*);
static unsigned Checks=0,Comparisons=0;
static bool Check(bool result){++Checks;return result;}
static int Sign(int value){return (value>0)-(value<0);}
static bool Identity(void *target,const char *path){
    Dl_info d{};if(!dladdr(target,&d)||d.dli_saddr!=target||!d.dli_fname||!d.dli_fbase)return false;
    char actual[PATH_MAX]{},expected[PATH_MAX]{};
    if(!realpath(d.dli_fname,actual)||!realpath(path,expected)||std::strcmp(actual,expected))return false;
    auto h=static_cast<const mach_header_64*>(d.dli_fbase);
    if(h->magic!=MH_MAGIC_64||h->sizeofcmds>65536||h->ncmds>256)return false;
    auto at=reinterpret_cast<const unsigned char*>(h+1);auto end=at+h->sizeofcmds;bool found=false;
    for(uint32_t i=0;i<h->ncmds;++i){
        if(at+8>end)return false;auto command=reinterpret_cast<const load_command*>(at);
        if(command->cmdsize<8||at+command->cmdsize>end)return false;
        if(command->cmd==LC_UUID){if(found||command->cmdsize!=24)return false;found=true;
            char uuid[33]{};for(int k=0;k<16;++k)std::snprintf(uuid+k*2,3,"%02x",at[8+k]);
            if(std::strcmp(uuid,PROVIDER_UUID))return false;
        }at+=command->cmdsize;
    }return found&&at==end;
}
static bool Pair(Compare function,const char *a,const char *b,int expected){
    ++Comparisons;return Check(Sign(function(a,b))==expected)&&Check(Sign(std::strcmp(a,b))==expected);
}
int main(int argc,char **argv){
    alarm(10);std::setbuf(stdout,nullptr);if(argc!=2)return 70;
    void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!Check(h!=nullptr))return 71;
    void *named=dlsym(h,"_platform_strcmp");if(!Check(named!=nullptr))return 72;
    auto raw=ptrauth_strip(named,ptrauth_key_function_pointer);
    if(!Check(Identity(raw,argv[1])))return 73;
    auto exact=reinterpret_cast<Compare>(ptrauth_sign_unauthenticated(raw,ptrauth_key_function_pointer,0));
    for(unsigned n=0;n<32;++n){
        char a[34]{},b[34]{};for(unsigned k=0;k<n;++k)a[k]=b[k]=char(1+(k*31+n*17)%255);
        if(!Pair(exact,a,b,0))return 74;
        b[n]=char(1+n);if(!Pair(exact,a,b,-1)||!Pair(exact,b,a,1))return 75;
        if(n){b[n]=0;auto old=static_cast<unsigned char>(a[0]);b[0]=char(old==255?1:old+1);
            int expected=old<static_cast<unsigned char>(b[0])?-1:1;
            if(!Pair(exact,a,b,expected)||!Pair(exact,b,a,-expected))return 76;
        }
    }
    for(unsigned value=1;value<256;++value){
        char a[2]{char(value),0},b[2]{char(value==255?1:value+1),0};int expected=value==255?1:-1;
        if(!Pair(exact,a,a,0)||!Pair(exact,a,b,expected)||!Pair(exact,b,a,-expected))return 77;
    }
    char a[]={'a',0,'x',0},b[]={'a',0,'y',0};if(!Pair(exact,a,b,0))return 78;
    if(!Check(dlclose(h)==0))return 79;
    std::printf("{\"record\":\"scopedStrcmpSummary\",\"PID\":%d,\"checks\":%u,\"ownedPairs\":%u,\"exactPrivateExport\":true,\"exactProviderUUIDAndPath\":true,\"nullInputsInvoked\":false,\"originalDispatchTargetPreserved\":false,\"hostPublicLibcSemanticsVerified\":true,\"originalVZConsumerExecuted\":false,\"actualVZCalls\":0,\"originalVMMExecuted\":false,\"guestInstructions\":0,\"full27\":false,\"passed\":true}\n",getpid(),Checks,Comparisons);
    alarm(0);return 0;
}
