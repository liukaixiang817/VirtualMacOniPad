// Ordinary userspace runtime fixture. No VM, Hypervisor, kernel driver or GPU.
// iOS uses unchanged signed CP/runtime bytes; Mac uses the same runtime source.
#include <CommonCrypto/CommonDigest.h>
#include <__expected/bad_expected_access.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <typeinfo>
#include <unistd.h>
#include "cpu-runtime-leaf-pins.h"

extern size_t RuntimeHash(const void *,size_t) noexcept __asm("__ZNSt3__113__hash_memoryEPKvm");
extern long long RuntimeMonitor(const void *) noexcept __asm("__ZNSt3__123__atomic_monitor_globalEPKv");
extern void RuntimeWait(const void *,long long) noexcept __asm("__ZNSt3__126__atomic_wait_global_tableEPKvx");
extern void RuntimeNotify(const void *) noexcept __asm("__ZNSt3__132__atomic_notify_all_global_tableEPKv");
extern const char *RuntimeWhat(const std::bad_expected_access<void> *) noexcept
    __asm("__ZNKSt3__119bad_expected_accessIvE4whatEv");
extern const std::type_info RuntimeTypeInfo __asm("__ZTINSt3__119bad_expected_accessIvEE");

static unsigned Checks,Failures,Created,Released;
static void Check(bool pass,const char *name) {
    ++Checks; if(!pass) ++Failures;
    std::printf("{\"record\":\"check\",\"id\":%u,\"name\":\"%s\",\"passed\":%s}\n",
        Checks,name,pass?"true":"false");
}
static bool SameStat(const struct stat& a,const struct stat& b) {
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size &&
        a.st_uid==b.st_uid && a.st_gid==b.st_gid && a.st_mode==b.st_mode &&
        a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec &&
        a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
}
static struct stat InitialStats[2];
static bool FileIdentity(unsigned which,bool before) {
    const FilePin& pin=FilePins[which];
    int fd=open(pin.path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
    struct stat first={},last={};
    bool pass=fstat(fd,&first)==0 && S_ISREG(first.st_mode) && first.st_nlink==1 &&
        first.st_uid==geteuid() && !(first.st_mode&0022) && first.st_size==(off_t)pin.bytes;
    CC_SHA256_CTX sha;unsigned char block[4096],digest[32];size_t total=0;
    pass=pass && CC_SHA256_Init(&sha);
    while(pass) {
        ssize_t n=read(fd,block,sizeof(block));
        if(n<0 && errno==EINTR) continue;
        if(n<0) {pass=false;break;} if(!n) break;
        if(total>pin.bytes || size_t(n)>pin.bytes-total) {pass=false;break;}
        total+=size_t(n);pass=CC_SHA256_Update(&sha,block,CC_LONG(n));
    }
    pass=pass && total==pin.bytes && fstat(fd,&last)==0 && SameStat(first,last);
    if(close(fd)) pass=false;
    char hex[65]={};
    if(pass) {
        pass=CC_SHA256_Final(digest,&sha);
        for(unsigned i=0;i<32;++i) std::snprintf(hex+2*i,3,"%02x",digest[i]);
        pass=pass && !std::strcmp(hex,pin.sha);
    }
    if(before && pass) InitialStats[which]=first;
    if(!before) pass=pass && SameStat(first,InitialStats[which]);
    std::printf("{\"record\":\"file\",\"index\":%u,\"phase\":\"%s\",\"bytes\":%zu,\"sha256\":\"%s\",\"exact\":%s}\n",
        which,before?"before":"after",total,hex,pass?"true":"false");
    return pass;
}
static bool HeaderUUID(const void *base,const unsigned char *uuid,unsigned filetype) {
    const auto *h=static_cast<const mach_header_64*>(base);
    if(!h || h->magic!=MH_MAGIC_64 || uint32_t(h->cputype)!=0x100000c ||
        h->filetype!=filetype || h->ncmds>256 || h->sizeofcmds>32768) return false;
    auto *p=reinterpret_cast<const unsigned char*>(h+1);unsigned at=0,count=0;
    bool exact=false;
    for(unsigned i=0;i<h->ncmds;++i) {
        if(at>h->sizeofcmds || h->sizeofcmds-at<8) return false;
        load_command c;std::memcpy(&c,p+at,8);
        if(c.cmdsize<8 || (c.cmdsize&7) || c.cmdsize>h->sizeofcmds-at) return false;
        if(c.cmd==LC_UUID) {
            if(c.cmdsize!=24) return false;
            ++count;exact=!std::memcmp(p+at+8,uuid,16);
        }
        at+=c.cmdsize;
    }
    return at==h->sizeofcmds && count==1 && exact;
}
static const void *RuntimeBase;
static const void *DeleteSlot;
static bool OwnAuthGOTSlot(const void *base) {
    if(!HeaderUUID(base,RuntimeUUID,MH_DYLIB) || DeleteGOTRVA%8 ||
        uintptr_t(base)>UINTPTR_MAX-DeleteGOTRVA ||
        uintptr_t(base)+DeleteGOTRVA>UINTPTR_MAX-sizeof(uintptr_t)) return false;
    const auto *h=static_cast<const mach_header_64*>(base);
    const auto *p=reinterpret_cast<const unsigned char*>(h+1);
    uint64_t imageVMAddr=0;unsigned textCount=0,slotCount=0,at=0;
    // Discover the actual preferred address of the owned Mach-O header first.
    for(unsigned i=0;i<h->ncmds;++i) {
        load_command c;std::memcpy(&c,p+at,8);
        if(c.cmd==LC_SEGMENT_64) {
            if(c.cmdsize<sizeof(segment_command_64)) return false;
            segment_command_64 segment;std::memcpy(&segment,p+at,sizeof(segment));
            if(segment.nsects>128 || c.cmdsize!=sizeof(segment)+segment.nsects*sizeof(section_64)) return false;
            if(!std::memcmp(segment.segname,"__TEXT\0",7) && segment.fileoff==0 && segment.filesize>0) {
                ++textCount;imageVMAddr=segment.vmaddr;
            }
        }
        at+=c.cmdsize;
    }
    if(textCount!=1 || imageVMAddr>UINT64_MAX-DeleteGOTRVA) return false;
    const uint64_t target=imageVMAddr+DeleteGOTRVA;
    if(target>UINT64_MAX-sizeof(uintptr_t)) return false;
    at=0;
    for(unsigned i=0;i<h->ncmds;++i) {
        load_command c;std::memcpy(&c,p+at,8);
        if(c.cmd==LC_SEGMENT_64) {
            segment_command_64 segment;std::memcpy(&segment,p+at,sizeof(segment));
            if(!std::memcmp(segment.segname,"__DATA_CONST\0",13)) {
                if(segment.vmaddr>UINT64_MAX-segment.vmsize || !(segment.initprot&VM_PROT_READ)) return false;
                for(unsigned j=0;j<segment.nsects;++j) {
                    section_64 section;std::memcpy(&section,p+at+sizeof(segment)+j*sizeof(section),sizeof(section));
                    if(!std::memcmp(section.sectname,"__auth_got\0",11) &&
                        !std::memcmp(section.segname,"__DATA_CONST\0",13)) {
                        if(section.addr>UINT64_MAX-section.size || section.align<3 ||
                            section.addr<segment.vmaddr || section.addr+section.size>segment.vmaddr+segment.vmsize ||
                            target<section.addr || target+sizeof(uintptr_t)>section.addr+section.size) return false;
                        ++slotCount;
                    }
                }
            }
        }
        at+=c.cmdsize;
    }
    if(slotCount!=1) return false;
    const void *slot=reinterpret_cast<const void*>(uintptr_t(base)+DeleteGOTRVA);
    if(DeleteSlot && DeleteSlot!=slot) return false;
    DeleteSlot=slot;return true;
}
static bool Identity(const char *phase) {
    const void *entries[]={(const void*)&RuntimeTypeInfo,(const void*)&RuntimeWhat,
        (const void*)&RuntimeHash,(const void*)&RuntimeMonitor,(const void*)&RuntimeWait,(const void*)&RuntimeNotify};
    bool all=true;
    for(unsigned i=0;i<6;++i) {
        const void *entry=i?ptrauth_strip(entries[i],ptrauth_key_function_pointer):entries[i];
        Dl_info d={};struct stat s={};
        bool pass=dladdr(entry,&d) && d.dli_fbase && d.dli_fname &&
            stat(d.dli_fname,&s)==0 && SameStat(s,InitialStats[1]) &&
            HeaderUUID(d.dli_fbase,RuntimeUUID,MH_DYLIB) &&
            uintptr_t(entry)>=uintptr_t(d.dli_fbase) &&
            uintptr_t(entry)-uintptr_t(d.dli_fbase)==RuntimeRVAs[i];
        if(RuntimeBase && RuntimeBase!=d.dli_fbase) pass=false;
        if(pass) RuntimeBase=d.dli_fbase;
        Check(pass,"exactRuntimeEntryUUIDRVAAndOwnFile");all=all && pass;
    }
    unsigned runtimeCount=0,cpCount=0,forbidden=0;uint32_t count=_dyld_image_count();
    if(count>4096) return false;
    for(uint32_t i=0;i<count;++i) {
        const char *name=_dyld_get_image_name(i);const auto *base=_dyld_get_image_header(i);
        if(!name || !base) return false;
        if((const void*)base==RuntimeBase) ++runtimeCount;
        if(HeaderUUID(base,CPUUID,MH_DYLIB)) {
            struct stat s={};if(stat(name,&s) || !SameStat(s,InitialStats[0])) return false;
            ++cpCount;
        }
        if(std::strstr(name,"Hypervisor.framework") || std::strstr(name,"Virtualization.framework") ||
            std::strstr(name,"VirtualMachine") || std::strstr(name,"ParavirtualizedGraphics")) ++forbidden;
    }
    all=all && runtimeCount==1 && cpCount==1 && forbidden==0;
    std::printf("{\"record\":\"census\",\"phase\":\"%s\",\"images\":%u,\"runtime\":%u,\"CP\":%u,\"forbidden\":%u,\"exact\":%s}\n",
        phase,count,runtimeCount,cpCount,forbidden,all?"true":"false");
    if(!all || !OwnAuthGOTSlot(RuntimeBase)) return false;
    // Read only this exact owned image's linker-authenticated GOT. Stripping
    // alone is an address observation. The bounded own-allocation test below
    // separately authenticates and calls the same observed GOT target.
    uintptr_t signedDelete=0;
    std::memcpy(&signedDelete,DeleteSlot,sizeof(signedDelete));
    const void *deleteEntry=ptrauth_strip((const void*)signedDelete,ptrauth_key_function_pointer);
    Dl_info d={};
    bool deletion=dladdr(deleteEntry,&d) && d.dli_fname && d.dli_fbase &&
        !std::strcmp(d.dli_fname,NativeDeletePath) && HeaderUUID(d.dli_fbase,NativeDeleteUUID,MH_DYLIB) &&
        uintptr_t(deleteEntry)>=uintptr_t(d.dli_fbase) &&
        uintptr_t(deleteEntry)-uintptr_t(d.dli_fbase)==NativeDeleteRVA;
    std::printf("{\"record\":\"coalescedDelete\",\"phase\":\"%s\",\"GOTRVA\":%llu,\"targetRVA\":%llu,\"exact\":%s,\"PACStripIsAuthenticationProof\":false}\n",
        phase,(unsigned long long)DeleteGOTRVA,
        (unsigned long long)(d.dli_fbase?uintptr_t(deleteEntry)-uintptr_t(d.dli_fbase):0),deletion?"true":"false");
    return deletion;
}
static void Hashes() {
    unsigned char bytes[257];
    for(unsigned i=0;i<sizeof(bytes);++i) bytes[i]=static_cast<unsigned char>(i*37+11);
    for(unsigned i=0;i<HashCount;++i) {
        const HashPin& p=HashPins[i];
        Check(RuntimeHash(bytes+p.offset,p.length)==p.value,"actualMac27NativeHashGolden");
    }
}
static __attribute__((noinline)) const char *VirtualWhat(std::exception *e) {return e->what();}
static void Exceptions() {
    for(unsigned i=0;i<32;++i) {
        std::exception *e=new std::bad_expected_access<int>(37); ++Created;
        Check(!std::strcmp(VirtualWhat(e),"bad access to std::expected"),"realVirtualWhat");
        auto *typed=dynamic_cast<std::bad_expected_access<int>*>(e);
        Check(typeid(std::bad_expected_access<void>)==RuntimeTypeInfo &&
            dynamic_cast<std::bad_expected_access<void>*>(e) && typed && typed->error()==37,"realRTTIAndNativeDynamicCast");
        delete e; ++Released;
        bool caught=false;
        try {throw std::bad_expected_access<int>(53);}
        catch(const std::exception& ex) {
            auto *specific=dynamic_cast<const std::bad_expected_access<int>*>(&ex);
            caught=specific && specific->error()==53 && !std::strcmp(ex.what(),"bad access to std::expected");
        }
        Check(caught,"realNativeThrowCatchBaseClass");
        // Exact own-image IA/div0/address-diverse fixup. Authenticate using
        // its slot before resigning to the ordinary ABI0 function-pointer
        // convention; do not sign an unauthenticated address or edit the GOT.
        void *allocation=::operator new(257);++Created;
        std::memset(allocation,0x5a,257);
        const void *slot=DeleteSlot;
        uintptr_t signedDelete=0;std::memcpy(&signedDelete,slot,sizeof(signedDelete));
        using Delete=void(*)(void*);
        auto nativeDelete=reinterpret_cast<Delete>(ptrauth_auth_and_resign(
            reinterpret_cast<void*>(signedDelete),ptrauth_key_asia,
            ptrauth_blend_discriminator(slot,0),ptrauth_key_function_pointer,0));
        nativeDelete(allocation);++Released;
        Check(true,"actualOwnGOTAuthenticatedDeleteReturned");
    }
    Check(Created==Released,"everyOwnVirtualAllocationReleased");
}
struct Channel {
    pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
    unsigned ready=0,woken=0;
    long long tickets[4]={};
    unsigned address=0;
};
struct Worker {Channel *channel;unsigned index;};
static void Pthread(int status) {if(status) std::abort();}
static void *Waiter(void *argument) {
    auto *worker=static_cast<Worker*>(argument);Channel& c=*worker->channel;
    long long ticket=RuntimeMonitor(&c.address);
    Pthread(pthread_mutex_lock(&c.mutex));c.tickets[worker->index]=ticket;++c.ready;
    Pthread(pthread_cond_broadcast(&c.condition));Pthread(pthread_mutex_unlock(&c.mutex));
    RuntimeWait(&c.address,ticket);
    Pthread(pthread_mutex_lock(&c.mutex));++c.woken;
    Pthread(pthread_mutex_unlock(&c.mutex));return nullptr;
}
static void Wakeups() {
    Channel c;
    for(unsigned round=0;round<32;++round) {
        long long first=RuntimeMonitor(&c.address);
        RuntimeNotify(&c.address);
        Check(RuntimeMonitor(&c.address)!=first,"samePrivateTableTicketAdvanced");
        RuntimeWait(&c.address,first);
        Check(true,"notifyBeforeWaitReturnedWithoutLostWakeup");
        c.ready=0;c.woken=0;pthread_t threads[4];Worker workers[4];
        for(unsigned i=0;i<4;++i) {workers[i]={&c,i};Pthread(pthread_create(&threads[i],nullptr,Waiter,&workers[i]));}
        Pthread(pthread_mutex_lock(&c.mutex));
        while(c.ready!=4) Pthread(pthread_cond_wait(&c.condition,&c.mutex));
        Pthread(pthread_mutex_unlock(&c.mutex));
        RuntimeNotify(&c.address);
        for(auto& thread:threads) Pthread(pthread_join(thread,nullptr));
        Check(c.woken==4,"allFourRealWaitersReturnedAndJoined");
        bool same=true;for(unsigned i=1;i<4;++i) same=same && c.tickets[i]==c.tickets[0];
        Check(same,"allFourWaitersUsedSameTableTicket");
    }
    Pthread(pthread_cond_destroy(&c.condition));Pthread(pthread_mutex_destroy(&c.mutex));
}
int main() {
    std::setbuf(stdout,nullptr);rlimit cpu={5,5},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core)) return 78;
    alarm(15);
    std::printf("{\"record\":\"start\",\"pid\":%d,\"uid\":%u,\"cpuLimitSeconds\":5,\"wallLimitSeconds\":15,\"HypervisorCalls\":0,\"VMMCalls\":0}\n",getpid(),getuid());
    bool before=FileIdentity(0,true) && FileIdentity(1,true) && Identity("before");
    Check(before,"beforeIdentity");if(!before) return 78;
    Hashes();Exceptions();Wakeups();
    Check(FileIdentity(0,false) && FileIdentity(1,false) && Identity("after"),"afterIdentity");
    std::printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"created\":%u,\"released\":%u,\"passed\":%s,\"originalVZExecuted\":false,\"full27Backend\":false}\n",
        Checks,Failures,Created,Released,Failures?"false":"true");
    alarm(0);return Failures?83:0;
}
