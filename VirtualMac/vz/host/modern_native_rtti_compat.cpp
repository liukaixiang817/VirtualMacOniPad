// Genuine, code-pinned __si complete/base destructor forwarding only.
// No RTTI class, vtable, deleting destructor or synthetic successful stub.
#include "modern_native_rtti_compat.h"
#include "native-rtti-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <typeinfo>

extern "C" kern_return_t mach_vm_read_overwrite(vm_map_read_t,
    mach_vm_address_t,mach_vm_size_t,mach_vm_address_t,mach_vm_size_t*);
extern unsigned char NativeSiVTable[] __asm("__ZTVN10__cxxabiv120__si_class_type_infoE");
extern void NativeTypeInfoBaseDestructor(std::type_info*) noexcept __asm("__ZNSt9type_infoD2Ev");
namespace {
std::atomic<int> Status{0};
std::atomic<uint64_t> CompleteCalls{0},BaseCalls{0};
std::atomic<uintptr_t> CompleteRaw{0};
using NativeDestructor=void(*)(__cxxabiv1::__si_class_type_info*) noexcept;
bool Read(uintptr_t address,void *buffer,size_t bytes) {
    mach_vm_size_t copied=0;
    return mach_vm_read_overwrite(mach_task_self(),address,bytes,
        reinterpret_cast<mach_vm_address_t>(buffer),&copied)==KERN_SUCCESS&&copied==bytes;
}
bool Code(uintptr_t address,const unsigned char *sha,size_t bytes) {
    if(!bytes||bytes>2048)return false;
    unsigned char code[2048],digest[32];
    return Read(address,code,bytes)&&CC_SHA256(code,CC_LONG(bytes),digest)&&!std::memcmp(digest,sha,32);
}
bool Image(uintptr_t base) {
    mach_header_64 h={};unsigned char commands[16384];
    if(!Read(base,&h,sizeof(h))||h.magic!=MH_MAGIC_64||h.filetype!=MH_DYLIB||
        uint32_t(h.cputype)!=0x100000c||uint32_t(h.cpusubtype)!=0x80000002||
        !h.ncmds||h.ncmds>256||!h.sizeofcmds||h.sizeofcmds>sizeof(commands)||
        !Read(base+sizeof(h),commands,h.sizeofcmds))return false;
    unsigned at=0,uuids=0;bool exact=false;
    for(unsigned i=0;i<h.ncmds;++i){
        if(at>h.sizeofcmds||h.sizeofcmds-at<8)return false;
        load_command c;std::memcpy(&c,commands+at,8);
        if(c.cmdsize<8||c.cmdsize&7||c.cmdsize>h.sizeofcmds-at)return false;
        if(c.cmd==LC_UUID){if(c.cmdsize!=24)return false;++uuids;exact=!std::memcmp(commands+at+8,NativeUUID,16);}
        at+=c.cmdsize;
    }return uuids==1&&exact&&at==h.sizeofcmds;
}
int Verify() {
    Dl_info table={},base={};
    void *baseFunction=ptrauth_strip(reinterpret_cast<void*>(&NativeTypeInfoBaseDestructor),ptrauth_key_function_pointer);
    if(!dladdr(NativeSiVTable,&table)||!dladdr(baseFunction,&base)||!table.dli_fbase||
        table.dli_fbase!=base.dli_fbase||!table.dli_fname||!base.dli_fname||
        std::strcmp(table.dli_fname,"/usr/lib/libc++abi.dylib")||std::strcmp(base.dli_fname,table.dli_fname))return -1;
    uintptr_t image=reinterpret_cast<uintptr_t>(table.dli_fbase);
    if(!Image(image))return -2;
    if(reinterpret_cast<uintptr_t>(NativeSiVTable)-image!=NativeTableRVA||
        reinterpret_cast<uintptr_t>(baseFunction)-image!=NativeTypeBaseRVA)return -3;
    uint64_t entries[4]={};
    if(!Read(reinterpret_cast<uintptr_t>(NativeSiVTable),entries,sizeof(entries))||entries[0])return -4;
    uintptr_t complete=reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(entries[2]),ptrauth_key_function_pointer));
    uintptr_t deleting=reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(entries[3]),ptrauth_key_function_pointer));
    if(complete!=image+NativeCompleteRVA||deleting!=image+NativeDeletingRVA||
        !Code(complete,NativeCompleteSHA,NativeCompleteBytes)||
        !Code(deleting,NativeDeletingSHA,NativeDeletingBytes)||
        !Code(reinterpret_cast<uintptr_t>(baseFunction),NativeTypeBaseSHA,NativeTypeBaseBytes))return -5;
    // The entire complete entry is a direct B to public std::type_info D2.
    // This verifies no vtable-specific access, virtual base work or freeing.
    uint32_t word=0;if(!Read(complete,&word,4)||(word&0xfc000000)!=0x14000000||NativeCompleteBytes!=4)return -6;
    int32_t delta=int32_t(word<<6)>>6;
    if(int64_t(complete)+int64_t(delta)*4!=int64_t(reinterpret_cast<uintptr_t>(baseFunction)))return -7;
    CompleteRaw.store(complete,std::memory_order_release);return 1;
}
void Destroy(__cxxabiv1::__si_class_type_info *object) noexcept {
    if(VM27NativeRTTIABIStatus()!=1)std::abort();
    auto entry=reinterpret_cast<NativeDestructor>(ptrauth_sign_unauthenticated(
        reinterpret_cast<void*>(CompleteRaw.load(std::memory_order_acquire)),ptrauth_key_function_pointer,0));
    entry(object);
}
} // namespace
extern "C" int VM27NativeRTTIABIStatus(){
    int status=Status.load(std::memory_order_acquire);
    if(!status){status=Verify();Status.store(status,std::memory_order_release);}return status;
}
extern "C" uint64_t VM27NativeRTTICompleteCalls(){return CompleteCalls.load(std::memory_order_relaxed);}
extern "C" uint64_t VM27NativeRTTIBaseCalls(){return BaseCalls.load(std::memory_order_relaxed);}
void VM27SiCompleteDestructor(__cxxabiv1::__si_class_type_info *object) noexcept {
    Destroy(object);CompleteCalls.fetch_add(1,std::memory_order_relaxed);
}
void VM27SiBaseDestructor(__cxxabiv1::__si_class_type_info *object) noexcept {
    // Official __si has only single nonvirtual bases. Complete and base
    // destruction both execute this identical native base-destructor chain.
    Destroy(object);BaseCalls.fetch_add(1,std::memory_order_relaxed);
}
