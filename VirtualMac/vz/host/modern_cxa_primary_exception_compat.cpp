// Scoped adaptation of LLVM21.1.3 libcxxabi/src/cxa_exception.cpp initialization.
// Apache-2.0 WITH LLVM-exception. See the frozen upstream source/license pins.
// The iOS16 header and IA/zero-discriminator function pointers are verified
// against genuine __cxa_throw, allocation, refcount and cleanup machine code.
// No allocator, reference counting, unwinder or exception destructor is replaced.
#include "modern_cxa_primary_exception_compat.h"
#include "cxa-native-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <dlfcn.h>
#include <exception>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <unwind.h>

extern "C" kern_return_t mach_vm_read_overwrite(vm_map_read_t,
    mach_vm_address_t,mach_vm_size_t,mach_vm_address_t,mach_vm_size_t*);

namespace {
// The Mac fixture separately tests today's native PAC schema. The deployed
// iOS16 provider must never use today's address-diverse cxxabi field schema.
#if defined(VM27_PRIMARY_EXCEPTION_NEW_PAC)
#define VM27_DTOR __ptrauth_cxxabi_exception_destructor
#define VM27_UNEXPECTED __ptrauth_cxxabi_unexpected_handler
#define VM27_TERMINATE __ptrauth_cxxabi_terminate_handler
#else
#define VM27_DTOR
#define VM27_UNEXPECTED
#define VM27_TERMINATE
#endif
struct Header {
    void *reserve;
    size_t referenceCount;
    std::type_info *exceptionType;
    void (*VM27_DTOR exceptionDestructor)(void*);
    std::unexpected_handler VM27_UNEXPECTED unexpectedHandler;
    std::terminate_handler VM27_TERMINATE terminateHandler;
    Header *nextException;
    int handlerCount;
    int handlerSwitchValue;
    const unsigned char *actionRecord;
    const unsigned char *languageSpecificData;
    void *catchTemp;
    void *adjustedPtr;
    _Unwind_Exception unwindHeader;
};
static_assert(sizeof(void*)==8 && sizeof(Header)==128 && alignof(Header)==16,
    "Audited LP64 system exception header");
static_assert(offsetof(Header,referenceCount)==8 &&
    offsetof(Header,exceptionType)==16 && offsetof(Header,exceptionDestructor)==24 &&
    offsetof(Header,unexpectedHandler)==32 && offsetof(Header,terminateHandler)==40 &&
    offsetof(Header,unwindHeader)==96 && sizeof(_Unwind_Exception)==32,
    "Offsets confirmed by genuine allocation/throw/refcount/cleanup code");
using Cleanup=void(*)(_Unwind_Reason_Code,_Unwind_Exception*);
std::atomic<uint64_t> Calls{0};
std::atomic<int> Gate{0};
std::atomic<uintptr_t> CleanupRaw{0};

bool Read(uintptr_t address,void *out,size_t size) {
    mach_vm_size_t copied=0;
    return mach_vm_read_overwrite(mach_task_self(),address,size,
        reinterpret_cast<mach_vm_address_t>(out),&copied)==KERN_SUCCESS && copied==size;
}
bool Image(uintptr_t base) {
    mach_header_64 header={};
    if(!Read(base,&header,sizeof(header)) || header.magic!=MH_MAGIC_64 ||
        uint32_t(header.cputype)!=0x100000c || uint32_t(header.cpusubtype)!=0x80000002 ||
        header.filetype!=MH_DYLIB || !header.ncmds || header.ncmds>256 ||
        !header.sizeofcmds || header.sizeofcmds>16384) return false;
    unsigned char commands[16384];
    if(!Read(base+sizeof(header),commands,header.sizeofcmds)) return false;
    unsigned at=0,uuids=0;bool exact=false;
    for(unsigned i=0;i<header.ncmds;++i) {
        if(at>header.sizeofcmds || header.sizeofcmds-at<8) return false;
        load_command command;std::memcpy(&command,commands+at,8);
        if(command.cmdsize<8 || command.cmdsize&7 || command.cmdsize>header.sizeofcmds-at) return false;
        if(command.cmd==LC_UUID) {
            if(command.cmdsize!=24) return false;
            ++uuids;exact=!std::memcmp(commands+at+8,NativeUUID,16);
        }
        at+=command.cmdsize;
    }
    return at==header.sizeofcmds && uuids==1 && exact;
}
bool Code(uintptr_t base,const NativeFunctionPin& pin) {
    if(!pin.bytes || pin.bytes>2048) return false;
    unsigned char data[2048],digest[32];
    return Read(base+pin.rva,data,pin.bytes) &&
        CC_SHA256(data,CC_LONG(pin.bytes),digest)!=nullptr &&
        !std::memcmp(digest,pin.sha256,32);
}
int Verify() {
    uintptr_t base=0;
    for(const auto& pin:NativeFunctions) {
        void *function=dlsym(RTLD_DEFAULT,pin.name);
        void *raw=ptrauth_strip(function,ptrauth_key_function_pointer);
        Dl_info info={};
        if(!function || !dladdr(raw,&info) || !info.dli_fbase || !info.dli_fname ||
            std::strcmp(info.dli_fname,"/usr/lib/libc++abi.dylib")) return -1;
        if(!base) {
            base=reinterpret_cast<uintptr_t>(info.dli_fbase);
            if(!Image(base)) return -2;
        }
        if(base!=reinterpret_cast<uintptr_t>(info.dli_fbase) ||
            reinterpret_cast<uintptr_t>(raw)-base!=pin.rva || !Code(base,pin)) return -3;
    }
    if(!Code(base,NativeCleanup)) return -4;
    CleanupRaw.store(base+NativeCleanup.rva,std::memory_order_release);
    return 1;
}
} // namespace

extern "C" int VM27PrimaryExceptionNativeABIStatus() {
    int status=Gate.load(std::memory_order_acquire);
    if(!status) {
        status=Verify();
        // System shared-cache images remain loaded for the process lifetime.
        // Concurrent checks have the same immutable, identity-pinned image.
        Gate.store(status,std::memory_order_release);
    }
    return status;
}
extern "C" uint64_t VM27PrimaryExceptionInitializeCalls() {
    return Calls.load(std::memory_order_relaxed);
}
extern "C" uintptr_t VM27PrimaryExceptionNativeCleanupAddress() {
    return VM27PrimaryExceptionNativeABIStatus()==1 ? CleanupRaw.load(std::memory_order_acquire) : 0;
}

namespace __cxxabiv1 {
extern "C" __cxa_exception* __cxa_init_primary_exception(void *object,
        std::type_info *type,void(*destructor)(void*)) noexcept {
    // Unsupported system identities are rejected before touching an object.
    // Returning an uninitialized header would violate the real API contract.
    if(VM27PrimaryExceptionNativeABIStatus()!=1) std::abort();
    auto *header=static_cast<Header*>(object)-1;
    header->referenceCount=0;
    header->unexpectedHandler=std::get_unexpected();
    header->terminateHandler=std::get_terminate();
    header->exceptionType=type;
    header->exceptionDestructor=destructor;
    constexpr uint64_t exceptionClass=0x434c4e47432b2b00ull;
    std::memcpy(&header->unwindHeader.exception_class,&exceptionClass,sizeof(exceptionClass));
    // Reuse the real, fully code-pinned native cleanup. It decrements genuine
    // primary references for FOREIGN_EXCEPTION_CAUGHT and invokes the saved
    // terminate handler for every other reason, exactly as the upstream API.
    auto cleanup=reinterpret_cast<Cleanup>(ptrauth_sign_unauthenticated(
        reinterpret_cast<void*>(CleanupRaw.load(std::memory_order_acquire)),
        ptrauth_key_function_pointer,0));
    header->unwindHeader.exception_cleanup=cleanup;
    Calls.fetch_add(1,std::memory_order_relaxed);
    return reinterpret_cast<__cxa_exception*>(header);
}
} // namespace __cxxabiv1
