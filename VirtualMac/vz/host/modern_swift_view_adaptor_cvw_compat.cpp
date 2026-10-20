// Bounded Swift.org BytecodeLayouts.cpp ownership adaptation at
// 5ea0a2a5d8e126628da27747739e8d017c1d4882. Copyright Apple/Swift authors.
// Apache-2.0 with Runtime Library Exception; see vendor license.
// Exact genuine VZ27 ViewAdaptor only, no global runtime override.
#include "modern_swift_view_adaptor_cvw_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>
extern "C" void *objc_retain(void *);
extern "C" void objc_release(void *);
namespace {
constexpr unsigned char VZUUID[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
constexpr unsigned char OldObjCUUID[16] = {0xab,0x79,0x70,0x7f,0xaf,0x64,0x3b,0xa5,
    0x88,0x99,0x3b,0x71,0x1c,0x6c,0xff,0x5c};
constexpr unsigned char NewObjCUUID[16] = {0xc0,0x68,0x0d,0xf6,0x99,0x00,0x3c,0x29,
    0xa0,0x71,0x95,0xa0,0x31,0x68,0x6e,0xf8};
bool Read(const void *address, void *output, size_t length) {
    if (!address || !output || !length || length > 4096) return false;
    vm_size_t copied = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)address, length,
        (vm_address_t)output, &copied) == KERN_SUCCESS && copied == length;
}
bool UUID(const void *base, unsigned char result[16]) {
    mach_header_64 header{};
    if (!Read(base,&header,sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.cputype != CPU_TYPE_ARM64 || header.ncmds > 1024 ||
        header.sizeofcmds > 65536) return false;
    uintptr_t at = (uintptr_t)base + sizeof(header), end = at + header.sizeofcmds;
    if (end < at) return false;
    unsigned found = 0;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (at > end || end - at < 8 || !Read((void *)at,&command,sizeof(command)) ||
            command.cmdsize < 8 || command.cmdsize % 8 || command.cmdsize > end - at) return false;
        if (command.cmd == LC_UUID) {
            uuid_command uuid{};
            if (command.cmdsize != sizeof(uuid) || !Read((void *)at,&uuid,sizeof(uuid))) return false;
            std::memcpy(result,uuid.uuid,16); ++found;
        }
        at += command.cmdsize;
    }
    return at == end && found == 1;
}
bool Owner(const void *address, const unsigned char uuid[16], const void **base = nullptr) {
    Dl_info image{}; unsigned char actual[16]{};
    if (!address || !dladdr(address,&image) || !UUID(image.dli_fbase,actual) ||
        std::memcmp(actual,uuid,16)) return false;
    if (base) *base = image.dli_fbase;
    return true;
}
bool Pair(const void *first, const void *second, const unsigned char old[16],
          const unsigned char modern[16]) {
    const void *a = nullptr, *b = nullptr;
    bool found = (Owner(first,old,&a) && Owner(second,old,&b)) ||
                 (Owner(first,modern,&a) && Owner(second,modern,&b));
    return found && a == b;
}
bool Decode(const void *metadata,VM27ViewCVWInfo &info) {
    const void *owner=nullptr;
    if (!metadata || ((uintptr_t)metadata&7) || (uintptr_t)metadata<16 || !Owner(metadata,VZUUID,&owner)) return false;
    const void *slots[2]{};
    if (!Read((const unsigned char *)metadata-16,slots,sizeof(slots))) return false;
    const unsigned char *layout=(const unsigned char *)slots[0],*table=(const unsigned char *)slots[1];
#if __has_feature(ptrauth_calls)
    layout=(const unsigned char *)ptrauth_auth_data(layout,ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata-16,0x8b65));
    table=(const unsigned char *)ptrauth_auth_data(table,ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata-8,0x2e3f));
#endif
    const void *a=nullptr,*b=nullptr;
    const uint64_t expected[4]={0,8,UINT64_C(0x0a00000000000000),0};uint64_t program[4]{};
    if (((uintptr_t)layout&1) || !Owner(layout,VZUUID,&a) || !Owner(table,VZUUID,&b) || a!=owner || b!=owner ||
        !Read(layout,program,sizeof(program)) || std::memcmp(program,expected,sizeof(program)) ||
        !Read(table+64,&info,sizeof(info)) || info.size!=8 || info.stride!=8 ||
        info.flags!=0x02010007 || info.extraInhabitants!=0x7fffffff) return false;
    return Pair(ptrauth_strip((void *)&objc_retain,ptrauth_key_function_pointer),
        ptrauth_strip((void *)&objc_release,ptrauth_key_function_pointer),OldObjCUUID,NewObjCUUID);
}
void Require(const void *metadata) { VM27ViewCVWInfo info{};if(!Decode(metadata,info))__builtin_trap(); }
void Value(const void *value) { if(!value || ((uintptr_t)value&7))__builtin_trap(); }
void Values(void *dest,const void *src) {
    uintptr_t d=(uintptr_t)dest,s=(uintptr_t)src;Value(dest);Value(src);
    if(d>UINTPTR_MAX-24 || s>UINTPTR_MAX-24 || !(d+24<=s || s+24<=d))__builtin_trap();
}
void *Object(const void *value) { void *object=nullptr;std::memcpy(&object,value,8);return object; }
void Copy(void *dest,const void *src) {
    void *object=Object(src);std::memcpy(dest,src,8);objc_retain(object);
}
} // namespace
extern "C" int VM27ViewCVWQuery(const void *metadata,VM27ViewCVWInfo *info) {
    VM27ViewCVWInfo result{};if(!info || !Decode(metadata,result))return 0;*info=result;return 1;
}
extern "C" void VM27ViewCVWDestroy(void *value,const void *metadata) {
    Require(metadata);Value(value);objc_release(Object(value));
}
extern "C" void *VM27ViewCVWInitWithCopy(void *dest,const void *src,const void *metadata) {
    Require(metadata);Values(dest,src);Copy(dest,src);return dest;
}
extern "C" void *VM27ViewCVWBufferCopy(void *dest,const void *src,const void *metadata) {
    return VM27ViewCVWInitWithCopy(dest,src,metadata);
}
extern "C" void *VM27ViewCVWAssignWithCopy(void *dest,const void *src,const void *metadata) {
    Require(metadata);Values(dest,src);void *old=Object(dest),*next=Object(src);
    std::memcpy(dest,src,8);objc_release(old);objc_retain(next);return dest;
}
extern "C" void *VM27ViewCVWAssignWithTake(void *dest,void *src,const void *metadata) {
    Require(metadata);Values(dest,src);objc_release(Object(dest));std::memcpy(dest,src,8);return dest;
}
