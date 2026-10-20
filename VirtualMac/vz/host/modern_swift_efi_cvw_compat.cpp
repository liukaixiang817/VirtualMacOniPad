// This source adapts the Swift.org open source project's runtime code.
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors.
// Apache License v2.0 with Runtime Library Exception, see vendor license.
// Bounded adaptation of BytecodeLayouts.cpp at 5ea0a2a5d8e126628da27747739e8d017c1d4882.
// One genuine VZ27 enum and its authentic nested Data layout, no global registry.
#include "modern_swift_efi_cvw_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>

extern "C" void *swift_retain(void *);
extern "C" void swift_release(void *);
extern "C" void *objc_retain(void *);
extern "C" void objc_release(void *);
static_assert(sizeof(void *) == 8, "Audited Darwin arm64 LP64 only");
namespace {
constexpr unsigned char VZUUID[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
constexpr unsigned char OldSwiftUUID[16] = {0xf8,0x96,0xd1,0x45,0xe0,0x25,0x39,0xd6,
    0xaf,0xd3,0xbc,0x0a,0x2a,0xd4,0xf8,0x39};
constexpr unsigned char NewSwiftUUID[16] = {0xc9,0xb3,0x6d,0xa7,0xbb,0x34,0x35,0xaf,
    0xbc,0x5d,0x91,0xec,0xbc,0xaa,0x9e,0xd0};
constexpr unsigned char OldObjCUUID[16] = {0xab,0x79,0x70,0x7f,0xaf,0x64,0x3b,0xa5,
    0x88,0x99,0x3b,0x71,0x1c,0x6c,0xff,0x5c};
constexpr unsigned char NewObjCUUID[16] = {0xc0,0x68,0x0d,0xf6,0x99,0x00,0x3c,0x29,
    0xa0,0x71,0x95,0xa0,0x31,0x68,0x6e,0xf8};
// Swift-Shims-System.h:156, same fixed upstream commit. NativeStrong only.
constexpr uintptr_t SwiftSpareBitsMask = UINT64_C(0xf000000000000007);
// Darwin arm64 supports ObjC tagged pointers: preserve ObjC words unchanged.
constexpr uint64_t Program[27] = {0x8000000000000000,192,0x1400000000000000,
    0xfffffffffff47ee4,2,136,16,0,16,0x0a00000000000000,0,
    0x1400000000000000,0xfffffffffff47e80,3,48,16,0,8,24,0,
    0x0200000000000008,0,0x0200000000000000,0x0200000000000000,0,0,0};
constexpr uint32_t OuterCode[3] = {0xf9400408,0xd37df500,0xd65f03c0};
constexpr uint32_t InnerCode[7] = {0xb9400008,0xf9400409,0xd37efd29,0x11000d08,
    0xf1000d3f,0x1a890100,0xd65f03c0};
using Tag = unsigned (*)(const void *);
struct Contract { VM27EFICVWInfo info{}; Tag outer = nullptr, inner = nullptr; };
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
bool Primitives() {
    return Pair(ptrauth_strip((void *)&swift_retain,ptrauth_key_function_pointer),
                ptrauth_strip((void *)&swift_release,ptrauth_key_function_pointer),OldSwiftUUID,NewSwiftUUID) &&
           Pair(ptrauth_strip((void *)&objc_retain,ptrauth_key_function_pointer),
                ptrauth_strip((void *)&objc_release,ptrauth_key_function_pointer),OldObjCUUID,NewObjCUUID);
}
template<size_t N> bool Getter(const unsigned char *slot, int32_t relative,
                               const uint32_t (&code)[N], const void *owner, Tag &result) {
    uintptr_t at = (uintptr_t)slot, target = at + (intptr_t)relative;
    if ((relative > 0 && target < at) || (relative < 0 && target > at)) return false;
    uint32_t actual[N]{}; const void *base = nullptr;
    if (!Owner((void *)target,VZUUID,&base) || base != owner ||
        !Read((void *)target,actual,sizeof(actual)) || std::memcmp(actual,code,sizeof(code))) return false;
#if __has_feature(ptrauth_calls)
    result = (Tag)ptrauth_sign_unauthenticated((void *)target,ptrauth_key_function_pointer,0);
#else
    result = (Tag)target;
#endif
    return true;
}
bool Decode(const void *metadata, Contract &contract) {
    const void *owner = nullptr;
    if (!metadata || ((uintptr_t)metadata & 7) || (uintptr_t)metadata < 16 ||
        !Owner(metadata,VZUUID,&owner)) return false;
    const void *slots[2]{};
    if (!Read((const unsigned char *)metadata - 16,slots,sizeof(slots))) return false;
    const unsigned char *layout = (const unsigned char *)slots[0], *table = (const unsigned char *)slots[1];
#if __has_feature(ptrauth_calls)
    layout = (const unsigned char *)ptrauth_auth_data(layout,ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata - 16,0x8b65));
    table = (const unsigned char *)ptrauth_auth_data(table,ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata - 8,0x2e3f));
#endif
    const void *a = nullptr, *b = nullptr;
    if ((uintptr_t)layout & 1 || !Owner(layout,VZUUID,&a) || !Owner(table,VZUUID,&b) ||
        a != owner || b != owner) return false;
    uint64_t program[27]{};
    if (!Read(layout,program,sizeof(program))) return false;
    for (unsigned i = 0; i < 27; ++i)
        if (i != 3 && i != 12 && program[i] != Program[i]) return false;
    if (!Read(table + 64,&contract.info,sizeof(contract.info)) || contract.info.size != 16 ||
        contract.info.stride != 16 || contract.info.flags != 0x02210007 ||
        contract.info.extraInhabitants != 2 || !Primitives()) return false;
    return Getter(layout + 24,(int32_t)program[3],OuterCode,owner,contract.outer) &&
           Getter(layout + 96,(int32_t)program[12],InnerCode,owner,contract.inner);
}
Contract Require(const void *metadata) {
    Contract contract{}; if (!Decode(metadata,contract)) __builtin_trap(); return contract;
}
unsigned Shape(const Contract &contract, const void *value) {
    if (!value || ((uintptr_t)value & 7)) __builtin_trap();
    unsigned outer = contract.outer(value);
    if (outer > 1) __builtin_trap();
    if (!outer) return 0; // Genuine SecCertificate/ObjC payload.
    unsigned inner = contract.inner(value);
    if (inner > 3) __builtin_trap();
    return inner + 1; // inline bytes, one native ref, two native refs, empty.
}
void RequirePair(void *dest, const void *src) {
    uintptr_t d = (uintptr_t)dest, s = (uintptr_t)src;
    if (!dest || !src || (d & 7) || (s & 7) || d > UINTPTR_MAX - 24 || s > UINTPTR_MAX - 24 ||
        !(d + 24 <= s || s + 24 <= d)) __builtin_trap();
}
uintptr_t Word(const void *value,unsigned offset) {
    uintptr_t word; std::memcpy(&word,(const unsigned char *)value + offset,8); return word;
}
void Retain(uintptr_t word, bool objc) {
    if (objc) objc_retain((void *)word);
    else swift_retain((void *)(word & ~SwiftSpareBitsMask));
}
void Release(uintptr_t word, bool objc) {
    if (objc) objc_release((void *)word);
    else swift_release((void *)(word & ~SwiftSpareBitsMask));
}
void Destroy(void *value,unsigned shape) {
    if (shape == 0) Release(Word(value,0),true);
    else if (shape == 2) Release(Word(value,8),false);
    else if (shape == 3) { Release(Word(value,0),false); Release(Word(value,8),false); }
}
void Copy(void *dest,const void *src,unsigned shape) {
    std::memcpy(dest,src,16);
    if (shape == 0) Retain(Word(src,0),true);
    else if (shape == 2) Retain(Word(src,8),false);
    else if (shape == 3) { Retain(Word(src,0),false); Retain(Word(src,8),false); }
}
void AssignWord(void *dest,const void *src,unsigned offset,bool objc) {
    uintptr_t old = Word(dest,offset), next = Word(src,offset);
    std::memcpy((unsigned char *)dest + offset,&next,8);
    Release(old,objc); Retain(next,objc);
}
} // namespace
extern "C" int VM27EFICVWQuery(const void *metadata,VM27EFICVWInfo *info) {
    Contract contract{}; if (!info || !Decode(metadata,contract)) return 0;
    *info = contract.info; return 1;
}
extern "C" unsigned VM27EFICVWGetEnumTag(const void *value,const void *metadata) {
    Contract contract = Require(metadata); Shape(contract,value); return contract.outer(value);
}
extern "C" void VM27EFICVWDestroy(void *value,const void *metadata) {
    Contract contract = Require(metadata); Destroy(value,Shape(contract,value));
}
extern "C" void *VM27EFICVWInitWithCopy(void *dest,const void *src,const void *metadata) {
    Contract contract = Require(metadata); RequirePair(dest,src);
    Copy(dest,src,Shape(contract,src)); return dest;
}
extern "C" void *VM27EFICVWBufferCopy(void *dest,const void *src,const void *metadata) {
    return VM27EFICVWInitWithCopy(dest,src,metadata); // Exact flags establish inline storage.
}
extern "C" void *VM27EFICVWAssignWithCopy(void *dest,const void *src,const void *metadata) {
    Contract contract = Require(metadata); RequirePair(dest,src);
    unsigned old = Shape(contract,dest), next = Shape(contract,src);
    if (old != next) { Destroy(dest,old); Copy(dest,src,next); }
    else if (next == 0) { AssignWord(dest,src,0,true); std::memcpy((unsigned char *)dest+8,(const unsigned char *)src+8,8); }
    else if (next == 2) { std::memcpy(dest,src,8); AssignWord(dest,src,8,false); }
    else if (next == 3) { AssignWord(dest,src,0,false); AssignWord(dest,src,8,false); }
    else std::memcpy(dest,src,16); // Authentic inline/empty Data branch has no owned refs.
    return dest;
}
extern "C" void *VM27EFICVWAssignWithTake(void *dest,void *src,const void *metadata) {
    Contract contract = Require(metadata); RequirePair(dest,src);
    unsigned old = Shape(contract,dest); Shape(contract,src);
    Destroy(dest,old); std::memcpy(dest,src,16); return dest;
}
