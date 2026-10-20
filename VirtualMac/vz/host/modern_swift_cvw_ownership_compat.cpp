// This source file adapts the Swift.org open source project's runtime code.
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception.
// See vendor/swift-bytecode-enum-tag/LICENSE.txt.
// App-written bounded adaptation of Swift commit 5ea0a2a5d8e126628da27747739e8d017c1d4882
// BytecodeLayouts.cpp: bridgeDestroy, bridgeCopy, bridgeAssignWithCopy,
// swift_cvw_assignWithTakeImpl and initializeBufferWithCopyOfBufferImpl.
// This covers one identified type, not the entire interpreter or registry.
#include "modern_swift_cvw_ownership_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>

extern "C" void *swift_bridgeObjectRetain(void *);
extern "C" void swift_bridgeObjectRelease(void *);
static_assert(sizeof(void *) == 8, "Audited LP64 ABI only");
namespace {
constexpr unsigned char kVZUUID[16] = {0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,
    0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
constexpr unsigned char kOldSwiftUUID[16] = {0xf8,0x96,0xd1,0x45,0xe0,0x25,0x39,0xd6,
    0xaf,0xd3,0xbc,0x0a,0x2a,0xd4,0xf8,0x39};
constexpr unsigned char kNewSwiftUUID[16] = {0xc9,0xb3,0x6d,0xa7,0xbb,0x34,0x35,0xaf,
    0xbc,0x5d,0x91,0xec,0xbc,0xaa,0x9e,0xd0};
// The complete original 112-byte program. Only the relocated relative getter
// slot is excluded from comparison; that callback has a separate code/owner gate.
constexpr uint64_t kProgram[14] = {0x8000000000000000,88,0x1400000000000000,
    0xfffffffffff47e98,2,32,17,0,16,0x0800000000000008,0,
    0x0800000000000008,0,0};
constexpr uint32_t kGetter[3] = {0x39404008,0x12000100,0xd65f03c0};
using TagFunction = unsigned (*)(const void *);
struct Contract { VM27CVWOwnershipInfo info{}; TagFunction tag = nullptr; };

bool Read(const void *address, void *output, size_t size) {
    if (!address || !output || size == 0 || size > 4096) return false;
    vm_size_t copied = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)address, size,
        (vm_address_t)output, &copied) == KERN_SUCCESS && copied == size;
}
bool UUID(const void *base, unsigned char result[16]) {
    mach_header_64 header{};
    if (!Read(base, &header, sizeof(header)) || header.magic != MH_MAGIC_64 ||
        header.sizeofcmds > 65536 || header.ncmds > 1024) return false;
    uintptr_t start = (uintptr_t)base + sizeof(header);
    uintptr_t end = start + header.sizeofcmds;
    if (end < start) return false;
    for (uint32_t i = 0; i < header.ncmds; ++i) {
        load_command command{};
        if (start > end || end - start < sizeof(command) ||
            !Read((void *)start, &command, sizeof(command)) ||
            command.cmdsize < sizeof(command) || command.cmdsize > end - start)
            return false;
        if (command.cmd == LC_UUID && command.cmdsize == sizeof(uuid_command)) {
            uuid_command uuid{};
            if (!Read((void *)start, &uuid, sizeof(uuid))) return false;
            std::memcpy(result, uuid.uuid, 16); return true;
        }
        start += command.cmdsize;
    }
    return false;
}
bool Owner(const void *address, const unsigned char uuid[16], const void **base) {
    Dl_info image{}; unsigned char actual[16]{};
    if (!address || !dladdr(address, &image) || !image.dli_fbase ||
        !UUID(image.dli_fbase, actual) || std::memcmp(actual, uuid, 16)) return false;
    if (base) *base = image.dli_fbase;
    return true;
}
bool SwiftPrimitives() {
    const void *retain = ptrauth_strip((void *)&swift_bridgeObjectRetain,
                                      ptrauth_key_function_pointer);
    const void *release = ptrauth_strip((void *)&swift_bridgeObjectRelease,
                                       ptrauth_key_function_pointer);
    const void *retainOwner = nullptr, *releaseOwner = nullptr;
    bool old = Owner(retain, kOldSwiftUUID, &retainOwner) &&
               Owner(release, kOldSwiftUUID, &releaseOwner);
    bool modern = Owner(retain, kNewSwiftUUID, &retainOwner) &&
                  Owner(release, kNewSwiftUUID, &releaseOwner);
    return (old || modern) && retainOwner == releaseOwner;
}
bool Decode(const void *metadata, Contract &contract) {
    if (!metadata || (uintptr_t)metadata < 16 || ((uintptr_t)metadata & 7)) return false;
    const void *metadataOwner = nullptr;
    if (!Owner(metadata, kVZUUID, &metadataOwner)) return false;
    const void *slots[2]{};
    if (!Read((const unsigned char *)metadata - 16, slots, sizeof(slots))) return false;
    const unsigned char *layout = (const unsigned char *)slots[0];
    const unsigned char *table = (const unsigned char *)slots[1];
    if (!layout || !table) return false;
#if __has_feature(ptrauth_calls)
    layout = (const unsigned char *)ptrauth_auth_data(layout,
        ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata - 16, 0x8b65));
    table = (const unsigned char *)ptrauth_auth_data(table,
        ptrauth_key_process_independent_data,
        ptrauth_blend_discriminator((const unsigned char *)metadata - 8, 0x2e3f));
#endif
    if ((uintptr_t)layout & 1) return false;
    const void *layoutOwner = nullptr, *tableOwner = nullptr;
    if (!Owner(layout, kVZUUID, &layoutOwner) ||
        !Owner(table, kVZUUID, &tableOwner) || layoutOwner != tableOwner ||
        metadataOwner != layoutOwner) return false;
    uint64_t program[14]{};
    if (!Read(layout, program, sizeof(program))) return false;
    for (size_t i = 0; i < 14; ++i)
        if (i != 3 && program[i] != kProgram[i]) return false;
    VM27CVWOwnershipInfo info{};
    if (!Read(table + 64, &info, sizeof(info)) || info.size != 17 || info.stride != 24 ||
        info.flags != 0x02210007 || info.extraInhabitants != 254) return false;
    int32_t relative = (int32_t)program[3];
    uintptr_t slot = (uintptr_t)(layout + 24);
    uintptr_t callback = slot + (intptr_t)relative;
    if ((relative > 0 && callback < slot) || (relative < 0 && callback > slot)) return false;
    const void *getterOwner = nullptr;
    uint32_t code[3]{};
    if (!Owner((void *)callback, kVZUUID, &getterOwner) || getterOwner != layoutOwner ||
        !Read((void *)callback, code, sizeof(code)) || std::memcmp(code, kGetter, sizeof(code)) ||
        !SwiftPrimitives()) return false;
#if __has_feature(ptrauth_calls)
    contract.tag = (TagFunction)ptrauth_sign_unauthenticated((void *)callback,
        ptrauth_key_function_pointer, 0);
#else
    contract.tag = (TagFunction)callback;
#endif
    contract.info = info; return true;
}
Contract Require(const void *metadata) {
    Contract contract{};
    if (!Decode(metadata, contract)) __builtin_trap();
    return contract;
}
void RequireValue(const Contract &contract, const void *value) {
    if (!value || ((uintptr_t)value & 7) || contract.tag(value) > 1) __builtin_trap();
}
void RequirePair(const Contract &contract, void *dest, const void *src, bool initializedDest) {
    uintptr_t d = (uintptr_t)dest, s = (uintptr_t)src;
    if (!dest || !src || (d & 7) || (s & 7) || d > UINTPTR_MAX - 24 ||
        s > UINTPTR_MAX - 24 || !(d + 24 <= s || s + 24 <= d)) __builtin_trap();
    RequireValue(contract, src);
    if (initializedDest) RequireValue(contract, dest);
}
void *Bridge(const void *value) {
    void *word = nullptr; std::memcpy(&word, (const unsigned char *)value + 8, 8); return word;
}
void Copy(void *dest, const void *src) {
    // Preserve the original tagged Bridge word. The native primitive owns its
    // tag handling; no invented pointer stripping or guessed object header.
    std::memcpy(dest, src, 17);
    swift_bridgeObjectRetain(Bridge(src));
}
void Destroy(void *value) { swift_bridgeObjectRelease(Bridge(value)); }
} // namespace

extern "C" int VM27CVWOwnershipQuery(const void *metadata, VM27CVWOwnershipInfo *info) {
    Contract contract{};
    if (!info || !Decode(metadata, contract)) return 0;
    *info = contract.info; return 1;
}
extern "C" void swift_cvw_destroy(void *value, const void *metadata) {
    Contract contract = Require(metadata); RequireValue(contract, value); Destroy(value);
}
extern "C" void *swift_cvw_initWithCopy(void *dest, const void *src, const void *metadata) {
    Contract contract = Require(metadata); RequirePair(contract, dest, src, false);
    Copy(dest, src); return dest;
}
extern "C" void *swift_cvw_initializeBufferWithCopyOfBuffer(void *dest, const void *src,
                                                           const void *metadata) {
    Contract contract = Require(metadata); RequirePair(contract, dest, src, false);
    // The exact authenticated flags above establish inline storage. No box
    // fallback is claimed or performed for an unsupported non-inline type.
    Copy(dest, src); return dest;
}
extern "C" void *swift_cvw_assignWithCopy(void *dest, const void *src, const void *metadata) {
    Contract contract = Require(metadata); RequirePair(contract, dest, src, true);
    if (contract.tag(dest) != contract.tag(src)) { Destroy(dest); Copy(dest, src); }
    else {
        void *old = Bridge(dest), *next = Bridge(src);
        std::memcpy(dest, src, 17);
        swift_bridgeObjectRelease(old); swift_bridgeObjectRetain(next);
    }
    return dest;
}
extern "C" void *swift_cvw_assignWithTake(void *dest, void *src, const void *metadata) {
    Contract contract = Require(metadata); RequirePair(contract, dest, src, true);
    // Exact flags exclude IsNonBitwiseTakable; source ownership transfers.
    Destroy(dest); std::memcpy(dest, src, 17); return dest;
}
