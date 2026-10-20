// Finite adaptation of Swift BytecodeLayouts.cpp at
// 5ea0a2a5d8e126628da27747739e8d017c1d4882; Apache 2.0 with Runtime Exception.
// The six actual HID tags are End, NativeStrong, Bridge, ObjC, Existential,
// MultiPayloadEnumFN. Original lazy compatibility override hooks are separate.
#include "modern_swift_hid_observed_cvw_compat.h"
#define VM27_HID_BITWISE_TAKE_COMPONENT_FIXTURE 1
#include "modern_swift_hid_bitwise_take_compat.cpp"
#include <ptrauth.h>
#include <cstring>

extern "C" void *swift_retain(void *);
extern "C" void swift_release(void *);
extern "C" void *swift_bridgeObjectRetain(void *);
extern "C" void swift_bridgeObjectRelease(void *);
extern "C" void *objc_retain(void *);
extern "C" void objc_release(void *);

namespace VM27HIDObservedCVW {
using Init = void *(*)(void *, const void *, const void *);
using Destroy = void (*)(void *, const void *);
struct Table {
    Init __ptrauth(0,1,0xda4a) buffer;
    Destroy __ptrauth(0,1,0x04f8) destroy;
    Init __ptrauth(0,1,0xe3ba) copy;
    Init __ptrauth(0,1,0x8751) assignCopy;
    Init __ptrauth(0,1,0x48d8) take;
    Init __ptrauth(0,1,0xefda) assignTake;
    void *getTag, *setTag;
    Layout layout;
};
using TagFunction = unsigned (*)(const void *);
constexpr uint32_t NonInline = 0x00020000;
constexpr uint32_t NonBitwise = 0x00100000;
constexpr uint32_t Incomplete = 0x00400000;
constexpr uint64_t SkipMask = 0x00ffffffffffffff;
// Exact AND immediate used by the original native/ObjC strong handlers.
constexpr uintptr_t ReferenceMask = 0x0ffffffffffffff8;

bool Number(const Program &program, size_t at, size_t end, uint64_t &value) {
    if (!program.bytes || end > program.byteCount || at > end || end - at < 8) return false;
    std::memcpy(&value, program.bytes + at, 8);
    return true;
}

TagFunction Function(const Program &program, size_t at, size_t end) {
    uint64_t relative = 0;
    if (!Number(program, at, end, relative) || !program.allowFunction) return nullptr;
    intptr_t distance = int32_t(relative);
    uintptr_t slot = uintptr_t(program.bytes + at);
    uintptr_t address = slot + distance;
    if ((distance > 0 && address < slot) || (distance < 0 && address > slot) ||
        !program.allowFunction((const void *)address, program.functionContext)) return nullptr;
#if __has_feature(ptrauth_calls)
    return (TagFunction)ptrauth_sign_unauthenticated((void *)address, ptrauth_key_function_pointer, 0);
#else
    return (TagFunction)address;
#endif
}

bool ValidateSequence(const Program &program, size_t begin, size_t end,
                      size_t valueLimit, unsigned depth, bool relativeFunctions, size_t &valueBytes) {
    if (depth >= 8 || begin >= end || end > program.byteCount || (end - begin) % 8) return false;
    size_t at = begin, offset = 0;
    while (at < end) {
        uint64_t instruction = 0;
        if (!Number(program, at, end, instruction)) return false;
        at += 8;
        const unsigned tag = instruction >> 56;
        size_t skip = instruction & SkipMask;
        if (offset > valueLimit || skip > valueLimit - offset) return false;
        offset += skip;
        if (!tag) { valueBytes = offset; return at == end; }
        if (tag == 2 || tag == 8 || tag == 10 || tag == 14) {
            size_t bytes = tag == 14 ? 24 : 8;
            if (bytes > valueLimit - offset) return false;
            offset += bytes;
            continue;
        }
        if (tag != 20 || !relativeFunctions || !Function(program, at, end)) return false;
        uint64_t count = 0, references = 0, enumSize = 0;
        if (!Number(program, at + 8, end, count) || !Number(program, at + 16, end, references) ||
            !Number(program, at + 24, end, enumSize) || !count || count > 64 ||
            !references || references > 65536 || enumSize > valueLimit - offset) return false;
        at += 32;
        if (at > end || count * 8 > end - at) return false;
        size_t table = at;
        at += count * 8;
        if (references > end - at) return false;
        uint64_t previous = 0;
        for (size_t index = 0; index < count; ++index) {
            uint64_t start = 0, limit = references;
            if (!Number(program, table + index * 8, end, start) ||
                (index + 1 < count && !Number(program, table + (index + 1) * 8, end, limit)) ||
                (!index && start != 0) || start >= limit || limit > references ||
                (index && start <= previous)) return false;
            size_t nested = 0;
            if (!ValidateSequence(program, at + start, at + limit, enumSize, depth + 1, relativeFunctions, nested)) return false;
            previous = start;
        }
        at += references;
        offset += enumSize;
    }
    return false;
}

bool Validate(const Program &program, const Layout &layout) {
    if (!program.bytes || program.byteCount < 24 || program.byteCount > 65536 ||
        !layout.size || layout.size > 4096 || layout.stride < layout.size ||
        layout.flags & (NonBitwise | Incomplete)) return false;
    uint64_t flags = 0, length = 0;
    if (!Number(program, 0, program.byteCount, flags) || !Number(program, 8, program.byteCount, length) ||
        (flags != 0 && flags != uint64_t(1) << 63) || length > program.byteCount - 24 ||
        length + 24 != program.byteCount) return false;
    size_t bytes = 0;
    return ValidateSequence(program, 16, program.byteCount, layout.size, 0, flags >> 63, bytes) && bytes == layout.size;
}

const Table *Witnesses(const void *metadata) {
    return (const Table *)VM27HIDBitwiseTake::DataPointer(metadata, -8, 0x2e3f);
}

void *Reference(const unsigned char *address, bool mask) {
    uintptr_t word = 0;
    std::memcpy(&word, address, 8);
    return (void *)(mask ? word & ReferenceMask : word);
}

void Retain(unsigned tag, void *object) {
    if (tag == 2) swift_retain(object);
    else if (tag == 8) swift_bridgeObjectRetain(object);
    else objc_retain(object);
}
void Release(unsigned tag, void *object) {
    if (tag == 2) swift_release(object);
    else if (tag == 8) swift_bridgeObjectRelease(object);
    else objc_release(object);
}

void Existential(Operation operation, unsigned char *destination, const unsigned char *source) {
    const void *sourceType = nullptr, *destinationType = nullptr;
    if (source) std::memcpy(&sourceType, source + 24, 8);
    if (operation != Operation::InitializeCopy) std::memcpy(&destinationType, destination + 24, 8);
    if (operation == Operation::Destroy) {
        auto table = Witnesses(destinationType);
        if (!table) __builtin_trap();
        if (table->layout.flags & NonInline) swift_release(Reference(destination, false));
        else table->destroy(destination, destinationType);
        return;
    }
    auto from = Witnesses(sourceType);
    if (!from) __builtin_trap();
    if (operation == Operation::InitializeCopy) {
        from->buffer(destination, source, sourceType);
        return;
    }
    auto into = Witnesses(destinationType);
    if (!into) __builtin_trap();
    if (sourceType == destinationType) {
        if (from->layout.flags & NonInline) {
            swift_release(Reference(destination, false));
            std::memcpy(destination, source, 8);
            swift_retain(Reference(source, false));
        } else from->assignCopy(destination, source, sourceType);
        return;
    }
    if (into->layout.flags & NonInline) swift_release(Reference(destination, false));
    else into->destroy(destination, destinationType);
    if (from->layout.flags & NonInline) {
        std::memcpy(destination, source, 8);
        swift_retain(Reference(source, false));
    } else from->copy(destination, source, sourceType);
}

size_t Walk(Operation operation, const Program &program, size_t begin, size_t end,
            size_t initialOffset, unsigned char *destination, const unsigned char *source) {
    size_t at = begin, offset = initialOffset;
    while (at < end) {
        uint64_t instruction = 0;
        if (!Number(program, at, end, instruction)) __builtin_trap();
        at += 8;
        unsigned tag = instruction >> 56;
        size_t skip = instruction & SkipMask;
        if (skip && operation != Operation::Destroy)
            std::memcpy(destination + offset, source + offset, skip);
        offset += skip;
        if (!tag) return offset;
        if (tag == 2 || tag == 8 || tag == 10) {
            bool mask = tag != 8;
            if (operation == Operation::Destroy) Release(tag, Reference(destination + offset, mask));
            else {
                void *old = operation == Operation::AssignCopy ? Reference(destination + offset, mask) : nullptr;
                void *next = Reference(source + offset, mask);
                std::memcpy(destination + offset, source + offset, 8);
                if (operation == Operation::AssignCopy) Release(tag, old);
                Retain(tag, next);
            }
            offset += 8;
            continue;
        }
        if (tag == 14) {
            Existential(operation, destination + offset, source ? source + offset : nullptr);
            offset += 24;
            continue;
        }
        uint64_t count = 0, references = 0, enumSize = 0;
        auto getter = Function(program, at, end);
        if (tag != 20 || !getter || !Number(program, at + 8, end, count) ||
            !Number(program, at + 16, end, references) || !Number(program, at + 24, end, enumSize)) __builtin_trap();
        at += 32;
        size_t cases = at, body = at + count * 8;
        auto selection = [&](unsigned index, Operation selected) {
            uint64_t first = 0, last = references;
            if (!Number(program, cases + index * 8, end, first) ||
                (index + 1 < count && !Number(program, cases + (index + 1) * 8, end, last))) __builtin_trap();
            return Walk(selected, program, body + first, body + last, offset, destination, source);
        };
        const size_t limit = offset + enumSize;
        if (operation == Operation::Destroy) {
            unsigned tagValue = getter(destination + offset);
            if (tagValue < count) selection(tagValue, Operation::Destroy);
        } else {
            unsigned srcTag = getter(source + offset);
            unsigned dstTag = operation == Operation::AssignCopy ? getter(destination + offset) : unsigned(count);
            size_t written = offset;
            if (srcTag < count) {
                if (operation == Operation::AssignCopy && dstTag < count && srcTag != dstTag)
                    selection(dstTag, Operation::Destroy);
                written = selection(srcTag, operation == Operation::AssignCopy && srcTag == dstTag ?
                    Operation::AssignCopy : Operation::InitializeCopy);
            } else if (operation == Operation::AssignCopy && dstTag < count) selection(dstTag, Operation::Destroy);
            if (written > limit) __builtin_trap();
            if (written < limit) std::memcpy(destination + written, source + written, limit - written);
        }
        at = body + references;
        offset = limit;
    }
    __builtin_trap();
}

bool Apply(Operation operation, const Program &program, const Layout &layout,
           void *destination, const void *source, void **valueAddress) {
    if (!destination || (operation != Operation::Destroy && !source) || !Validate(program, layout)) return false;
    auto into = (unsigned char *)destination;
    auto from = (const unsigned char *)source;
    if (operation == Operation::CopyBuffer && layout.flags & NonInline) {
        std::memcpy(destination, source, 8);
        swift_retain(Reference(from, false));
        if (valueAddress) *valueAddress = (unsigned char *)Reference(into, false) + 16;
        return true;
    }
    if (operation == Operation::AssignTake) {
        Walk(Operation::Destroy, program, 16, program.byteCount, 0, into, nullptr);
        std::memcpy(destination, source, layout.size);
    } else {
        auto actual = operation == Operation::CopyBuffer ? Operation::InitializeCopy : operation;
        if (Walk(actual, program, 16, program.byteCount, 0, into, from) != layout.size) __builtin_trap();
    }
    if (valueAddress) *valueAddress = destination;
    return true;
}
} // namespace VM27HIDObservedCVW
