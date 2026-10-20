#ifndef VM27_SWIFT_STATIC_CN_FIXED_LAYOUT_V1_H
#define VM27_SWIFT_STATIC_CN_FIXED_LAYOUT_V1_H

// StaticCN data schema only. No Swift class symbol, object, factory, runtime
// registration or provider loading is supplied by this header. Pointer words
// are storage slots requiring genuine relocation/PAC construction in a future
// LLVM provider; these structs must never be cast onto a live runtime class.
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace vm27::static_cn_v1 {
struct ObjCClassSlots {
    std::uint64_t isa;
    std::uint64_t superclass;
    std::uint64_t cache;
    std::uint64_t cacheFlagsOrVtable;
    std::uint64_t classROTaggedPointer;
};
struct ClassRO {
    std::uint32_t flags;
    std::uint32_t instanceStart;
    std::uint32_t instanceSize;
    std::uint32_t reserved;
    std::uint64_t ivarLayout;
    std::uint64_t name;
    std::uint64_t methods;
    std::uint64_t protocols;
    std::uint64_t ivars;
    std::uint64_t weakIvarLayout;
    std::uint64_t properties;
};
struct PositiveMetadata {
    ObjCClassSlots objc;
    std::uint32_t flags;
    std::uint32_t instanceAddressPoint;
    std::uint32_t instanceSize;
    std::uint16_t instanceAlignmentMask;
    std::uint16_t reserved;
    std::uint32_t classSize;
    std::uint32_t classAddressPoint;
    std::uint64_t nominalDescriptor;
    std::uint64_t ivarDestroyer;
    std::uint64_t inheritedAllocator;
    std::uint64_t inheritedWithUnsafeBufferOfObjects;
    std::uint64_t countAndCapacityFieldOffset;
    std::uint64_t doNotCallMeBase;
    std::uint64_t withVerbatimBridgedUnsafeBuffer;
    std::uint64_t getNonVerbatimBridgingBuffer;
    std::uint64_t canStoreElements;
    std::uint64_t staticElementType;
    std::uint64_t doNotCallMe;
};
struct CompleteMetadata {
    std::uint64_t negativeReserved;
    std::uint64_t deallocator;
    std::uint64_t nativeObjectValueWitness;
    PositiveMetadata cn;
};
struct MethodDescriptor {
    std::uint32_t flags;
    std::int32_t implementationRelative;
};
struct MethodOverride {
    std::int32_t parentDescriptorIndirectableRelative;
    std::int32_t parentMethodIndirectableRelative;
    std::int32_t implementationRelative;
};
struct NominalDescriptor {
    std::uint32_t flags;
    std::int32_t moduleRelative;
    std::int32_t typeNameRelative;
    std::int32_t accessorRelative;
    std::int32_t fieldDescriptorRelative;
    std::int32_t superclassTypeRelative;
    std::uint32_t metadataNegativeWords;
    std::uint32_t metadataPositiveWords;
    std::uint32_t immediateMembers;
    std::uint32_t fields;
    std::uint32_t fieldOffsetVector;
    std::uint32_t vtableOffset;
    std::uint32_t vtableCount;
    MethodDescriptor ownInitializer;
    std::uint32_t overrideCount;
    MethodOverride overrides[5];
};
inline constexpr std::uint32_t kDescriptorFlags=0xc0000050;
inline constexpr std::uint32_t kClassFlags=2;
inline constexpr std::uint32_t kNegativeWords=3;
inline constexpr std::uint32_t kPositiveWords=19;
inline constexpr std::uint32_t kClassBytes=176;
inline constexpr std::uint32_t kAddressPoint=24;
inline constexpr std::uint32_t kInstanceBytes=32;
inline constexpr std::uint16_t kInstanceAlignmentMask=7;
inline constexpr std::uint32_t kOwnVtableOffset=18;
inline constexpr std::uint32_t kOwnVtableCount=1;
inline constexpr std::uint32_t kOverrideCount=5;
inline constexpr char kSwiftName[]="Swift.__StaticArrayStorage";
inline constexpr char kObjCName[]="_TtCs20__StaticArrayStorage";
static_assert(sizeof(std::uint64_t)==8 && sizeof(std::uint32_t)==4);
static_assert(std::is_standard_layout_v<PositiveMetadata>);
static_assert(std::is_standard_layout_v<CompleteMetadata>);
static_assert(std::is_standard_layout_v<NominalDescriptor>);
static_assert(sizeof(ObjCClassSlots)==40);
static_assert(sizeof(ClassRO)==72);
static_assert(sizeof(PositiveMetadata)==152);
static_assert(sizeof(CompleteMetadata)==176);
static_assert(offsetof(CompleteMetadata,cn)==24);
static_assert(offsetof(PositiveMetadata,flags)==40);
static_assert(offsetof(PositiveMetadata,instanceAddressPoint)==44);
static_assert(offsetof(PositiveMetadata,instanceSize)==48);
static_assert(offsetof(PositiveMetadata,instanceAlignmentMask)==52);
static_assert(offsetof(PositiveMetadata,classSize)==56);
static_assert(offsetof(PositiveMetadata,classAddressPoint)==60);
static_assert(offsetof(PositiveMetadata,nominalDescriptor)==64);
static_assert(offsetof(PositiveMetadata,ivarDestroyer)==72);
static_assert(offsetof(PositiveMetadata,inheritedAllocator)==80);
static_assert(offsetof(PositiveMetadata,inheritedWithUnsafeBufferOfObjects)==88);
static_assert(offsetof(PositiveMetadata,countAndCapacityFieldOffset)==96);
static_assert(offsetof(PositiveMetadata,doNotCallMeBase)==104);
static_assert(offsetof(PositiveMetadata,withVerbatimBridgedUnsafeBuffer)==112);
static_assert(offsetof(PositiveMetadata,getNonVerbatimBridgingBuffer)==120);
static_assert(offsetof(PositiveMetadata,canStoreElements)==128);
static_assert(offsetof(PositiveMetadata,staticElementType)==136);
static_assert(offsetof(PositiveMetadata,doNotCallMe)==144);
static_assert(sizeof(NominalDescriptor)==124);
static_assert(offsetof(NominalDescriptor,ownInitializer)==52);
static_assert(offsetof(NominalDescriptor,overrideCount)==60);
static_assert(offsetof(NominalDescriptor,overrides)==64);
} // namespace vm27::static_cn_v1
#endif
