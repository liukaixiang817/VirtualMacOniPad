// 六个 Builtin.Word 的 ABI 来自原始 SwiftCore 64-byte 函数及 UH 唯一调用方。
// 原始函数固定查询 platform=1(macOS) 与 platform=2(iOS)，由系统选择适用版本。
// 版本编码与原始 compiler-runtime lsl/bfi/bfxil 指令相同；不把 iPad 冒充新系统。
// LLVM compiler-rt os_version_check.c 仅用于交叉核对；本机原始代码没有 9999 特例。
// 要求真实 _availability_version_check 强导出；没有伪造返回值或旧系统缺符号回退。
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t platform;
    uint32_t version;
} VM27AvailabilityVersion;

_Static_assert(sizeof(uintptr_t) == 8, "Six-word ABI requires 64-bit words");
_Static_assert(sizeof(VM27AvailabilityVersion) == 8, "Real dyld version pair layout");
_Static_assert(_Alignof(VM27AvailabilityVersion) == 4, "Real dyld version pair alignment");

extern bool _availability_version_check(uint32_t count,
    VM27AvailabilityVersion versions[]);

#ifndef VM27_AVAILABILITY_ASM_NAME
#define VM27_AVAILABILITY_ASM_NAME "_$ss042_stdlib_isOSVersionAtLeastOrVariantVersiondE0yBi1_Bw_BwBwBwBwBwtF"
#endif

__attribute__((swiftcall, visibility("default")))
bool VM27OSOrVariantVersionAtLeast(uintptr_t major, uintptr_t minor,
    uintptr_t patch, uintptr_t variantMajor, uintptr_t variantMinor,
    uintptr_t variantPatch) __asm__(VM27_AVAILABILITY_ASM_NAME);

static uint32_t EncodedVersion(uintptr_t major, uintptr_t minor, uintptr_t patch) {
    return ((uint32_t)major << 16) |
        (((uint32_t)minor & UINT32_C(0xff)) << 8) |
        ((uint32_t)patch & UINT32_C(0xff));
}

__attribute__((swiftcall, visibility("default")))
bool VM27OSOrVariantVersionAtLeast(uintptr_t major, uintptr_t minor,
    uintptr_t patch, uintptr_t variantMajor, uintptr_t variantMinor,
    uintptr_t variantPatch) {
    VM27AvailabilityVersion versions[2] = {
        {UINT32_C(1), EncodedVersion(major, minor, patch)},
        {UINT32_C(2), EncodedVersion(variantMajor, variantMinor, variantPatch)}
    };
    return _availability_version_check(UINT32_C(2), versions);
}
