// 普通 macOS 对照：私有命名的同一源实现与真实 libswiftCore 六参数函数逐次比较。
// 不加载 iOS candidate，不接触 CPU/Hypervisor，不把 macOS 运行当成 iPad 运行。
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef bool __attribute__((swiftcall)) (*AvailabilityFn)(uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern bool __attribute__((swiftcall)) VM27OSOrVariantVersionAtLeast(
    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t)
    __asm__("VM27OSOrVariantVersionAtLeastFixture");

static unsigned checks, trueCount, falseCount;
static void Compare(AvailabilityFn native, const uintptr_t values[6]) {
    bool actual = VM27OSOrVariantVersionAtLeast(values[0], values[1], values[2],
        values[3], values[4], values[5]);
    bool expected = native(values[0], values[1], values[2], values[3], values[4], values[5]);
    if (actual != expected) {
        fprintf(stderr, "Mismatch at query %u\n", checks);
        exit(3);
    }
    checks++;
    if (actual) trueCount++; else falseCount++;
}

int main(void) {
    void *handle = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "Genuine SwiftCore dlopen: %s\n", dlerror()); return 4; }
    void *raw = dlsym(handle, "$ss042_stdlib_isOSVersionAtLeastOrVariantVersiondE0yBi1_Bw_BwBwBwBwBwtF");
    Dl_info origin;
    if (!raw || !dladdr(raw, &origin) || !origin.dli_fname ||
        !strstr(origin.dli_fname, "libswiftCore.dylib")) { fprintf(stderr, "Genuine SwiftCore dlsym/provenance unavailable: %s\n", dlerror()); return 5; }
    AvailabilityFn native = (AvailabilityFn)raw;
    for (uintptr_t primary = 0; primary <= 35; primary++) {
        for (uintptr_t variant = 0; variant <= 35; variant++) {
            for (uintptr_t minor = 0; minor <= 3; minor++) {
                for (uintptr_t patch = 0; patch <= 2; patch++) {
                    uintptr_t values[6] = {primary, minor, patch, variant, minor, patch};
                    Compare(native, values);
                }
            }
        }
    }
    const uintptr_t edges[] = {0,1,15,18,27,255,256,65535,65536,9999,
        UINT32_MAX, UINT64_C(0x100000000), UINT64_C(0x123456780000000f), UINTPTR_MAX};
    for (unsigned slot = 0; slot < 6; slot++) {
        for (unsigned e = 0; e < sizeof(edges)/sizeof(edges[0]); e++) {
            uintptr_t values[6] = {15,0,0,18,0,0};
            values[slot] = edges[e];
            Compare(native, values);
        }
    }
    if (!trueCount || !falseCount || checks != 15636) { fprintf(stderr, "Actual counts %u/%u/%u\n", checks, trueCount, falseCount); return 6; }
    printf("{\"checks\":%u,\"trueResults\":%u,\"falseResults\":%u,"
           "\"sameSourceFixtureComparedToGenuineSwiftCore\":true,\"deviceOperations\":0}\n",
           checks, trueCount, falseCount);
    return dlclose(handle) == 0 ? 0 : 7;
}
