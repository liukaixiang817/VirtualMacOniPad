#include "vm27_actual_executable_image_v1.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#if TARGET_OS_OSX
#include <mach/mach_vm.h>
#else
/* The iOS SDK omits this header; this is the real libSystem MIG ABI, also
 * used by the existing production PVG observation source. */
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
#endif

static bool ImageReadV1(uintptr_t source, void *target, size_t size) {
    if (!source || !target || !size || source > UINTPTR_MAX - size) return false;
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), source, size,
        (mach_vm_address_t)(uintptr_t)target, &copied) == KERN_SUCCESS && copied == size;
}
static bool ImagePathV1(const char *source, char target[PATH_MAX]) {
    uintptr_t base = (uintptr_t)source;
    if (!base || !vm_page_size) return false;
    for (size_t used = 0; used < PATH_MAX;) {
        if (base > UINTPTR_MAX - used) return false;
        uintptr_t address = base + used;
        size_t size = 16, page = vm_page_size - address % vm_page_size;
        if (size > page) size = page;
        if (size > PATH_MAX - used) size = PATH_MAX - used;
        char bytes[16];
        if (!ImageReadV1(address, bytes, size)) return false;
        for (size_t i = 0; i < size; ++i) {
            target[used + i] = bytes[i];
            if (!bytes[i]) return used + i != 0;
        }
        used += size;
    }
    return false;
}
static bool ImageCanonicalPathV1(const char *source, const char *expected) {
    char copied[PATH_MAX], canonical[PATH_MAX];
    return ImagePathV1(source, copied) && realpath(copied, canonical) &&
        !strcmp(canonical, expected);
}
static bool ImageHeaderV1(const struct mach_header_64 *header,
                          struct mach_header_64 *copy) {
    return ImageReadV1((uintptr_t)header, copy, sizeof(*copy)) &&
        copy->magic == MH_MAGIC_64 && (uint32_t)copy->cputype == 0x100000c &&
        copy->filetype == MH_EXECUTE && copy->ncmds && copy->ncmds <= 512 &&
        copy->sizeofcmds <= 1024 * 1024 && copy->sizeofcmds >= copy->ncmds * 8u;
}
static bool ImageUUIDV1(const struct mach_header_64 *header,
                       const struct mach_header_64 *copy, uint8_t uuid[16]) {
    uintptr_t base = (uintptr_t)header;
    if (base > UINTPTR_MAX - sizeof(*copy) ||
        base + sizeof(*copy) > UINTPTR_MAX - copy->sizeofcmds) return false;
    uintptr_t commands = base + sizeof(*copy);
    size_t offset = 0; bool found = false;
    for (uint32_t i = 0; i < copy->ncmds; ++i) {
        struct load_command lc;
        if (offset > copy->sizeofcmds || copy->sizeofcmds - offset < sizeof(lc) ||
            !ImageReadV1(commands + offset, &lc, sizeof(lc)) || lc.cmdsize < 8 ||
            (lc.cmdsize & 7) || lc.cmdsize > copy->sizeofcmds - offset) return false;
        if (lc.cmd == LC_UUID) {
            if (found || lc.cmdsize != sizeof(struct uuid_command) ||
                !ImageReadV1(commands + offset + 8, uuid, 16)) return false;
            found = true;
        }
        offset += lc.cmdsize;
    }
    return found && offset == copy->sizeofcmds;
}
int VM27ActualExecutableImageFindV1(const char *canonicalExecutable,
                                  VM27ActualExecutableImageV1 *out) {
    if (!canonicalExecutable || !out) return EINVAL;
    char supplied[PATH_MAX], canonical[PATH_MAX];
    if (!ImagePathV1(canonicalExecutable, supplied) || supplied[0] != '/' ||
        !realpath(supplied, canonical) || strcmp(canonical, supplied)) return EINVAL;
    /* Both the signed App and the original child export this exact real
     * executable header at RVA 0. RTLD_MAIN_ONLY cannot resolve a dylib owner. */
    const struct mach_header_64 *header = dlsym(RTLD_MAIN_ONLY, "_mh_execute_header");
    Dl_info info = {0}; struct mach_header_64 copy;
    if (!header || !dladdr(header, &info) || info.dli_fbase != (const void *)header ||
        !ImageCanonicalPathV1(info.dli_fname, canonical) || !ImageHeaderV1(header, &copy)) return ENOEXEC;
    uint32_t count = _dyld_image_count(), selected = UINT32_MAX, matches = 0;
    if (!count || count > 4096) return ENOEXEC;
    for (uint32_t i = 0; i < count; ++i) {
        const struct mach_header_64 *candidate = (const void *)_dyld_get_image_header(i);
        struct mach_header_64 candidateCopy;
        if (!candidate || !ImageReadV1((uintptr_t)candidate, &candidateCopy, sizeof(candidateCopy))) return ENOEXEC;
        if (candidateCopy.magic != MH_MAGIC_64 || candidateCopy.filetype != MH_EXECUTE) continue;
        if (!ImageCanonicalPathV1(_dyld_get_image_name(i), canonical)) continue;
        if (++matches != 1 || candidate != header || !ImageHeaderV1(candidate, &candidateCopy)) return ENOEXEC;
        selected = i;
    }
    VM27ActualExecutableImageV1 result = {.header = header, .ncmds = copy.ncmds,
        .sizeofcmds = copy.sizeofcmds, .dyldIndex = selected};
    struct mach_header_64 after;
    if (matches != 1 || !ImageUUIDV1(header, &copy, result.uuid) ||
        count != _dyld_image_count() || _dyld_get_image_header(selected) != (const void *)header ||
        !ImageCanonicalPathV1(_dyld_get_image_name(selected), canonical) ||
        !ImageReadV1((uintptr_t)header, &after, sizeof(after)) || memcmp(&copy, &after, sizeof(copy))) return ENOEXEC;
    *out = result;
    return 0;
}
int VM27ActualExecutableImageFindSelfV1(VM27ActualExecutableImageV1 *out) {
    if (!out) return EINVAL;
    char actual[PATH_MAX] = {0}, canonical[PATH_MAX]; uint32_t capacity = sizeof(actual);
    if (_NSGetExecutablePath(actual, &capacity) || capacity > sizeof(actual) ||
        !memchr(actual, 0, sizeof(actual)) || !realpath(actual, canonical)) return ENOEXEC;
    return VM27ActualExecutableImageFindV1(canonical, out);
}
