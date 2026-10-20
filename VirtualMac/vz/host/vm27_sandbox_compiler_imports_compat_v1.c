/* App-private imports for the genuine Mac27 sandbox compiler, version 1.
 *
 * The storage values and parameter widths come from the exact Mac27 native
 * libsystem_sandbox image and its genuine compiler call sites. Typed free
 * follows Apple's SDK27.1 _malloc.h backdeployment branch to real legacy free.
 *
 * Mac27 os_variant_is_basesystem and os_variant_is_recovery branch into one
 * native implementation. This explicit iOS adaptation asks the real native
 * iOS Recovery boot-role question. iOS uses its ReleaseType state whereas Mac
 * uses BaseSystem content; this does not claim their platform state is equal.
 *
 * The remaining APIs belong to Mac apply or bundle verification paths. They
 * stay unavailable here. Unexpected use returns a real error or terminates;
 * no successful sandbox application or protected-volume answer is fabricated.
 */
#include "vm27_sandbox_compiler_imports_compat_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <TargetConditionals.h>
#include <unistd.h>
#if TARGET_OS_OSX
#include <mach/mach_vm.h>
#else
/* Real libSystem MIG ABI; the iOS SDK omits the mach_vm.h header. */
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t,
    mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
#endif
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

_Static_assert(sizeof(void *) == 8 && sizeof(uint64_t) == 8 && sizeof(bool) == 1,
    "Audited Darwin LP64 ABI only");

const uint64_t VM27SandboxStorageGroupAnyV1 = UINT64_C(0);
const uint64_t VM27SandboxStorageWriteRestrictedV1 = UINT64_C(2);

/* This spelling prevents the compiler from rewriting the native free call. */
extern void VM27SandboxRealLegacyFreeV1(void *) __asm("_free");
extern void *VM27SandboxRealLegacyMallocV1(size_t) __asm("_malloc");

void VM27SandboxCompilerTypedFreeV1(void *pointer, uint64_t type_id) {
    (void)type_id;
    VM27SandboxRealLegacyFreeV1(pointer);
}

static bool ReadOwnMemory(uintptr_t address, void *output, size_t count) {
    mach_vm_size_t actual = 0;
    return address && count && address <= UINTPTR_MAX - count &&
        mach_vm_read_overwrite(mach_task_self(), address, count,
            (mach_vm_address_t)output, &actual) == KERN_SUCCESS && actual == count;
}

static bool IsNativeRecoveryImage(uintptr_t base) {
    static const unsigned char expectedUUID[16] = {
        0x2f, 0x7e, 0x2d, 0x4e, 0x1e, 0xd3, 0x31, 0x16,
        0x99, 0xe2, 0x81, 0x32, 0xb2, 0x08, 0xbb, 0xd3
    };
    struct mach_header_64 header;
    if (!ReadOwnMemory(base, &header, sizeof(header)) ||
        header.magic != MH_MAGIC_64 || header.ncmds == 0 ||
        header.ncmds > 1024 || header.sizeofcmds < sizeof(struct uuid_command) ||
        header.sizeofcmds > 65536 || base > UINTPTR_MAX - sizeof(header)) return false;
    unsigned char *commands = VM27SandboxRealLegacyMallocV1(header.sizeofcmds);
    if (!commands) return false;
    bool valid = ReadOwnMemory(base + sizeof(header), commands, header.sizeofcmds);
    size_t offset = 0;
    unsigned matches = 0;
    for (uint32_t i = 0; valid && i < header.ncmds; ++i) {
        struct load_command command;
        if (offset > header.sizeofcmds ||
            header.sizeofcmds - offset < sizeof(command)) { valid = false; break; }
        memcpy(&command, commands + offset, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize % 8 ||
            command.cmdsize > header.sizeofcmds - offset) { valid = false; break; }
        if (command.cmd == LC_UUID) {
            struct uuid_command uuid;
            if (command.cmdsize != sizeof(uuid)) { valid = false; break; }
            memcpy(&uuid, commands + offset, sizeof(uuid));
            ++matches;
            valid = memcmp(uuid.uuid, expectedUUID, sizeof(expectedUUID)) == 0;
        }
        offset += command.cmdsize;
    }
    valid = valid && offset == header.sizeofcmds && matches == 1;
    VM27SandboxRealLegacyFreeV1(commands);
    return valid;
}

__attribute__((noreturn)) static void RecoveryGuardFailure(void) {
    static const char message[] = "VM27_SANDBOX_COMPILER_NATIVE_RECOVERY_GUARD_FAILED\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    __builtin_trap();
}

bool VM27SandboxCompilerIsBaseSystemV1(const char *subsystem) {
    static const char nativePath[] = "/usr/lib/system/libsystem_darwin.dylib";
    typedef bool (*NativeRecoveryFunction)(const char *);
    int entryErrno = errno;
    void *handle = dlopen(nativePath, RTLD_NOW | RTLD_LOCAL);
    if (!handle) RecoveryGuardFailure();
    void *symbol = dlsym(handle, "os_variant_is_recovery");
    void *address = symbol;
#if __has_feature(ptrauth_calls)
    address = ptrauth_strip(symbol, ptrauth_key_function_pointer);
#endif
    Dl_info identity = {0};
    if (!symbol || !dladdr(address, &identity) || !identity.dli_fname ||
        strcmp(identity.dli_fname, nativePath) || !identity.dli_fbase ||
        (uintptr_t)identity.dli_fbase > UINTPTR_MAX - UINT64_C(0x27c4) ||
        (uintptr_t)address != (uintptr_t)identity.dli_fbase + UINT64_C(0x27c4) ||
        !IsNativeRecoveryImage((uintptr_t)identity.dli_fbase)) {
        (void)dlclose(handle);
        RecoveryGuardFailure();
    }
    /* Keep the authenticated dlsym pointer for the genuine call. */
    NativeRecoveryFunction query = (NativeRecoveryFunction)symbol;
    errno = entryErrno;
    bool answer = query(subsystem);
    int nativeErrno = errno;
    if (dlclose(handle)) RecoveryGuardFailure();
    errno = nativeErrno;
    return answer;
}

int VM27SandboxCompilerRootlessVolumeFDV1(int fd) {
    (void)fd;
    errno = ENOTSUP;
    return -1;
}

int VM27SandboxCompilerCheckStorageClassV1(int fd, uint64_t properties,
                                         uint64_t group) {
    (void)fd;
    (void)properties;
    (void)group;
    errno = ENOTSUP;
    return -1;
}

void VM27SandboxCompilerNotifyLibXPCV1(void) {
    static const char message[] = "VM27_SANDBOX_COMPILER_MAC_APPLY_NOTIFY_UNAVAILABLE\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    __builtin_trap();
}
