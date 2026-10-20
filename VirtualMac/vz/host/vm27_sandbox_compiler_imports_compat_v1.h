#ifndef VM27_SANDBOX_COMPILER_IMPORTS_COMPAT_V1_H
#define VM27_SANDBOX_COMPILER_IMPORTS_COMPAT_V1_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM27_SANDBOX_COMPILER_EXPORT __attribute__((visibility("default")))

/* These are exact Darwin LP64 data symbols, not pointer-valued constants. */
VM27_SANDBOX_COMPILER_EXPORT extern const uint64_t VM27SandboxStorageGroupAnyV1
    __asm("_SANDBOX_STORAGE_CLASS_GROUP_ANY");
VM27_SANDBOX_COMPILER_EXPORT extern const uint64_t VM27SandboxStorageWriteRestrictedV1
    __asm("_SANDBOX_STORAGE_CLASS_PROPERTY_WRITE_RESTRICTED");

VM27_SANDBOX_COMPILER_EXPORT void VM27SandboxCompilerTypedFreeV1(void *pointer, uint64_t type_id)
    __asm("_malloc_type_free");
VM27_SANDBOX_COMPILER_EXPORT bool VM27SandboxCompilerIsBaseSystemV1(const char *subsystem)
    __asm("_os_variant_is_basesystem");
VM27_SANDBOX_COMPILER_EXPORT int VM27SandboxCompilerRootlessVolumeFDV1(int fd)
    __asm("_rootless_protected_volume_fd");
VM27_SANDBOX_COMPILER_EXPORT int VM27SandboxCompilerCheckStorageClassV1(int fd, uint64_t properties,
                                         uint64_t group)
    __asm("_sandbox_check_storage_class");
VM27_SANDBOX_COMPILER_EXPORT void VM27SandboxCompilerNotifyLibXPCV1(void)
    __asm("__sandbox_enter_notify_libxpc");

#undef VM27_SANDBOX_COMPILER_EXPORT
#ifdef __cplusplus
}
#endif
#endif
