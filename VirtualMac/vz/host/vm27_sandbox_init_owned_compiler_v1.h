#ifndef VM27_SANDBOX_INIT_OWNED_COMPILER_V1_H
#define VM27_SANDBOX_INIT_OWNED_COMPILER_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Exact original sandbox_init_with_parameters calling ABI. Owned flags3 is
 * limited to the original child/resource/NULL-parameters profile. Other flags
 * call the verified current native API; no failure-to-success fallback. */
__attribute__((visibility("default")))
int VM27SandboxInitWithOwnedCompilerV1(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);
#ifdef __cplusplus
}
#endif
#endif
