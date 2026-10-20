#ifndef VM27_OWNED_APP_CHILD_PREMAIN_V5_H
#define VM27_OWNED_APP_CHILD_PREMAIN_V5_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Explicit owned launch preparation. A zero result describes verified owned
 * platform process preparation only; no sandbox profile is applied. */
__attribute__((visibility("default")))
int VM27OwnedPlatformLaunchPrepareV1(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);
#ifdef __cplusplus
}
#endif
#endif
