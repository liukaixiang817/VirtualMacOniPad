/* App-private adaptation of VZ's libc dispatch entry. No interposition or VM API. */
#include <string.h>

int VM27ScopedPlatformStrcmp(const char *left, const char *right)
    __asm__("__platform_strcmp");

int VM27ScopedPlatformStrcmp(const char *left, const char *right) {
    /* Preserve libc's int result; the public entry selects the host implementation. */
    return strcmp(left, right);
}
