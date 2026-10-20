#include "scoped_softlinking.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

/* Reuse the old project's path-list iteration only. The macOS27 provider
 * observably uses FIRST, leaves successful error output alone, and retries all
 * failed candidates to aggregate their individual errors separated by '\n'.
 * No Installation lifetime interpose or constructor is inherited.
 */
void *_sl_dlopen(const char *const paths[], char **errorString) {
    size_t count = 0;
    for (; paths[count]; count++) {
        void *handle = dlopen(paths[count], RTLD_LAZY | RTLD_FIRST);
        if (handle) return handle;
    }
    if (!errorString) return NULL;
    char **messages = calloc(count, sizeof(*messages));
    if (!messages && count) abort();
    size_t total = count ? count : 1;
    void *handle = NULL;
    for (size_t i = 0; i < count; i++) {
        handle = dlopen(paths[i], RTLD_LAZY | RTLD_FIRST);
        if (handle) break;
        const char *error = dlerror();
        if (!error || !(messages[i] = strdup(error))) abort();
        size_t length = strlen(messages[i]);
        if (length > (size_t)-1 - total) abort();
        total += length;
    }
    if (!handle) {
        char *message = calloc(total, 1);
        if (!message) abort();
        for (size_t i = 0; i < count; i++) {
            strlcat(message, messages[i], total);
            if (i + 1 < count) strlcat(message, "\n", total);
        }
        *errorString = message;
    }
    for (size_t i = 0; i < count; i++) free(messages[i]);
    free(messages);
    return handle;
}
