#ifndef VM27_LARGE_ORIGINAL_PARENT_H
#define VM27_LARGE_ORIGINAL_PARENT_H
#include "modern_xpc_approved_code.h"
/* New scope only: fixed8MiB, own regular executable, no symlinks/hardlinks,
 * immutable whole-file pin plus every signed code page and embedded slot. */
int VM27LargeOriginalParentCheckFile(const char *absolutePath,
    const char *reviewedSHA256, const char *reviewedCDHash,
    VM27ApprovedCodeInfo *result);
#endif
