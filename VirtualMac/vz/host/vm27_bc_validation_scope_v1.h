#pragma once
#include <stdbool.h>
#include <stdint.h>

/* A synchronous validator may query a geometry-compatible format. Other
 * threads and unrelated textures must always observe the actual format. */
typedef struct VM27BCValidationScopeV1 {
    const void *texture;
    uint64_t format;
    struct VM27BCValidationScopeV1 *previous;
} VM27BCValidationScopeV1;
static _Thread_local VM27BCValidationScopeV1 *VM27BCValidationTopV1;
static inline void VM27BCValidationEnterV1(VM27BCValidationScopeV1 *scope,
        const void *texture, uint64_t format) {
    *scope = (VM27BCValidationScopeV1){texture, format, VM27BCValidationTopV1};
    VM27BCValidationTopV1 = scope;
}
static inline void VM27BCValidationLeaveV1(VM27BCValidationScopeV1 *scope) {
    VM27BCValidationTopV1 = scope->previous;
}
static inline bool VM27BCValidationLookupV1(const void *texture, uint64_t *format) {
    for (VM27BCValidationScopeV1 *scope = VM27BCValidationTopV1; scope; scope = scope->previous)
        if (scope->texture == texture) { *format = scope->format; return true; }
    return false;
}
