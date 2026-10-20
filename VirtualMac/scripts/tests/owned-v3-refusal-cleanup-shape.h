/* Ordinary diagnostic teardown protocol only; conveys no authorization. */
#ifndef VM27_OWNED_REFUSAL_CLEANUP_SHAPE_H
#define VM27_OWNED_REFUSAL_CLEANUP_SHAPE_H
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <xpc/xpc.h>

#define VM27_OWNED_REFUSAL_METHOD "VM27.owned-v3.refusal.v1"
#define VM27_OWNED_REFUSAL_COMMIT_METHOD "VM27.owned-v3.refusal-cleanup-commit.v1"
static bool VM27OwnedRefusalMessageShape(xpc_object_t request, uint64_t nonce,
                                        const char *expectedMethod) {
    if (!request || xpc_get_type(request) != XPC_TYPE_DICTIONARY ||
        !nonce || xpc_dictionary_get_count(request) != 3) return false;
    const char *method = xpc_dictionary_get_string(request, "privateMethod");
    return method && !strcmp(method, expectedMethod) &&
        xpc_get_type(xpc_dictionary_get_value(request, "nonce")) == XPC_TYPE_UINT64 &&
        xpc_dictionary_get_uint64(request, "nonce") == nonce &&
        xpc_get_type(xpc_dictionary_get_value(request, "refusalStatus")) == XPC_TYPE_INT64 &&
        xpc_dictionary_get_int64(request, "refusalStatus") == EACCES;
}
static bool VM27OwnedRefusalRequestShape(xpc_object_t request, uint64_t nonce) {
    return VM27OwnedRefusalMessageShape(request, nonce, VM27_OWNED_REFUSAL_METHOD);
}
static bool VM27OwnedRefusalCommitShape(xpc_object_t request, uint64_t nonce) {
    return VM27OwnedRefusalMessageShape(request, nonce, VM27_OWNED_REFUSAL_COMMIT_METHOD);
}
static bool VM27OwnedRefusalAckShape(xpc_object_t reply, uint64_t nonce) {
    return reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY && nonce &&
        xpc_dictionary_get_count(reply) == 3 &&
        xpc_get_type(xpc_dictionary_get_value(reply, "refusalStatus")) == XPC_TYPE_INT64 &&
        xpc_dictionary_get_int64(reply, "refusalStatus") == EACCES &&
        xpc_get_type(xpc_dictionary_get_value(reply, "nonce")) == XPC_TYPE_UINT64 &&
        xpc_dictionary_get_uint64(reply, "nonce") == nonce &&
        xpc_get_type(xpc_dictionary_get_value(reply, "cleanupOnly")) == XPC_TYPE_BOOL &&
        xpc_dictionary_get_bool(reply, "cleanupOnly");
}
#endif
