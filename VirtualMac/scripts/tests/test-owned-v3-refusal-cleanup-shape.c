/* Uses real host XPC values only. No endpoint, native policy or device calls. */
#include "owned-v3-refusal-cleanup-shape.h"
#include <assert.h>
#include <stdio.h>

static xpc_object_t Request(void) {
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(value, "privateMethod", VM27_OWNED_REFUSAL_METHOD);
    xpc_dictionary_set_uint64(value, "nonce", 27);
    xpc_dictionary_set_int64(value, "refusalStatus", EACCES);
    return value;
}
static xpc_object_t Ack(void) {
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(value, "refusalStatus", EACCES);
    xpc_dictionary_set_uint64(value, "nonce", 27);
    xpc_dictionary_set_bool(value, "cleanupOnly", true);
    return value;
}
static xpc_object_t Commit(void) {
    xpc_object_t value = Request();
    xpc_dictionary_set_string(value, "privateMethod", VM27_OWNED_REFUSAL_COMMIT_METHOD);
    return value;
}
int main(void) {
    xpc_object_t request = Request(), reply = Ack(), commit = Commit();
    assert(VM27OwnedRefusalRequestShape(request, 27));
    assert(VM27OwnedRefusalAckShape(reply, 27));
    assert(!VM27OwnedRefusalRequestShape(request, 0));
    assert(!VM27OwnedRefusalRequestShape(request, 28));
    assert(!VM27OwnedRefusalAckShape(reply, 0));
    assert(!VM27OwnedRefusalAckShape(reply, 28));
    assert(!VM27OwnedRefusalRequestShape(reply, 27));
    assert(!VM27OwnedRefusalAckShape(request, 27));
    assert(VM27OwnedRefusalCommitShape(commit, 27));
    assert(!VM27OwnedRefusalCommitShape(commit, 28));
    assert(!VM27OwnedRefusalCommitShape(request, 27));
    assert(!VM27OwnedRefusalRequestShape(commit, 27));
    xpc_release(request); xpc_release(reply); xpc_release(commit);
    for (unsigned fault = 0; fault < 7; ++fault) {
        request = Request(); reply = Ack(); commit = Commit();
        switch (fault) {
            case 0:
                xpc_dictionary_set_int64(request, "refusalStatus", 0);
                xpc_dictionary_set_int64(commit, "refusalStatus", 0);
                xpc_dictionary_set_int64(reply, "refusalStatus", 0); break;
            case 1:
                xpc_dictionary_set_uint64(request, "refusalStatus", EACCES);
                xpc_dictionary_set_uint64(commit, "refusalStatus", EACCES);
                xpc_dictionary_set_uint64(reply, "refusalStatus", EACCES); break;
            case 2:
                xpc_dictionary_set_string(request, "nonce", "27");
                xpc_dictionary_set_string(commit, "nonce", "27");
                xpc_dictionary_set_string(reply, "nonce", "27"); break;
            case 3:
                xpc_dictionary_set_string(request, "privateMethod", "VM27.owned-v3.stop.v1");
                xpc_dictionary_set_string(commit, "privateMethod", VM27_OWNED_REFUSAL_METHOD);
                xpc_dictionary_set_bool(reply, "cleanupOnly", false); break;
            case 4:
                xpc_dictionary_set_uint64(request, "extra", 1);
                xpc_dictionary_set_uint64(commit, "extra", 1);
                xpc_dictionary_set_uint64(reply, "extra", 1); break;
            case 5:
                xpc_dictionary_set_value(request, "nonce", NULL);
                xpc_dictionary_set_value(commit, "nonce", NULL);
                xpc_dictionary_set_value(reply, "cleanupOnly", NULL); break;
            case 6:
                xpc_dictionary_set_bool(request, "refusalStatus", true);
                xpc_dictionary_set_bool(commit, "refusalStatus", true);
                xpc_dictionary_set_string(reply, "cleanupOnly", "true"); break;
        }
        assert(!VM27OwnedRefusalRequestShape(request, 27));
        assert(!VM27OwnedRefusalAckShape(reply, 27));
        assert(!VM27OwnedRefusalCommitShape(commit, 27));
        xpc_release(request); xpc_release(reply); xpc_release(commit);
    }
    puts("PASS: 33 refusal/ACK/cleanup-commit shape checks; host XPC only, no IPC or authorization");
    return 0;
}
