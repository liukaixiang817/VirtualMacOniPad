/* App-private port bridge, based on original project's epprobe/endpoint route.
 * Accept only exact pinned libxpc UUIDs, official own endpoint type, and actual
 * native send-right references before reading/writing its own shape+0x18.
 * No task_for_pid, system services, bootstrap alteration or image interposing.
 */
#include "modern_xpc_private_endpoint.h"
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdio.h>
#include <string.h>

int VM27PrivateEndpointCopyABI(VM27PrivateEndpointABI *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof(*result));
    const char *expected = TARGET_OS_IPHONE ? "7a0ca8d2728537ddae972efaa1de763e" : "0791121fb5fc3f84bf04115e86d2d882";
    void *function = ptrauth_strip((void *)xpc_endpoint_create, ptrauth_key_function_pointer);
    Dl_info info = {0};
    if (!dladdr(function, &info) || !info.dli_fbase || !info.dli_fname || strcmp(info.dli_fname, "/usr/lib/system/libxpc.dylib")) return ENOTSUP;
    const struct mach_header_64 *h = info.dli_fbase;
    if (h->magic != MH_MAGIC_64 || h->sizeofcmds > 16384 || h->ncmds > 256) return ENOTSUP;
    size_t at = sizeof(*h), end = at + h->sizeofcmds; unsigned uuids = 0;
    for (unsigned i = 0; i < h->ncmds; ++i) {
        if (at > end || end - at < 8) return ENOTSUP;
        const struct load_command *c = (const void *)((const char *)h + at);
        if (c->cmdsize < 8 || c->cmdsize > end - at) return ENOTSUP;
        if (c->cmd == LC_UUID) {
            if (c->cmdsize != 24) return ENOTSUP;
            const unsigned char *p = (const void *)((const char *)c + 8);
            for (unsigned j = 0; j < 16; ++j) snprintf(result->providerUUID + j * 2, 3, "%02x", p[j]);
            ++uuids;
        }
        at += c->cmdsize;
    }
    result->endpointCreateRVA = (uintptr_t)function - (uintptr_t)h;
    result->exactHostABI = at == end && uuids == 1 && !strcmp(result->providerUUID, expected) && result->endpointCreateRVA > 0;
    return result->exactHostABI ? 0 : ENOTSUP;
}
static int SendRight(mach_port_t port) {
    mach_port_type_t type = 0; mach_port_urefs_t refs = 0;
    if (!MACH_PORT_VALID(port) || mach_port_type(mach_task_self(), port, &type) ||
        !(type & MACH_PORT_TYPE_SEND) || type & MACH_PORT_TYPE_DEAD_NAME ||
        mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, &refs) || !refs) return EINVAL;
    return 0;
}
static int OwnEndpointPort(xpc_endpoint_t endpoint, mach_port_t *result) {
    VM27PrivateEndpointABI identity;
    int status = VM27PrivateEndpointCopyABI(&identity);
    if (status) return status;
    if (!endpoint || xpc_get_type(endpoint) != XPC_TYPE_ENDPOINT) return EINVAL;
    mach_port_t port; memcpy(&port, (const char *)endpoint + 0x18, sizeof(port));
    status = SendRight(port);
    if (!status) *result = port;
    return status;
}
int VM27PrivateEndpointCopySendRight(xpc_endpoint_t endpoint, mach_port_t *result) {
    if (!result) return EINVAL;
    *result = MACH_PORT_NULL;
    mach_port_t port;
    int status = OwnEndpointPort(endpoint, &port);
    if (status) return status;
    kern_return_t rc = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1);
    if (rc) return EIO;
    *result = port; return 0;
}
int VM27PrivateEndpointConnectSendRight(mach_port_t port, dispatch_queue_t queue, xpc_connection_t *result) {
    if (!result) return EINVAL;
    *result = NULL;
    VM27PrivateEndpointABI identity; int status = VM27PrivateEndpointCopyABI(&identity);
    if (status) return status;
    if (!queue || SendRight(port)) return EINVAL;
    xpc_connection_t dummy = xpc_connection_create(NULL, queue);
    if (!dummy) return ENOMEM;
    xpc_connection_set_event_handler(dummy, ^(xpc_object_t event) { (void)event; }); xpc_connection_resume(dummy);
    xpc_endpoint_t shape = xpc_endpoint_create(dummy);
    mach_port_t old = MACH_PORT_NULL;
    status = OwnEndpointPort(shape, &old);
    if (!status && mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1)) status = EIO;
    if (!status) {
        /* Only the fresh endpoint object created above is modified. */
        memcpy((char *)shape + 0x18, &port, sizeof(port));
        if (mach_port_deallocate(mach_task_self(), old)) {
            memcpy((char *)shape + 0x18, &old, sizeof(old));
            (void)mach_port_deallocate(mach_task_self(), port); status = EIO;
        }
    }
    if (!status) {
        *result = xpc_connection_create_from_endpoint(shape);
        if (!*result) status = ENOMEM;
        else xpc_connection_set_target_queue(*result, queue);
    }
    if (shape) xpc_release(shape);
    xpc_connection_cancel(dummy); xpc_release(dummy);
    return status;
}
