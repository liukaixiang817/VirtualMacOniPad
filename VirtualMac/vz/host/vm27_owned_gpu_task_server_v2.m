/* Independent GPU task transport only. This owns no GPU command, reply,
 * feature, completion stamp or fabricated task. Root's exact main-entry port
 * reaches this function only after dyld completed all actual image init funcs.
 * The genuine Apple ServiceDelegate and task objects handle all NSXPC work. */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include "vm27_owned_gpu_task_transport_v1.h"
#include "vm27_owned_gpu_parent_inspection_v1.h"
#include "vm27_owned_app_parent_identity_v1.h"
#include "modern_xpc_private_endpoint.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/log.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef, audit_token_t);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef, CFStringRef, CFErrorRef *);
extern Boolean SecTaskEntitlementsValidated(SecTaskRef);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

static dispatch_queue_t ControlQueueV1;
static dispatch_semaphore_t ReplyReadyV1;
static xpc_connection_t ControlV1;
static dispatch_source_t ParentExitV1;
static id ListenerV1, DelegateV1;
static VM27OwnedAppParentIdentityV1 ParentIdentityV1;
static uint64_t NonceV1;
static int ReplyStatusV1 = EINPROGRESS;
static bool RunningV1, InvalidV1;
static const struct mach_header_64 *MainHeaderV1;
static _Atomic(bool) NativeReadyV1;

static void FailV1(const char *boundary, int status) {
    fprintf(stderr, "[Independent27GPU] owned-server failure boundary=%s status=%d pid=%d ppid=%d sandboxProfileApplied=0\n",
        boundary, status, getpid(), getppid());
    _exit(70);
}
static bool StringV1(xpc_object_t d, const char *key, const char *expected) {
    xpc_object_t o = xpc_dictionary_get_value(d, key);
    return o && xpc_get_type(o) == XPC_TYPE_STRING && !strcmp(xpc_string_get_string_ptr(o), expected);
}
static bool UUIDV1(const uint8_t *p, const char *expected) {
    static const char digits[] = "0123456789abcdef";
    if (!expected || strnlen(expected, 33) != 32) return false;
    char text[33];
    for (unsigned i = 0; i < 16; ++i) { text[i * 2] = digits[p[i] >> 4]; text[i * 2 + 1] = digits[p[i] & 15]; }
    text[32] = 0; return !strcmp(text, expected);
}
/* Failure-only bounded observations. Header fields are read only after the
 * same preceding predicates which allowed their original reads. Command
 * payloads are read only after the original complete command-range checks. */
static void MainHeaderFailureV2(const struct mach_header_64 *h,
                                const VM27OwnedGPUTaskServerProfileV1 *p) {
    int saved = errno;
    uint32_t known = 0, magic = 0, type = 0, cpu = 0, count = 0, size = 0, word = 0;
    if (h) {
        known |= 1; magic = h->magic;
        if (magic == MH_MAGIC_64) {
            known |= 2; type = h->filetype;
            if (type == MH_EXECUTE) {
                known |= 4; cpu = (uint32_t)h->cputype;
                if (cpu == CPU_TYPE_ARM64) {
                    known |= 8; count = h->ncmds;
                    if (count && count <= 256) {
                        known |= 16; size = h->sizeofcmds;
                        if (size && size <= 16384 && p->nativeMainRVA &&
                            p->nativeMainRVA <= 1024U * 1024U &&
                            (p->admittedMainBranchWord & 0xfc000000U) == 0x14000000U) {
                            known |= 32;
                            word = *(const uint32_t *)((const uint8_t *)h + p->nativeMainRVA);
                        }
                    }
                }
            }
        }
    }
    fprintf(stderr, "[Independent27GPU] MainScope failure phase=header loadedHeader=%p knownMask=0x%x magic=0x%x filetype=%u cputype=0x%x ncmds=%u sizeofcmds=%u mainRVA=0x%lx loadedBranch=0x%x expectedBranch=0x%x rereadNonAtomic=1\n",
        (const void *)h, known, magic, type, cpu, count, size,
        (unsigned long)p->nativeMainRVA, word, p->admittedMainBranchWord);
    errno = saved;
}
static void MainCommandFailureV2(const char *phase, const struct mach_header_64 *h,
                                 const uint8_t *at, const uint8_t *end, uint32_t index,
                                 const struct load_command *command, unsigned payload,
                                 const VM27OwnedGPUTaskServerProfileV1 *p) {
    int saved = errno;
    char uuid[33] = {0}; uint64_t entry = 0; unsigned uuidKnown = 0, entryKnown = 0;
    if (command && command->cmdsize == 24 && (size_t)(end - at) >= 24) {
        if (payload == 1) {
            static const char digits[] = "0123456789abcdef";
            for (unsigned i = 0; i < 16; ++i) {
                uint8_t byte = at[8 + i];
                uuid[i * 2] = digits[byte >> 4]; uuid[i * 2 + 1] = digits[byte & 15];
            }
            uuidKnown = 1;
        } else if (payload == 2) {
            entry = ((const struct entry_point_command *)command)->entryoff; entryKnown = 1;
        }
    }
    fprintf(stderr, "[Independent27GPU] MainScope failure phase=%s loadedHeader=%p index=%u commandOffset=0x%lx remaining=%zu commandKnown=%u cmd=0x%x cmdsize=%u uuidKnown=%u loadedUUID=%s expectedUUID=%s entryKnown=%u loadedEntry=0x%llx expectedEntry=0x%lx rereadNonAtomic=1\n",
        phase, (const void *)h, index, (unsigned long)(at - (const uint8_t *)h),
        (size_t)(end - at), command != NULL, command ? command->cmd : 0,
        command ? command->cmdsize : 0, uuidKnown, uuid, p->nativeMainUUID,
        entryKnown, (unsigned long long)entry, (unsigned long)p->nativeMainRVA);
    errno = saved;
}
static int MainScopeV1(int argc, char *const argv[]) {
    const VM27OwnedGPUTaskServerProfileV1 *p = &VM27OwnedGPUTaskPinnedServerProfileV1;
    if (p->version != 1 || p->ownerUID != 501 || getuid() != p->ownerUID || geteuid() != p->ownerUID ||
        getppid() <= 1 || argc != 1 || !argv || !argv[0] || !p->canonicalExecutablePath ||
        strcmp(argv[0], p->canonicalExecutablePath) || !p->canonicalParentBundlePath ||
        !p->parentExecutableName) return EACCES;
    char actual[PATH_MAX]; uint32_t capacity = sizeof(actual);
    if (_NSGetExecutablePath(actual, &capacity) || strcmp(actual, p->canonicalExecutablePath)) return EACCES;
    const char *role = getenv(VM27_GPU_TASK_ROLE_ENV_V1);
    if (!role || strcmp(role, VM27_GPU_TASK_SERVER_ROLE_V1)) return EACCES;
    /* Environment selects this role; it supplies no identity, code hash,
     * endpoint or nonce authority. Dyld's actual main image admits the role. */
    MainHeaderV1 = (const struct mach_header_64 *)_dyld_get_image_header(0);
    const struct mach_header_64 *h = MainHeaderV1;
    if (!h || h->magic != MH_MAGIC_64 || h->filetype != MH_EXECUTE || h->cputype != CPU_TYPE_ARM64 ||
        !h->ncmds || h->ncmds > 256 || !h->sizeofcmds || h->sizeofcmds > 16384 ||
        !p->nativeMainRVA || p->nativeMainRVA > 1024U * 1024U ||
        (p->admittedMainBranchWord & 0xfc000000U) != 0x14000000U ||
        *(const uint32_t *)((const uint8_t *)h + p->nativeMainRVA) != p->admittedMainBranchWord) {
        MainHeaderFailureV2(h, p); return ENOTSUP;
    }
    const uint8_t *at = (const uint8_t *)(h + 1), *end = at + h->sizeofcmds;
    unsigned uuids = 0, entries = 0;
    for (uint32_t i = 0; i < h->ncmds; ++i) {
        if ((size_t)(end - at) < 8) {
            MainCommandFailureV2("command-header-range", h, at, end, i, NULL, 0, p); return ENOTSUP;
        }
        const struct load_command *c = (const void *)at;
        if (c->cmdsize < 8 || (c->cmdsize & 7) || c->cmdsize > (size_t)(end - at)) {
            MainCommandFailureV2("command-size", h, at, end, i, c, 0, p); return ENOTSUP;
        }
        if (c->cmd == LC_UUID) { if (c->cmdsize != 24 || !UUIDV1(at + 8, p->nativeMainUUID)) {
            MainCommandFailureV2("uuid", h, at, end, i, c, 1, p); return ENOTSUP;
        } ++uuids; }
        if (c->cmd == LC_MAIN) {
            if (c->cmdsize != sizeof(struct entry_point_command) ||
                ((const struct entry_point_command *)c)->entryoff != p->nativeMainRVA) {
                MainCommandFailureV2("entry", h, at, end, i, c, 2, p); return ENOTSUP;
            }
            ++entries;
        }
        at += c->cmdsize;
    }
    if (!(at == end && uuids == 1 && entries == 1)) {
        int saved = errno;
        fprintf(stderr, "[Independent27GPU] MainScope failure phase=footer loadedHeader=%p finalOffset=0x%lx expectedEndOffset=0x%lx uuids=%u entries=%u ncmds=%u rereadNonAtomic=1\n",
            (const void *)h, (unsigned long)(at - (const uint8_t *)h),
            (unsigned long)(end - (const uint8_t *)h), uuids, entries, h->ncmds);
        errno = saved;
    }
    return at == end && uuids == 1 && entries == 1 ? 0 : ENOTSUP;
}
int VM27OwnedGPUTaskAdmitNativeCallerV1(const void *entry, uintptr_t expectedRVA) {
    if (!atomic_load_explicit(&NativeReadyV1, memory_order_acquire) || !MainHeaderV1 || !entry) return EACCES;
#if __has_feature(ptrauth_calls)
    entry = __builtin_ptrauth_strip(entry, 0);
#endif
    uintptr_t address = (uintptr_t)entry, base = (uintptr_t)MainHeaderV1;
    if (address <= base) return EACCES;
    uintptr_t rva = address - base;
    if (expectedRVA) return rva == expectedRVA ? 0 : EACCES;
    const uint8_t *at = (const uint8_t *)(MainHeaderV1 + 1);
    for (uint32_t i = 0; i < MainHeaderV1->ncmds; ++i) {
        const struct load_command *c = (const void *)at;
        if (c->cmd == LC_SEGMENT_64 && c->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *s = (const void *)c;
            if (!strcmp(s->segname, "__TEXT") && (s->initprot & VM_PROT_EXECUTE) && rva < s->vmsize) return 0;
        }
        at += c->cmdsize;
    }
    return EACCES;
}
static bool NativeTrueV1(SecTaskRef task, CFStringRef name) {
    CFErrorRef error = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, name, &error);
    bool actual = !error && value && CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)value);
    if (error) CFRelease(error); if (value) CFRelease(value); return actual;
}
static int OwnPermissionsV1(void) {
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) || count != TASK_AUDIT_TOKEN_COUNT ||
        token.val[5] != (uint32_t)getpid() || !token.val[7]) return EACCES;
    uint32_t flags = 0;
    if (csops_audittoken(getpid(), 0, &flags, sizeof(flags), &token) || !(flags & 1)) return EACCES;
    SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, token);
    if (!task) return EACCES;
    bool noSandbox = NativeTrueV1(task, CFSTR("com.apple.private.security.no-sandbox"));
    bool validated = SecTaskEntitlementsValidated(task);
    CFRelease(task);
    fprintf(stderr, "[Independent27GPU] actual-self-policy pid=%d pidversion=%u codeStatus=0x%x noSandbox=%d nativeEntitlementsValidated=%d sandboxProfileApplied=0 nativeMacSandboxCalled=0\n",
        getpid(), token.val[7], flags, noSandbox, validated);
    return noSandbox ? 0 : EACCES;
}
static int CheckParentV1(xpc_object_t message, bool requireSame) {
    const VM27OwnedGPUTaskServerProfileV1 *p = &VM27OwnedGPUTaskPinnedServerProfileV1;
    VM27OwnedAppParentIdentityV1 before = {0}, after = {0};
    int status = VM27OwnedAppCheckActualParentMessageV1(message, &before);
    xpc_connection_t connection = !status ? xpc_dictionary_get_remote_connection(message) : NULL;
    if (!status && (!connection || xpc_connection_get_euid(connection) != p->ownerUID)) status = EACCES;
    if (!status && requireSame && (before.auditPID != ParentIdentityV1.auditPID ||
        before.auditPIDVersion != ParentIdentityV1.auditPIDVersion || strcmp(before.kernelCDHash, ParentIdentityV1.kernelCDHash))) status = EACCES;
    VM27BundleParentInspectionV1 inspected = {0};
    if (!status) status = VM27OwnedGPUInspectActualParentV1(p->canonicalParentBundlePath,
        p->parentExecutableName, p->ownerUID, before.kernelCDHash, &inspected);
    if (!status) status = VM27OwnedAppCheckActualParentMessageV1(message, &after);
    if (!status && (before.auditPID != after.auditPID || before.auditPIDVersion != after.auditPIDVersion ||
        strcmp(before.kernelCDHash, after.kernelCDHash) || after.auditPID != (uint32_t)getppid())) status = EACCES;
    if (!status) {
        if (!requireSame) ParentIdentityV1 = after;
        fprintf(stderr, "[Independent27GPU] actual-parent pid=%u pidversion=%u codeStatus=0x%x kernelCDHash=%s actualFileSHA256=%s pages=%u externalSlots13=1 nativeEntitlementsValidated=%d\n",
            after.auditPID, after.auditPIDVersion, after.codeStatus, after.kernelCDHash,
            inspected.executableSHA256, inspected.codePages, after.nativeEntitlementsValidated);
    }
    return status;
}
static int AckShapeV1(xpc_object_t reply, const char *method, bool initial) {
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY || xpc_dictionary_get_count(reply) != 3 ||
        !StringV1(reply, "privateMethod", method)) return EPROTO;
    xpc_object_t nonce = xpc_dictionary_get_value(reply, "nonce"), result = xpc_dictionary_get_value(reply, "status");
    if (!nonce || xpc_get_type(nonce) != XPC_TYPE_UINT64 || !xpc_uint64_get_value(nonce) ||
        !result || xpc_get_type(result) != XPC_TYPE_INT64 || (!initial && xpc_uint64_get_value(nonce) != NonceV1)) return EPROTO;
    int64_t status = xpc_int64_get_value(result);
    if (status < 0 || status > INT_MAX) return EPROTO;
    int identity = CheckParentV1(reply, !initial);
    if (identity) return identity;
    if (status) return (int)status;
    if (initial) NonceV1 = xpc_uint64_get_value(nonce);
    return 0;
}
static int SendAndWaitV1(xpc_object_t message, const char *ack, bool initial, unsigned seconds) {
    __block int status = EINPROGRESS;
    dispatch_sync(ControlQueueV1, ^{ ReplyStatusV1 = EINPROGRESS; status = InvalidV1 ? ECONNRESET : 0; });
    if (status) return status;
    xpc_connection_send_message_with_reply(ControlV1, message, ControlQueueV1, ^(xpc_object_t reply) {
        if (ReplyStatusV1 == EINPROGRESS) ReplyStatusV1 = AckShapeV1(reply, ack, initial);
        dispatch_semaphore_signal(ReplyReadyV1);
    });
    if (dispatch_semaphore_wait(ReplyReadyV1, dispatch_time(DISPATCH_TIME_NOW, (int64_t)seconds * NSEC_PER_SEC))) return ETIMEDOUT;
    dispatch_sync(ControlQueueV1, ^{ status = InvalidV1 ? ECONNRESET : ReplyStatusV1; });
    return status;
}
static int ConnectOwnerV1(void) {
    ControlQueueV1 = dispatch_queue_create("VM27.owned.gpu-task.control.v1", DISPATCH_QUEUE_SERIAL);
    ReplyReadyV1 = dispatch_semaphore_create(0);
    if (!ControlQueueV1 || !ReplyReadyV1) return ENOMEM;
    mach_port_array_t ports = NULL; mach_msg_type_number_t count = 0;
    kern_return_t lookup = mach_ports_lookup(mach_task_self(), &ports, &count);
    int status = lookup == KERN_SUCCESS && ports && count == 3 && MACH_PORT_VALID(ports[2]) ?
        VM27PrivateEndpointConnectSendRight(ports[2], ControlQueueV1, &ControlV1) : ENOTCONN;
    if (ports) {
        for (mach_msg_type_number_t i = 0; i < count; ++i)
            if (MACH_PORT_VALID(ports[i]) && mach_port_deallocate(mach_task_self(), ports[i]) && !status) status = EIO;
        if (vm_deallocate(mach_task_self(), (vm_address_t)ports, (vm_size_t)count * sizeof(mach_port_t)) && !status) status = EIO;
    }
    if (status) return status;
    xpc_connection_set_event_handler(ControlV1, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID || event == XPC_ERROR_CONNECTION_INTERRUPTED) {
            InvalidV1 = true; ReplyStatusV1 = ECONNRESET;
            dispatch_semaphore_signal(ReplyReadyV1);
            if (RunningV1) _exit(0);
        } else if (xpc_get_type(event) != XPC_TYPE_ERROR) {
            /* Only replies to the two exact requests are part of this role. */
            InvalidV1 = true; ReplyStatusV1 = EPROTO;
            dispatch_semaphore_signal(ReplyReadyV1);
            if (RunningV1) FailV1("unexpected-control-message", EPROTO);
        }
    });
    xpc_connection_activate(ControlV1);
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    if (!request) return ENOMEM;
    xpc_dictionary_set_string(request, "privateMethod", VM27_GPU_TASK_CONFIGURATION_V1);
    status = SendAndWaitV1(request, VM27_GPU_TASK_CONFIGURATION_ACK_V1, true, VM27_GPU_TASK_CONFIGURATION_SECONDS_V1);
    xpc_release(request);
    return status;
}
static int PrepareNativeGlobalsV1(void) {
    const VM27OwnedGPUTaskServerProfileV1 *p = &VM27OwnedGPUTaskPinnedServerProfileV1;
    if (!p->nativeHostLogRVA || p->nativeHostLogRVA > 16U * 1024U * 1024U) return ENOTSUP;
    /* Check the actual native pointer global's VM segment before touching it.
     * The original main's unused confstr/mkdir cache prelude is deferred,
     * not reported as a successful system API or synthetic directory. */
    const uint8_t *at = (const uint8_t *)(MainHeaderV1 + 1);
    uint64_t textVM = 0; bool textFound = false, writable = false;
    for (uint32_t i = 0; i < MainHeaderV1->ncmds; ++i) {
        const struct load_command *c = (const void *)at;
        if (c->cmd == LC_SEGMENT_64 && c->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *s = (const void *)c;
            if (!strcmp(s->segname, "__TEXT")) { textVM = s->vmaddr; textFound = true; }
        }
        at += c->cmdsize;
    }
    if (!textFound || textVM > UINT64_MAX - p->nativeHostLogRVA) return ENOTSUP;
    uint64_t vm = textVM + p->nativeHostLogRVA;
    at = (const uint8_t *)(MainHeaderV1 + 1);
    for (uint32_t i = 0; i < MainHeaderV1->ncmds; ++i) {
        const struct load_command *c = (const void *)at;
        if (c->cmd == LC_SEGMENT_64 && c->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *s = (const void *)c;
            if ((s->initprot & VM_PROT_WRITE) && vm >= s->vmaddr && s->vmsize >= sizeof(os_log_t) && vm - s->vmaddr <= s->vmsize - sizeof(os_log_t)) writable = true;
        }
        at += c->cmdsize;
    }
    if (!writable) return ENOTSUP;
    os_log_t *target = (os_log_t *)((uint8_t *)MainHeaderV1 + p->nativeHostLogRVA);
    if (*target) return EALREADY;
    os_log_t log = os_log_create(VM27_GPU_TASK_SERVICE_V1, "task");
    if (!log) return ENOMEM;
    *target = log;
    fprintf(stderr, "[Independent27GPU] actual-native-host-log initialized=1 originalUnusedCachePreludeDeferred=1 nativeConfstrCalled=0 nativeMacSandboxCalled=0 sandboxProfileApplied=0\n");
    return 0;
}
int VM27OwnedGPUTaskMainV1(int argc, char *const argv[]) {
    @autoreleasepool {
        int status = MainScopeV1(argc, argv);
        if (status) FailV1("exact-native-main-role", status);
        if ((status = OwnPermissionsV1())) FailV1("actual-own-ipad-policy", status);
        if ((status = ConnectOwnerV1())) FailV1("inherited-owner-configuration", status);
        if ((status = PrepareNativeGlobalsV1())) FailV1("actual-native-host-log", status);
        atomic_store_explicit(&NativeReadyV1, true, memory_order_release);
        Class cls = objc_getClass("ServiceDelegate");
        const VM27OwnedGPUTaskServerProfileV1 *p = &VM27OwnedGPUTaskPinnedServerProfileV1;
        if (!cls || (uintptr_t)cls != (uintptr_t)MainHeaderV1 + p->nativeDelegateClassRVA) FailV1("native-ServiceDelegate", ENOTSUP);
        DelegateV1 = ((id (*)(id, SEL))objc_msgSend)(cls, sel_registerName("new"));
        ListenerV1 = [((id (*)(id, SEL))objc_msgSend)(objc_getClass("NSXPCListener"), sel_registerName("anonymousListener")) retain];
        if (!DelegateV1 || !ListenerV1) FailV1("native-listener-allocation", ENOMEM);
        ((void (*)(id, SEL, id))objc_msgSend)(ListenerV1, sel_registerName("setDelegate:"), DelegateV1);
        ((void (*)(id, SEL))objc_msgSend)(ListenerV1, sel_registerName("resume"));
        id endpoint = ((id (*)(id, SEL))objc_msgSend)(ListenerV1, sel_registerName("endpoint"));
        if (!endpoint || ![endpoint respondsToSelector:sel_registerName("_endpoint")]) FailV1("native-NSXPC-endpoint", ENOTSUP);
        xpc_object_t native = ((xpc_object_t (*)(id, SEL))objc_msgSend)(endpoint, sel_registerName("_endpoint"));
        if (!native || xpc_get_type(native) != XPC_TYPE_ENDPOINT) FailV1("actual-XPC-endpoint", EPROTO);
        xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
        if (!hello) FailV1("endpoint-hello", ENOMEM);
        xpc_dictionary_set_string(hello, "privateMethod", VM27_GPU_TASK_ENDPOINT_V1);
        xpc_dictionary_set_string(hello, "serviceIdentifier", VM27_GPU_TASK_SERVICE_V1);
        xpc_dictionary_set_uint64(hello, "nonce", NonceV1);
        xpc_dictionary_set_value(hello, "serviceEndpoint", native);
        status = SendAndWaitV1(hello, VM27_GPU_TASK_ENDPOINT_ACK_V1, false, VM27_GPU_TASK_ENDPOINT_SECONDS_V1);
        xpc_release(hello);
        if (status) FailV1("actual-endpoint-ack", status);
        ParentExitV1 = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, ParentIdentityV1.auditPID,
            DISPATCH_PROC_EXIT, ControlQueueV1);
        if (!ParentExitV1) FailV1("actual-parent-lifetime-observer", ENOMEM);
        dispatch_source_set_event_handler(ParentExitV1, ^{ _exit(0); });
        dispatch_resume(ParentExitV1);
        __block bool invalid = false;
        dispatch_sync(ControlQueueV1, ^{ invalid = InvalidV1; if (!invalid) RunningV1 = true; });
        if (invalid || getppid() != (pid_t)ParentIdentityV1.auditPID) FailV1("owner-lifetime-handoff", ECONNRESET);
        fprintf(stderr, "[Independent27GPU] actual-native-service-ready pid=%d ownerPID=%u ownerVersion=%u sandboxProfileApplied=0 originalTaskHandshakeEmulated=0 taskCommandsEmulated=0\n",
            getpid(), ParentIdentityV1.auditPID, ParentIdentityV1.auditPIDVersion);
        dispatch_main();
    }
    return 70;
}
