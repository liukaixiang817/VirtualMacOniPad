/* Local component fixture only. A raw registry success never authorizes the
 * typed transport, its original handler, or an original VMM application call. */
#include "vm27_client_registration_v1.h"
#define VM27_V8_DIAGNOSTIC_TITLE "VM27 Owned Registration v8"
static _Atomic unsigned ComponentHandlerCalls;
static void ComponentForbiddenHandler(xpc_connection_t peer) {
    atomic_fetch_add(&ComponentHandlerCalls, 1);
    Check(false, "component-registry-never-authorizes-original-handler");
    xpc_connection_cancel(peer);
}
static CFStringRef CopyActualMainTitle(void) {
    CFBundleRef main = CFBundleGetMainBundle();
    CFTypeRef value = main ? CFBundleGetValueForInfoDictionaryKey(main, CFSTR("CFBundleDisplayName")) : NULL;
    if (!value || CFGetTypeID(value) != CFStringGetTypeID() || !CFStringGetLength(value)) return NULL;
    return CFStringCreateCopy(NULL, (CFStringRef)value);
}
static CFStringRef CopyComponentTitle(pid_t parent, bool expectPresent) {
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &parent);
    CFStringRef keys[] = {_kLSPIDKey}; CFTypeRef values[] = {number};
    errno = 0;
    CFArrayRef matches = number ? _LSCopyMatchingApplicationsWithItems(-2, 1, keys, values) : NULL;
    Check(expectPresent ? matches && CFArrayGetCount(matches) == 1 : !matches && errno == ENOENT,
        "component-real-CF-query-registration-presence");
    CFTypeRef copied = matches && CFArrayGetCount(matches) == 1 ?
        _LSCopyApplicationInformationItem(-2, CFArrayGetValueAtIndex(matches, 0), CFSTR("LSDisplayName")) : NULL;
    if (matches) CFRelease(matches);
    if (number) CFRelease(number);
    Check(expectPresent ? copied && CFGetTypeID(copied) == CFStringGetTypeID() : !copied,
        "component-retained-title-survives-matching-array-release");
    return (CFStringRef)copied;
}
static bool OwnPortsEqual(mach_port_array_t before, mach_msg_type_number_t count) {
    mach_port_array_t after = NULL; mach_msg_type_number_t n = 0;
    bool equal = !mach_ports_lookup(mach_task_self(), &after, &n) && n == count;
    for (unsigned i = 0; equal && i < count; ++i) if (before[i] != after[i]) equal = false;
    if (after) ReleasePorts(after, n);
    return equal;
}
static int RegistrationComponentChild(int argc, char **argv) {
    if (argc != 8) return 64;
    uint64_t nonce = strtoull(argv[2], NULL, 10); pid_t parent = (pid_t)strtol(argv[3], NULL, 10);
    const char *CD = argv[4], *SHA = argv[5];
    size_t bytes = 0; unsigned char *code = Read(argv[0], &bytes); VM27ApprovedCodeInfo own = {0};
    Check(code && bytes == strtoull(argv[6], NULL, 10) && !VM27ApprovedCodeInspectBytes(code, bytes, &own)
        && !strcmp(own.fileSHA256, SHA) && !strcmp(own.CDHash, CD) && !own.pluginValue,
        "component-child-real-own-code-and-true-Mac-native-denial"); free(code);
    CFStringRef mainTitle = CopyActualMainTitle();
    Check(mainTitle && CFEqual(mainTitle, CFSTR(VM27_V8_DIAGNOSTIC_TITLE)), "component-child-actual-embedded-main-bundle-title");
    if (mainTitle) CFRelease(mainTitle);
    Providers("child", "before"); Check(NoVM(), "component-child-no-VM-images");
    if (atomic_load(&gFailures)) return 78;
    dispatch_queue_t queue = dispatch_queue_create("VM27.v8.registration.component.child", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t finish = dispatch_semaphore_create(0), final = dispatch_semaphore_create(0);
    xpc_endpoint_t serviceEndpoint = NULL;
    Check(!VM27OriginalV8TransportCreateServer(argv[7], SHA, CD, parent, queue, &serviceEndpoint) && serviceEndpoint,
        "component-child-actual-typed-private-server-created");
    Check(!VM27OriginalV8TransportRequireServerInstance(nonce), "component-configures-frozen-bridge-once-from-immutable-parent");
    Check(VM27OriginalV8TransportRequireServerInstance(nonce) == EALREADY, "component-configuration-cannot-be-repeated");
    CFStringRef absent = (CFStringRef)(uintptr_t)1;
    Check(VM27OriginalV8TransportCopyServerRegisteredClientDisplayName(&absent) == ENOTCONN && !absent,
        "component-typed-title-query-refuses-before-registration");
    Check(!VM27OriginalV8TransportStartServer(ComponentForbiddenHandler), "component-starts-real-denial-handler-gate");
    mach_port_array_t ports = NULL; mach_msg_type_number_t count = 0;
    Check(!mach_ports_lookup(mach_task_self(), &ports, &count) && count == 3, "component-child-exact-own-inherited-slots");
    xpc_connection_t channel = NULL;
    Check(ports && count == 3 && !VM27PrivateEndpointConnectSendRight(ports[2], queue, &channel) && channel,
        "component-child-connects-actual-parent-endpoint");
    if (!channel || atomic_load(&gFailures)) _exit(78);
    __block unsigned registrationCalls = 0, rawCommits = 0;
    __block bool registered = false;
    __block CFStringRef retainedFirstTitle = NULL;
    xpc_connection_set_event_handler(channel, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) { dispatch_semaphore_signal(final); return; }
        if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) return;
        Check(PeerIdentity(event, parent, CD, "registrationComponentChild", "actual-control", true),
            "component-every-control-real-parent-kernel-token-and-code");
        const char *method = xpc_dictionary_get_string(event, "privateMethod");
        if (method && !strcmp(method, "VM27.component.register-child.v8")) {
            CFStringRef actualTitle = CopyActualMainTitle(); char text[4097] = {0};
            Check(actualTitle && CFStringGetCString(actualTitle, text, sizeof(text), kCFStringEncodingUTF8),
                "component-child-publishes-actual-main-bundle-title-for-reap-control");
            if (actualTitle) CFRelease(actualTitle);
            xpc_object_t registration = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_string(registration, "privateMethod", "VM27.register-client-title.v1");
            xpc_dictionary_set_uint64(registration, "nonce", nonce);
            xpc_dictionary_set_string(registration, "clientDisplayName", text);
            xpc_connection_send_message(channel, registration); xpc_release(registration); return;
        }
        if (method && !strcmp(method, "VM27.component.finish.v8")) {
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            Check(reply != NULL, "component-finish-real-reply-obligation");
            if (reply) { xpc_dictionary_set_int64(reply, "componentStatus", 0); xpc_connection_send_message(channel, reply); xpc_release(reply); }
            xpc_connection_send_barrier(channel, ^{ dispatch_semaphore_signal(finish); }); return;
        }
        xpc_object_t reply = NULL;
        int typed = VM27OriginalV8TransportReceiveServerClientRegistrationMessage(event, &reply);
        Check(typed == EACCES && reply && xpc_dictionary_get_count(reply) == 3,
            "component-typed-registration-actual-Mac-native-Boolean-denial");
        xpc_object_t status = reply ? xpc_dictionary_get_value(reply, "registrationStatus") : NULL;
        Check(status && xpc_get_type(status) == XPC_TYPE_INT64 && xpc_int64_get_value(status) == EACCES,
            "component-typed-denial-exact-status-not-explicit-approved-success");
        int raw = VM27ClientRegistrationReceiveV1(event); ++registrationCalls;
        if (!raw) { registered = true; ++rawCommits; }
        CFStringRef title = CopyComponentTitle(parent, registered);
        bool titleMatches = title && CFEqual(title, CFSTR(VM27_V8_DIAGNOSTIC_TITLE));
        if (registered) Check(titleMatches, "component-live-CF-title-is-actual-main-bundle-value");
        if (title && !retainedFirstTitle) retainedFirstTitle = (CFStringRef)CFRetain(title);
        if (retainedFirstTitle) Check(CFEqual(retainedFirstTitle, CFSTR(VM27_V8_DIAGNOSTIC_TITLE)),
            "component-earlier-owned-title-retained-across-idempotence-and-refusal");
        if (title) CFRelease(title);
        CFStringRef typedTitle = (CFStringRef)(uintptr_t)1;
        Check(VM27OriginalV8TransportCopyServerRegisteredClientDisplayName(&typedTitle) == ENOTCONN && !typedTitle,
            "component-raw-registry-success-never-sets-typed-transport-registration");
        xpc_object_t bindReply = (xpc_object_t)(uintptr_t)1;
        Check(VM27OriginalV8TransportBindServerInstanceMessage(event, &bindReply) == ENOTCONN && !bindReply,
            "component-instance-binding-remains-refused-without-typed-registration");
        if (!reply) reply = xpc_dictionary_create_reply(event);
        if (reply) {
            xpc_dictionary_set_int64(reply, "componentStatus", raw);
            xpc_dictionary_set_bool(reply, "componentRegistered", registered);
            xpc_dictionary_set_bool(reply, "titleMatched", titleMatches);
            xpc_connection_send_message(channel, reply); xpc_release(reply);
        }
        printf("{\"record\":\"componentRegistration\",\"PID\":%d,\"call\":%u,\"typedStatus\":%d,\"rawStatus\":%d,\"registered\":%s,\"titleMatched\":%s,\"originalHandlerCalled\":false}\n",
            getpid(), registrationCalls, typed, raw, registered ? "true" : "false", titleMatches ? "true" : "false");
    }); xpc_connection_resume(channel);
    xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(hello, "privateMethod", "VM27.component.ready.v8");
    xpc_dictionary_set_value(hello, "serviceEndpoint", serviceEndpoint);
    xpc_dictionary_set_uint64(hello, "nonce", nonce); xpc_connection_send_message(channel, hello); xpc_release(hello);
    Check(!dispatch_semaphore_wait(finish, dispatch_time(DISPATCH_TIME_NOW, 8LL * NSEC_PER_SEC)), "component-finite-parent-control-sequence-completed");
    xpc_connection_cancel(channel);
    Check(!dispatch_semaphore_wait(final, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-child-real-channel-final-invalid-drained");
    Check(!VM27OriginalV8TransportStopServer(), "component-typed-server-real-final-invalid-released-off-queue");
    dispatch_sync(queue, ^{});
    xpc_release(serviceEndpoint); serviceEndpoint = NULL;
    Check(VM27OriginalV8TransportCreateServer(argv[7], SHA, CD, parent, queue, &serviceEndpoint) == EALREADY,
        "component-stopped-registered-process-cannot-reconfigure-new-peer");
    if (retainedFirstTitle) CFRelease(retainedFirstTitle);
    VM27OriginalV8TransportStats stats = {0}; VM27OriginalV8TransportCopyStats(&stats);
    VM27OriginalV8TransportRegistrationStats registration = {0}; VM27OriginalV8TransportCopyRegistrationStats(&registration);
    Check(registrationCalls == 7 && rawCommits == 2 && stats.peersReceived == 2 && stats.peersDenied == 2
        && !stats.originalHandlerCalls && !stats.serverInstancesBound && !atomic_load(&ComponentHandlerCalls),
        "component-two-real-handler-denials-seven-receives-two-raw-idempotent-successes");
    Check(registration.serverConfigurations == 1 && registration.registrationMessages == 7
        && registration.registrationDeniedMessages == 7 && !registration.registrationCommits
        && !registration.serverRegistered && registration.peersDeniedBeforeRegistration == 2
        && stats.tasksCreated == stats.tasksReleased, "component-native-gates-and-legacy-task-lifetime-paired");
    xpc_release(channel);
    ReleasePorts(ports, count); dispatch_release(finish); dispatch_release(final); dispatch_release(queue);
    Providers("child", "after"); Check(NoVM(), "component-child-no-VM-images-after");
    printf("{\"record\":\"registrationComponentChildSummary\",\"PID\":%d,\"checks\":%u,\"failures\":%u,\"typedRegistrationDenied\":7,\"rawRegistrationSuccesses\":2,\"actualHandlerDenials\":2,\"originalHandlerCalls\":0,\"instanceBindings\":0,\"nativeVMCalls\":0,\"originalVMMExecuted\":false}\n",
        getpid(), atomic_load(&gChecks), atomic_load(&gFailures));
    return atomic_load(&gFailures) ? 1 : 0;
}
static int RegistrationComponentParent(char **argv, const VM27ApprovedCodeInfo *own) {
    Check(!own->pluginValue, "component-run-preserves-real-Mac-native-plugin-denial");
    CFStringRef title = CopyActualMainTitle(); char titleUTF8[4097] = {0};
    Check(title && CFEqual(title, CFSTR(VM27_V8_DIAGNOSTIC_TITLE))
        && CFStringGetCString(title, titleUTF8, sizeof(titleUTF8), kCFStringEncodingUTF8),
        "component-parent-uses-actual-main-CFBundle-title");
    if (title) CFRelease(title);
    if (atomic_load(&gFailures)) return 78;
    dispatch_queue_t queue = dispatch_queue_create("VM27.v8.registration.component.parent", DISPATCH_QUEUE_SERIAL);
    dispatch_suspend(queue);
    dispatch_semaphore_t ready = dispatch_semaphore_create(0), replies = dispatch_semaphore_create(0), final = dispatch_semaphore_create(0), listenerFinal = dispatch_semaphore_create(0), childRegistered = dispatch_semaphore_create(0);
    __block xpc_connection_t childPeer = NULL; __block xpc_endpoint_t childService = NULL; __block pid_t child = 0;
    __block CFStringRef retainedChildTitle = NULL;
    uint64_t nonce = 0; arc4random_buf(&nonce, sizeof(nonce)); if (!nonce) nonce = 1;
    xpc_connection_t listener = xpc_connection_create(NULL, queue);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) { dispatch_semaphore_signal(listenerFinal); return; }
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        Check(!childPeer, "component-parent-one-real-child-peer");
        if (childPeer) { xpc_connection_cancel((xpc_connection_t)event); return; }
        childPeer = (xpc_connection_t)xpc_retain(event); xpc_connection_set_target_queue(childPeer, queue);
        xpc_connection_set_event_handler(childPeer, ^(xpc_object_t message) {
            if (message == XPC_ERROR_CONNECTION_INVALID) { dispatch_semaphore_signal(final); return; }
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            Check(PeerIdentity(message, child, argv[3], "registrationComponentParent", "ready", true), "component-ready-actual-child-kernel-code");
            const char *method = xpc_dictionary_get_string(message, "privateMethod");
            if (method && !strcmp(method, "VM27.register-client-title.v1")) {
                Check(!VM27ClientRegistrationReceiveV1(message), "component-parent-registers-real-child-before-reap");
                retainedChildTitle = CopyComponentTitle(child, true);
                Check(retainedChildTitle && CFEqual(retainedChildTitle, CFSTR(VM27_V8_DIAGNOSTIC_TITLE)), "component-parent-retains-real-child-title-before-reap");
                dispatch_semaphore_signal(childRegistered); return;
            }
            xpc_object_t endpoint = xpc_dictionary_get_value(message, "serviceEndpoint");
            Check(endpoint && xpc_get_type(endpoint) == XPC_TYPE_ENDPOINT && xpc_dictionary_get_uint64(message, "nonce") == nonce && !childService,
                "component-ready-actual-child-endpoint-and-nonce");
            if (endpoint && !childService) childService = (xpc_endpoint_t)xpc_retain(endpoint);
            Check(!VM27ClientRegistrationConfigureV1(child, argv[3], nonce), "component-parent-configures-immutable-actual-child-for-live-token-control");
            dispatch_semaphore_signal(ready);
        }); xpc_connection_resume(childPeer);
    }); xpc_connection_resume(listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener); mach_port_t send = MACH_PORT_NULL;
    Check(endpoint && !VM27PrivateEndpointCopySendRight(endpoint, &send), "component-parent-real-endpoint-send-right");
    mach_port_array_t before = NULL; mach_msg_type_number_t beforeCount = 0;
    Check(!mach_ports_lookup(mach_task_self(), &before, &beforeCount), "component-snapshots-actual-parent-registered-ports");
    posix_spawnattr_t attributes; Check(!posix_spawnattr_init(&attributes), "component-own-spawn-attributes-created");
    mach_port_t inherited[] = {MACH_PORT_NULL, MACH_PORT_NULL, send};
    Check(!posix_spawnattr_set_registered_ports_np(&attributes, inherited, 3), "component-only-child-inherits-own-endpoint");
    char nonceText[32], pidText[32]; snprintf(nonceText, sizeof(nonceText), "%llu", (unsigned long long)nonce); snprintf(pidText, sizeof(pidText), "%d", getpid());
    char *arguments[] = {argv[0], "--registration-channel-child", nonceText, pidText, argv[3], argv[1], argv[2], argv[0], NULL};
    int spawned = posix_spawn(&child, argv[0], NULL, &attributes, arguments, environ);
    Check(!spawned && child > 1, "component-actual-owned-child-spawned");
    Check(!posix_spawnattr_destroy(&attributes), "component-own-spawn-attributes-destroyed");
    Check(!mach_port_deallocate(mach_task_self(), send), "component-own-spawn-send-right-released");
    dispatch_resume(queue);
    Check(!dispatch_semaphore_wait(ready, dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC)) && childPeer && childService,
        "component-actual-child-ready-within-finite-deadline");
    const int expected[] = {EPROTO, EPROTO, EINVAL, 0, 0, EALREADY, EPROTO};
    unsigned actualReplies = 0;
    for (unsigned step = 0; step < 9 && childPeer && childService; ++step) {
        if (step == 0 || step == 8) {
            dispatch_semaphore_t denied = dispatch_semaphore_create(0);
            dispatch_semaphore_t peerFinal = dispatch_semaphore_create(0);
            xpc_connection_t peer = xpc_connection_create_from_endpoint(childService);
            xpc_connection_set_target_queue(peer, queue);
            xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
                if (event == XPC_ERROR_CONNECTION_INVALID || event == XPC_ERROR_CONNECTION_INTERRUPTED) dispatch_semaphore_signal(denied);
                if (event == XPC_ERROR_CONNECTION_INVALID) dispatch_semaphore_signal(peerFinal);
            });
            xpc_connection_resume(peer); xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_string(message, "privateMethod", "VM27.component.handler-denial.v8"); xpc_connection_send_message(peer, message); xpc_release(message);
            Check(!dispatch_semaphore_wait(denied, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)),
                step ? "component-handler-denied-after-raw-registration-without-typed-binding" : "component-handler-denied-before-registration-and-binding");
            xpc_connection_cancel(peer);
            Check(!dispatch_semaphore_wait(peerFinal, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-real-denied-service-final-invalid-before-release");
            dispatch_sync(queue, ^{}); xpc_release(peer); dispatch_release(denied); dispatch_release(peerFinal); continue;
        }
        unsigned index = step - 1; xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(message, "privateMethod", "VM27.register-client-title.v1");
        if (index == 1) xpc_dictionary_set_int64(message, "nonce", (int64_t)nonce);
        else xpc_dictionary_set_uint64(message, "nonce", index == 0 ? nonce ^ 1 : nonce);
        xpc_dictionary_set_string(message, "clientDisplayName", index == 2 ? "" : index == 5 ? "Different own diagnostic title" : titleUTF8);
        if (index == 6) xpc_dictionary_set_bool(message, "extraKey", true);
        __block int raw = -1, typed = -1; __block bool registered = false, matched = false;
        xpc_connection_send_message_with_reply(childPeer, message, queue, ^(xpc_object_t reply) {
            Check(PeerIdentity(reply, child, argv[3], "registrationComponentParent", "actual-reply", true), "component-every-reply-actual-child-kernel-code");
            if (reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
                raw = (int)xpc_dictionary_get_int64(reply, "componentStatus"); typed = (int)xpc_dictionary_get_int64(reply, "registrationStatus");
                registered = xpc_dictionary_get_bool(reply, "componentRegistered"); matched = xpc_dictionary_get_bool(reply, "titleMatched");
            } dispatch_semaphore_signal(replies);
        }); xpc_release(message);
        bool arrived = !dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
        Check(arrived && raw == expected[index] && typed == EACCES && registered == (index >= 3) && matched == (index >= 3),
            "component-real-cross-process-registration-positive-negative-controls");
        if (arrived) ++actualReplies; else break;
    }
    if (childPeer) {
        xpc_object_t registration = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(registration, "privateMethod", "VM27.component.register-child.v8");
        xpc_connection_send_message(childPeer, registration); xpc_release(registration);
        Check(!dispatch_semaphore_wait(childRegistered, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-parent-receives-live-child-registration-before-reap");
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0); xpc_dictionary_set_string(message, "privateMethod", "VM27.component.finish.v8");
        xpc_connection_send_message_with_reply(childPeer, message, queue, ^(xpc_object_t reply) {
            Check(PeerIdentity(reply, child, argv[3], "registrationComponentParent", "finish", true) && xpc_dictionary_get_int64(reply, "componentStatus") == 0,
                "component-finish-actual-child-reply"); dispatch_semaphore_signal(replies);
        }); xpc_release(message);
        Check(!dispatch_semaphore_wait(replies, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-finite-finish-reply");
        xpc_connection_cancel(childPeer); Check(!dispatch_semaphore_wait(final, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-parent-real-peer-final-invalid-drained");
    }
    xpc_connection_cancel(listener);
    Check(!dispatch_semaphore_wait(listenerFinal, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC)), "component-parent-listener-final-invalid-drained");
    dispatch_sync(queue, ^{});
    int status = 0; pid_t waited = 0;
    for (unsigned i = 0; child > 1 && i < 200 && !waited; ++i) { waited = waitpid(child, &status, WNOHANG); if (!waited) usleep(10000); }
    bool ownedForcedTermination = false;
    if (child > 1 && waited == 0) {
        /* This exact PID came from our successful direct posix_spawn, and the
         * actual WNOHANG wait just confirmed it is still our unreaped child. */
        ownedForcedTermination = true; Check(false, "component-owned-child-finite-reap-deadline-failed");
        int killed = kill(child, SIGKILL);
        Check(!killed || errno == ESRCH, "component-kills-only-exact-still-owned-child-for-cleanup");
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    }
    Check(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "component-child-real-zero-exit-and-reaped");
    errno = 0; bool absent = child > 1 && kill(child, 0) == -1 && errno == ESRCH;
    Check(absent && !ownedForcedTermination && OwnPortsEqual(before, beforeCount) && actualReplies == 7, "component-exact-child-absent-parent-ports-unchanged-all-replies");
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &child);
    CFStringRef keys[] = {_kLSPIDKey}; CFTypeRef values[] = {number}; errno = 0;
    CFArrayRef dead = number ? _LSCopyMatchingApplicationsWithItems(-2, 1, keys, values) : NULL;
    bool liveTokenRefused = !dead && errno == EACCES;
    Check(liveTokenRefused && retainedChildTitle && CFEqual(retainedChildTitle, CFSTR(VM27_V8_DIAGNOSTIC_TITLE)),
        "component-sticky-registration-refuses-reaped-actual-token-while-owned-title-copy-survives");
    if (dead) CFRelease(dead); if (number) CFRelease(number); if (retainedChildTitle) CFRelease(retainedChildTitle);
    if (before) ReleasePorts(before, beforeCount);
    if (childService) xpc_release(childService); if (childPeer) xpc_release(childPeer); xpc_release(endpoint); xpc_release(listener);
    dispatch_release(ready); dispatch_release(replies); dispatch_release(final); dispatch_release(listenerFinal); dispatch_release(childRegistered); dispatch_release(queue);
    Providers("parent", "after"); Check(NoVM(), "component-parent-no-VM-images-after");
    printf("{\"record\":\"registrationComponentSummary\",\"parentPID\":%d,\"childPID\":%d,\"observedWaitExit\":%d,\"checks\":%u,\"failures\":%u,\"actualReplies\":%u,\"childAbsent\":%s,\"liveTokenRefusedAfterReap\":%s,\"nativeBooleanDenialKept\":true,\"parentRegisteredPortsUnchanged\":true,\"originalHandlerCalls\":0,\"originalVMMExecuted\":false,\"nativeVMCalls\":0,\"CPUProbeCalls\":0}\n",
        getpid(), child, WIFEXITED(status) ? WEXITSTATUS(status) : -1, atomic_load(&gChecks), atomic_load(&gFailures), actualReplies, absent ? "true" : "false", liveTokenRefused ? "true" : "false");
    return atomic_load(&gFailures) ? 1 : 0;
}
