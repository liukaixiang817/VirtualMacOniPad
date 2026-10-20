#include "vm27_owned_startup_coordinator_v1.h"
#include "vm27_headless_checkin_v1.h"
#include <errno.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* LOCAL test doubles only. This executable does not link the genuine V8
 * provider. Endpoint cancellation is real own XPC; all transport statuses and
 * control replies below are test state, not authenticated original IPC proof. */
CFTypeRef VM27TestCheckInA(int32_t, CFDictionaryRef);
int32_t VM27TestCopyCheckInA(CFDictionaryRef *);
CFTypeRef VM27TestCheckInB(int32_t, CFDictionaryRef);
int32_t VM27TestCopyCheckInB(CFDictionaryRef *);
static _Atomic(unsigned) Checks;
static int CheckInRouting, CreateStatus, RequireStatus, StopTimeouts;
static unsigned CreateCalls, RequireCalls, StopCalls, RegistrationCalls, BindingCalls, ParentCalls;
static xpc_connection_t OwnListener;
static dispatch_queue_t OwnQueue;
static dispatch_semaphore_t OwnFinal, HoldRegistration, RegistrationEntered, HoldStop, StopEntered;
static bool StopStarted;

static void Check(bool condition, const char *name) {
    ++Checks;
    if (!condition) { fprintf(stderr, "FAILED: %s\n", name); exit(1); }
}
static bool Wait(dispatch_semaphore_t semaphore) {
    return !dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
}
CFTypeRef _LSApplicationCheckIn(int32_t session, CFDictionaryRef information) {
    return VM27TestCheckInA(session, information);
}
int32_t VM27CopyPrivateHeadlessCheckInState(CFDictionaryRef *output) {
    if (CheckInRouting == 2) {
        CFBundleRef bundle = CFBundleGetMainBundle();
        Check(VM27TestCheckInB(-2, CFBundleGetInfoDictionary(bundle)) != NULL, "second-real-helper-singleton-registered");
    }
    return CheckInRouting ? VM27TestCopyCheckInB(output) : VM27TestCopyCheckInA(output);
}
int VM27OriginalV8TransportCreateServer(const char *path, const char *SHA, const char *CD,
    pid_t parent, dispatch_queue_t queue, xpc_endpoint_t *output) {
    ++CreateCalls;
    Check(path && path[0] == '/' && strlen(SHA) == 64 && strlen(CD) == 40 && parent > 1,
        "explicit-parent-inputs-forwarded-to-test-double");
    if (CreateStatus) return CreateStatus;
    OwnQueue = queue; OwnFinal = dispatch_semaphore_create(0);
    OwnListener = xpc_connection_create(NULL, queue);
    if (!OwnListener || !OwnFinal) return ENOMEM;
    xpc_connection_set_event_handler(OwnListener, ^(xpc_object_t event) {
        if (event == XPC_ERROR_CONNECTION_INVALID) dispatch_semaphore_signal(OwnFinal);
    });
    *output = xpc_endpoint_create(OwnListener);
    return *output ? 0 : ENOMEM;
}
int VM27OriginalV8TransportRequireServerInstance(uint64_t nonce) {
    ++RequireCalls; Check(nonce == 19, "nonce-forwarded-without-body-identity"); return RequireStatus;
}
int VM27OriginalV8TransportStopServer(void) {
    ++StopCalls;
    if (StopEntered) { dispatch_semaphore_signal(StopEntered); Check(Wait(HoldStop), "test-stop-owner-released"); }
    if (StopTimeouts) { --StopTimeouts; return ETIMEDOUT; }
    if (!StopStarted) { StopStarted = true; xpc_connection_resume(OwnListener); xpc_connection_cancel(OwnListener); }
    Check(Wait(OwnFinal), "own-test-listener-real-final-invalid");
    dispatch_sync(OwnQueue, ^{});
    xpc_release(OwnListener); OwnListener = NULL;
    dispatch_release(OwnFinal); OwnFinal = NULL;
    return 0;
}
int VM27OriginalV8TransportReceiveServerClientRegistrationMessage(xpc_object_t message, xpc_object_t *reply) {
    (void)message; ++RegistrationCalls;
    if (RegistrationEntered) {
        dispatch_semaphore_signal(RegistrationEntered);
        Check(Wait(HoldRegistration), "test-control-call-owner-released");
    }
    *reply = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(*reply, "testOnlyStatus", EACCES);
    return EACCES;
}
int VM27OriginalV8TransportBindServerInstanceMessage(xpc_object_t message, xpc_object_t *reply) {
    (void)message; ++BindingCalls;
    *reply = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(*reply, "testOnlyStatus", EPROTO);
    return EPROTO;
}
int VM27OriginalV8TransportInstallClientFactoryMessage(VM27PrivateServiceConsumer *consumer,
    xpc_object_t message, uint64_t nonce) {
    (void)consumer; (void)message; Check(nonce == 19, "parent-expected-nonce-forwarded"); ++ParentCalls; return EACCES;
}
static VM27OwnedStartupConfigurationV1 Configuration(void) {
    return (VM27OwnedStartupConfigurationV1){"/private/test-only-reviewed-parent",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", getppid(), 19};
}
static xpc_object_t Message(const char *method, bool extra) {
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "privateMethod", method);
    xpc_dictionary_set_uint64(message, "nonce", 19);
    if (!strcmp(method, "VM27.bind-one-shot-instance.v1")) {
        unsigned char uuid[16] = {1}; xpc_dictionary_set_data(message, "instanceUUID", uuid, sizeof(uuid));
    } else xpc_dictionary_set_string(message, "clientDisplayName", "Real test bundle name");
    if (extra) xpc_dictionary_set_bool(message, "unacceptedField", true);
    return message;
}
static void Done(VM27OwnedStartupChildV1 **child, xpc_object_t hello, dispatch_queue_t queue) {
    Check(VM27OwnedStartupChildStopV1(*child) == 0, "bounded-test-stop-success");
    if (queue) { dispatch_sync(queue, ^{}); dispatch_release(queue); }
    if (hello) xpc_release(hello);
    Check(VM27OwnedStartupChildReleaseV1(child) == 0 && !*child, "context-released-after-real-own-listener-drain");
}
static void SuccessAndSchema(void) {
    VM27OwnedStartupConfigurationV1 configuration = Configuration();
    VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL;
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello) == 0 && child && hello, "ordinary-state-prepare");
    Check(xpc_dictionary_get_count(hello) == 3, "exact-three-field-hello");
    VM27OwnedStartupStateV1 state;
    Check(!VM27OwnedStartupChildCopyStateV1(child, &state) && state.phase == VM27OwnedStartupPreparedV1 &&
        state.privateCheckInVerified && state.transportCreated && state.registryConfigured && state.helloReturned,
        "real-cf-checkin-and-typed-preparation-state");
    Check(VM27OwnedStartupChildReleaseV1(&child) == EBUSY && child, "release-refused-before-stop");
    VM27OwnedStartupChildV1 *second = NULL; xpc_object_t secondHello = NULL;
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &second, &secondHello) == EALREADY && !second && !secondHello,
        "process-reservation-cannot-be-reused");
    dispatch_queue_t queue = NULL;
    Check(!VM27OwnedStartupChildCopyControlQueueV1(child, &queue) && queue, "retained-actual-owned-serial-queue");
    xpc_object_t registration = Message("VM27.register-client-title.v1", false), reply = NULL;
    Check(VM27OwnedStartupChildReceiveControlV1(child, registration, &reply) == EDEADLK && !reply,
        "off-queue-control-does-not-route");
    dispatch_sync(queue, ^{
        xpc_object_t response = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, registration, &response) == EACCES && response,
            "existing-registration-refusal-and-owned-reply-preserved"); xpc_release(response);
        xpc_object_t extra = Message("VM27.register-client-title.v1", true); response = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, extra, &response) == EPROTO && !response,
            "known-method-extra-field-pre-refused"); xpc_release(extra);
        xpc_object_t binding = Message("VM27.bind-one-shot-instance.v1", false); response = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, binding, &response) == EPROTO && response,
            "existing-binding-refusal-and-owned-reply-preserved"); xpc_release(response); xpc_release(binding);
        xpc_object_t unknown = Message("application-method-not-handled", false); response = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, unknown, &response) == ENOTSUP && !response,
            "unknown-original-application-protocol-not-handled"); xpc_release(unknown);
        Check(VM27OwnedStartupChildStopV1(child) == EDEADLK, "same-queue-stop-refused");
    });
    Check(!VM27OwnedStartupChildCopyStateV1(child, &state) && state.controlMessages == 4 &&
        state.registrationRoutes == 1 && state.bindingRoutes == 1 && state.refusedControlMessages == 4,
        "route-counters-count-actual-test-double-calls-only");
    /* Non-dereferenced sentinel is solely a test-double consumer handle. */
    VM27PrivateServiceConsumer *testConsumer = (VM27PrivateServiceConsumer *)(uintptr_t)1;
    Check(VM27OwnedStartupParentInstallFactoryV1(testConsumer, hello, 19) == EACCES && ParentCalls == 1,
        "parent-gate-denial-not-upgraded-to-success");
    Check(VM27OwnedStartupParentInstallFactoryV1(testConsumer, hello, 20) == EPROTO && ParentCalls == 1,
        "parent-wrong-nonce-rejected-before-gate");
    xpc_dictionary_set_bool(hello, "claimedIdentity", true);
    Check(VM27OwnedStartupParentInstallFactoryV1(testConsumer, hello, 19) == EPROTO && ParentCalls == 1,
        "parent-extra-identity-field-rejected-before-gate");
    pid_t forked = fork(); Check(forked >= 0, "own-fork-created");
    if (!forked) {
        VM27OwnedStartupStateV1 copy;
        int rc = VM27OwnedStartupChildCopyStateV1(child, &copy);
        _exit(rc == EPERM ? 0 : 1);
    }
    int waited = 0; Check(waitpid(forked, &waited, 0) == forked && WIFEXITED(waited) && !WEXITSTATUS(waited),
        "fork-child-refuses-inherited-context-before-mutex");
    xpc_release(registration); Done(&child, hello, queue);
}
static void InvalidConfiguration(void) {
    VM27OwnedStartupConfigurationV1 configuration = Configuration();
    VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL;
    configuration.bootstrapNonce = 0;
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello) == EINVAL && !child && !hello && !CreateCalls,
        "zero-nonce-rejected-before-private-state");
    configuration = Configuration(); configuration.actualParentCodePath = "relative";
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello) == EINVAL && !child && !hello,
        "relative-code-path-rejected");
    configuration = Configuration(); configuration.reviewedParentCDHash = "bb";
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello) == EINVAL && !child && !hello,
        "unreviewed-code-hash-rejected");
    configuration = Configuration();
    Check(!VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello), "invalid-preconditions-did-not-spend-valid-attempt");
    Done(&child, hello, NULL);
}
static void Failure(int kind) {
    CreateStatus = kind == 1 ? EACCES : 0; RequireStatus = kind == 2 ? EIO : 0;
    CheckInRouting = kind == 3 ? 1 : kind == 4 ? 2 : 0;
    VM27OwnedStartupConfigurationV1 configuration = Configuration();
    VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL;
    int expected = kind == 1 ? EACCES : kind == 2 ? EIO : kind == 3 ? ENOENT : EPROTO;
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello) == expected && child && !hello,
        "failure-context-retained-no-hello");
    VM27OwnedStartupStateV1 state;
    Check(!VM27OwnedStartupChildCopyStateV1(child, &state) && state.preparationStatus == expected && !state.helloReturned,
        "actual-failure-status-recorded");
    if (kind >= 3) Check(!CreateCalls && !state.privateCheckInVerified,
        "wrong-checkin-provider-singleton-rejected-before-transport");
    if (kind == 2) Check(state.phase == VM27OwnedStartupClosingV1 && state.transportCreated && !state.registryConfigured,
        "registration-failure-leaves-created-listener-owned");
    Done(&child, hello, NULL);
    Check(StopCalls == (kind == 2 ? 1u : 0u), "only-created-transport-needs-stop");
    VM27OwnedStartupChildV1 *again = NULL; xpc_object_t againHello = NULL;
    Check(VM27OwnedStartupChildPrepareV1(&configuration, &again, &againHello) == EALREADY && !again && !againHello,
        "failed-attempt-not-falsely-reset");
}
static void TimeoutRetry(void) {
    VM27OwnedStartupConfigurationV1 configuration = Configuration();
    VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL;
    Check(!VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello), "timeout-fixture-prepared");
    StopTimeouts = 1;
    Check(VM27OwnedStartupChildStopV1(child) == ETIMEDOUT, "test-double-timeout-preserved");
    VM27OwnedStartupStateV1 state;
    Check(!VM27OwnedStartupChildCopyStateV1(child, &state) && state.phase == VM27OwnedStartupClosingV1 &&
        state.cleanupStatus == ETIMEDOUT, "timeout-context-retained");
    Check(VM27OwnedStartupChildReleaseV1(&child) == EBUSY && child, "timeout-resource-release-refused");
    Done(&child, hello, NULL); Check(StopCalls == 2, "bounded-stop-retry-actually-called");
}
static void ActiveAndConcurrentStop(void) {
    VM27OwnedStartupConfigurationV1 configuration = Configuration();
    VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL; dispatch_queue_t queue = NULL;
    Check(!VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello), "concurrent-fixture-prepared");
    Check(!VM27OwnedStartupChildCopyControlQueueV1(child, &queue), "concurrent-actual-queue-retained");
    HoldRegistration = dispatch_semaphore_create(0); RegistrationEntered = dispatch_semaphore_create(0);
    dispatch_semaphore_t controlDone = dispatch_semaphore_create(0);
    xpc_object_t registration = Message("VM27.register-client-title.v1", false);
    dispatch_async(queue, ^{
        xpc_object_t reply = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, registration, &reply) == EACCES && reply,
            "inflight-control-refusal-remains-owned"); xpc_release(reply); dispatch_semaphore_signal(controlDone);
    });
    Check(Wait(RegistrationEntered), "real-serial-queue-control-call-entered");
    Check(VM27OwnedStartupChildStopV1(child) == EBUSY && !StopCalls, "active-control-stop-closes-admission-without-transport-stop");
    dispatch_semaphore_signal(HoldRegistration); Check(Wait(controlDone), "control-call-completed-after-busy-stop");
    dispatch_sync(queue, ^{
        xpc_object_t reply = NULL;
        Check(VM27OwnedStartupChildReceiveControlV1(child, registration, &reply) == ECANCELED && !reply,
            "closing-context-refuses-later-control-call");
    });
    StopEntered = dispatch_semaphore_create(0); HoldStop = dispatch_semaphore_create(0);
    dispatch_semaphore_t stopDone = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        Check(!VM27OwnedStartupChildStopV1(child), "one-concurrent-stop-owner-completed"); dispatch_semaphore_signal(stopDone);
    });
    Check(Wait(StopEntered), "transport-stop-owner-inflight");
    Check(VM27OwnedStartupChildStopV1(child) == EBUSY && StopCalls == 1,
        "second-stop-cannot-clear-other-owner-reservation");
    Check(VM27OwnedStartupChildReleaseV1(&child) == EBUSY && child, "inflight-stop-release-refused");
    dispatch_semaphore_signal(HoldStop); Check(Wait(stopDone), "actual-own-final-invalid-stop-completed");
    dispatch_sync(queue, ^{}); dispatch_release(queue); xpc_release(hello); xpc_release(registration);
    Check(!VM27OwnedStartupChildReleaseV1(&child) && !child, "concurrent-context-released-only-after-all-calls-finished");
    dispatch_release(HoldRegistration); dispatch_release(RegistrationEntered); dispatch_release(controlDone);
    dispatch_release(StopEntered); dispatch_release(HoldStop); dispatch_release(stopDone);
}
int main(void) {
    alarm(90); setvbuf(stdout, NULL, _IOLBF, 0);
    unsigned total = 0;
    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        pid_t child = fork(); if (child < 0) return 2;
        if (!child) {
            alarm(10); Checks = 0;
            if (scenario == 0) SuccessAndSchema();
            else if (scenario == 1) InvalidConfiguration();
            else if (scenario <= 5) Failure((int)scenario - 1);
            else if (scenario == 6) TimeoutRetry();
            else ActiveAndConcurrentStop();
            printf("{\"record\":\"localStateScenario\",\"scenario\":%u,\"checks\":%u,\"passed\":true,\"genuineV8Executed\":false,\"originalVMMExecuted\":false,\"nativeCPUOperations\":0}\n", scenario, atomic_load(&Checks));
            _exit(0);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
        ++total;
    }
    printf("{\"record\":\"localStateSummary\",\"scenarios\":%u,\"passed\":true,\"nativeDeviceReadiness\":false,\"full27Ready\":false}\n", total);
    return 0;
}
