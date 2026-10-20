#include "vm27_owned_startup_coordinator_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/* Actual existing frozen Mac V8 provider, without original main/handler or a
 * peer connection. Genuine capability denial is not overridden. Preparation
 * itself does not deliver a peer, bind an instance or execute any guest code. */
static unsigned Checks;
static void Check(bool condition, const char *name) {
    ++Checks;
    if (!condition) { fprintf(stderr, "FAILED: %s\n", name); _exit(1); }
}
int main(int argc, char **argv) {
    if (argc != 4 || argv[0][0] != '/') return 2;
    alarm(15); setvbuf(stdout, NULL, _IOLBF, 0);
    pid_t childPID = fork(); if (childPID < 0) return 2;
    if (!childPID) {
        alarm(10);
        VM27OwnedStartupConfigurationV1 configuration = {argv[0], argv[1], argv[2], getppid(), 19};
        VM27OwnedStartupChildV1 *child = NULL; xpc_object_t hello = NULL;
        int prepared = VM27OwnedStartupChildPrepareV1(&configuration, &child, &hello);
        printf("{\"record\":\"actualV8PreparationAttempt\",\"parentPID\":%d,\"childPID\":%d,\"status\":%d,\"genuineV8Executed\":true}\n",
            getppid(), getpid(), prepared);
        Check(!prepared && child && hello, "actual-frozen-v8-preparation-success");
        VM27OwnedStartupStateV1 state;
        Check(!VM27OwnedStartupChildCopyStateV1(child, &state) && state.privateCheckInVerified &&
            state.transportCreated && state.registryConfigured && state.helloReturned,
            "actual-cf-checkin-and-create-require-prepared");
        Check(xpc_dictionary_get_count(hello) == 3, "actual-owned-three-field-endpoint-hello");
        VM27OriginalV8TransportStats stats;
        VM27OriginalV8TransportRegistrationStats registration;
        VM27OriginalV8TransportCopyStats(&stats);
        VM27OriginalV8TransportCopyRegistrationStats(&registration);
        Check(stats.listenersCreated == 1 && stats.originalMainCalls == 0 && stats.originalHandlerCalls == 0 &&
            !stats.peersAccepted && !stats.serverInstancesBound && !stats.instanceRequests,
            "actual-listener-prepared-without-original-main-peer-or-instance");
        Check(registration.serverConfigurations == 1 && !registration.registrationMessages &&
            !registration.registrationCommits && !registration.clientRequests,
            "actual-registry-configured-without-authentication-or-bind-claims");
        Check(!VM27OwnedStartupChildStopV1(child), "actual-bounded-v8-stop-and-final-invalid-drain");
        VM27OriginalV8TransportCopyStats(&stats);
        Check(stats.listenersDestroyed == 1 && stats.tasksCreated == stats.tasksReleased,
            "actual-service-listener-released");
        xpc_release(hello);
        Check(!VM27OwnedStartupChildReleaseV1(&child) && !child, "actual-context-released-after-service-drain");
        printf("{\"record\":\"actualV8PreparationSummary\",\"checks\":%u,\"passed\":true,\"listenersCreated\":%llu,\"listenersDestroyed\":%llu,\"originalMainCalls\":%llu,\"originalHandlerCalls\":%llu,\"registrationMessages\":0,\"guestInstructions\":0,\"nativeCPUOperations\":0,\"originalVMMExecuted\":false,\"nativeDeviceReadiness\":false,\"full27Ready\":false}\n",
            Checks, (unsigned long long)stats.listenersCreated, (unsigned long long)stats.listenersDestroyed,
            (unsigned long long)stats.originalMainCalls, (unsigned long long)stats.originalHandlerCalls);
        _exit(0);
    }
    int status = 0;
    if (waitpid(childPID, &status, 0) != childPID || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    printf("{\"record\":\"actualV8PreparationParent\",\"parentPID\":%d,\"childPID\":%d,\"childReaped\":true,\"observedWaitExit\":0}\n", getpid(), childPID);
    return 0;
}
