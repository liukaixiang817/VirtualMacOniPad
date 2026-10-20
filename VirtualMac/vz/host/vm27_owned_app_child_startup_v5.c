/* Actual post-spawn diagnostics only. Each original typed callee executes once;
 * its return value, errno, output ownership and all frozen gates are preserved. */
#include "vm27_owned_app_child_startup_v3.h"
#include "vm27_owned_app_parent_identity_v1.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static int ReceivedMessageDiagnosticV5(VM27LargePrivateServiceConsumerV2 *consumer,
    xpc_object_t message, VM27ApprovedCodeMessageResult *out) {
    int status = VM27LargePrivateServiceConsumerV2CheckMessage(consumer, message, out);
    int actualErrno = errno;
    if (out) {
        const VM27LWCRMessageResult *native = &out->nativePolicy;
        fprintf(stderr, "[Independent27] parent-config check-message status=%d result=%d "
            "nativeResult=%d remote=%d task=%d entitlementsValidated=%d "
            "entitlementPresent=%d entitlementBoolean=%d entitlementValue=%d entitlementReadError=%d "
            "auditPID=%u auditVersion=%u auditTokenPresent=%d filePinMatched=%d "
            "codeHashMatched=%d codeStatus=%08x dynamicCodeValid=%d "
            "codeQueryError=%d statusQueryError=%d\n",
            status, out->result, native->result, native->hasRemoteConnection,
            native->taskCreated, native->entitlementsValidated, native->entitlementPresent,
            native->entitlementIsBoolean, native->entitlementValue, native->entitlementReadError,
            (unsigned)out->auditPID, (unsigned)out->auditPIDVersion, out->auditTokenPresent,
            out->filePinMatched, out->codeHashMatched, (unsigned)out->codeStatus,
            out->dynamicCodeValid, out->codeQueryError, out->statusQueryError);
    } else {
        fprintf(stderr, "[Independent27] parent-config check-message status=%d outputAbsent=1\n", status);
    }
    errno = actualErrno;
    return status;
}

static int ParentInstallFactoryDiagnosticV5(VM27LargePrivateServiceConsumerV2 *consumer,
    xpc_object_t message, uint64_t nonce) {
    int status = VM27OwnedStartupParentInstallFactoryV3(consumer, message, nonce);
    int actualErrno = errno;
    /* The frozen external coordinator/transport performs its own exact native
     * check. Its internal result is not available here, and is never repeated. */
    fprintf(stderr, "[Independent27] parent-hello install-factory status=%d nativeDetailsAvailable=0\n", status);
    errno = actualErrno;
    return status;
}

static int ActualParentMessageDiagnosticV5(xpc_object_t message,
    VM27OwnedAppParentIdentityV1 *out) {
    int status = VM27OwnedAppCheckActualParentMessageV1(message, out);
    int actualErrno = errno;
    fprintf(stderr, "[Independent27] child-parent-message status=%d pid=%ld ppid=%ld "
        "uid=%u euid=%u identityPublished=%d\n", status, (long)getpid(), (long)getppid(),
        (unsigned)getuid(), (unsigned)geteuid(), status == 0 && out != NULL);
    /* This API only publishes identity on success. Cleared failure output is
     * not represented as a successful audit/code/entitlement observation. */
    if (status == 0 && out) {
        fprintf(stderr, "[Independent27] child-parent-identity auditPID=%u auditVersion=%u "
            "codeStatus=%08x capabilityMask=%u entitlementsValidated=%d\n",
            (unsigned)out->auditPID, (unsigned)out->auditPIDVersion,
            (unsigned)out->codeStatus, (unsigned)out->baseCapabilityMask,
            out->nativeEntitlementsValidated);
    }
    errno = actualErrno;
    return status;
}

static int ChildPrepareDiagnosticV5(const VM27OwnedStartupConfigurationV3 *configuration,
    VM27OwnedStartupChildV3 **child, xpc_object_t *hello) {
    int status = VM27OwnedStartupChildPrepareV3(configuration, child, hello);
    int actualErrno = errno;
    fprintf(stderr, "[Independent27] child-prepare status=%d pid=%ld ppid=%ld "
        "uid=%u euid=%u acquiredOwnerReturned=%d helloReturned=%d\n",
        status, (long)getpid(), (long)getppid(), (unsigned)getuid(), (unsigned)geteuid(),
        child != NULL && *child != NULL, hello != NULL && *hello != NULL);
    errno = actualErrno;
    return status;
}

#define VM27LargePrivateServiceConsumerV2CheckMessage ReceivedMessageDiagnosticV5
#define VM27OwnedStartupParentInstallFactoryV3 ParentInstallFactoryDiagnosticV5
#define VM27OwnedAppCheckActualParentMessageV1 ActualParentMessageDiagnosticV5
#define VM27OwnedStartupChildPrepareV3 ChildPrepareDiagnosticV5
#include "vm27_owned_app_child_startup_v4.c"
#undef VM27LargePrivateServiceConsumerV2CheckMessage
#undef VM27OwnedStartupParentInstallFactoryV3
#undef VM27OwnedAppCheckActualParentMessageV1
#undef VM27OwnedStartupChildPrepareV3
