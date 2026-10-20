#include "vm27_owned_app_child_startup_v3.h"
#include "vm27_actual_executable_image_v1.h"
#include "vm27_owned_app_child_premain_v5.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(VM27_OWNED_PLATFORM_PREP_TESTING) && TARGET_OS_IPHONE
#error "Owned platform preparation fixture hooks are forbidden on iOS"
#endif
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef, audit_token_t);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef, CFStringRef, CFErrorRef *);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

#define VM27_CHILD_CONTENTS_V5 "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents"
#define VM27_CHILD_EXECUTABLE_V5 VM27_CHILD_CONTENTS_V5 "/MacOS/com.apple.Virtualization.VirtualMachine"
#define VM27_CHILD_PROFILE_V5 VM27_CHILD_CONTENTS_V5 "/Resources/com.apple.Virtualization.VirtualMachine.sb"
#define VM27_CHILD_PROFILE_BYTES_V5 32301U
#define VM27_CHILD_PROFILE_SHA_V5 "59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504"
/* Actual XNU cs_blobs.h flag values, queried from the current kernel. */
#define VM27_CS_REQUIRED_V5 (UINT32_C(0x00000001) | UINT32_C(0x04000000))
static VM27OwnedAppChildV1 *ActualChildStartupOwnerV4;
static bool ActualOwnedBootstrapCompletedV5;
static atomic_flag PlatformPreparationAttemptV5 = ATOMIC_FLAG_INIT;
static const uint8_t ActualChildUUIDV5[16] = {0x4a,0x6a,0x58,0x8d,0x1a,0xfd,0x30,0xf5,
    0xa6,0x4d,0x63,0x04,0xeb,0x79,0xbe,0x0b};

#if defined(VM27_OWNED_PLATFORM_PREP_TESTING)
/* HOST-only native query fixtures; these never enter an iOS product. */
extern uid_t VM27PlatformPrepTestUIDV5(void), VM27PlatformPrepTestEUIDV5(void);
extern pid_t VM27PlatformPrepTestPIDV5(void);
extern kern_return_t VM27PlatformPrepTestAuditV5(audit_token_t *, mach_msg_type_number_t *);
extern int VM27PlatformPrepTestCodeV5(pid_t, unsigned int, void *, size_t, audit_token_t *);
extern SecTaskRef VM27PlatformPrepTestTaskV5(CFAllocatorRef, audit_token_t);
extern CFTypeRef VM27PlatformPrepTestValueV5(SecTaskRef, CFStringRef, CFErrorRef *);
extern int VM27PlatformPrepTestImageV5(const char *, VM27ActualExecutableImageV1 *);
#define ACTUAL_UID_V5 VM27PlatformPrepTestUIDV5
#define ACTUAL_EUID_V5 VM27PlatformPrepTestEUIDV5
#define ACTUAL_PID_V5 VM27PlatformPrepTestPIDV5
#define ACTUAL_AUDIT_V5 VM27PlatformPrepTestAuditV5
#define ACTUAL_CODE_V5 VM27PlatformPrepTestCodeV5
#define ACTUAL_TASK_V5 VM27PlatformPrepTestTaskV5
#define ACTUAL_VALUE_V5 VM27PlatformPrepTestValueV5
#define ACTUAL_IMAGE_V5 VM27PlatformPrepTestImageV5
#else
#define ACTUAL_UID_V5 getuid
#define ACTUAL_EUID_V5 geteuid
#define ACTUAL_PID_V5 getpid
#define ACTUAL_CODE_V5 csops_audittoken
#define ACTUAL_TASK_V5 SecTaskCreateWithAuditToken
#define ACTUAL_VALUE_V5 SecTaskCopyValueForEntitlement
#define ACTUAL_IMAGE_V5 VM27ActualExecutableImageFindV1
static kern_return_t ActualSelfAuditV5(audit_token_t *token, mach_msg_type_number_t *count) {
    return task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)token, count);
}
#define ACTUAL_AUDIT_V5 ActualSelfAuditV5
#endif

#if !defined(VM27_OWNED_PLATFORM_PREP_TESTING)
static bool ActualOriginalChildV4(void) {
    VM27ActualExecutableImageV1 image = {0};
    return !VM27ActualExecutableImageFindSelfV1(&image) &&
        !memcmp(image.uuid, ActualChildUUIDV5, sizeof(ActualChildUUIDV5));
}
__attribute__((constructor)) static void ActualOwnedChildPreMainV4(void) {
    /* The inherited V3 bootstrap authenticates the actual parent before
     * accepting its configuration. Failure terminates this child unchanged. */
    if (!ActualOriginalChildV4() ||
        VM27OwnedAppChildBootstrapBeforeMainV3(&ActualChildStartupOwnerV4)) _exit(78);
    ActualOwnedBootstrapCompletedV5 = ActualChildStartupOwnerV4 != NULL;
    /* Preserve the true startup/control owner for original Main's lifetime.
     * No native VM/CPU operation or installer runs in this constructor. */
}
#endif

static bool ActualAuditIdentityV5(pid_t pid, const audit_token_t *token) {
    return pid > 1 && ACTUAL_PID_V5() == pid && ACTUAL_UID_V5() == 501 &&
        ACTUAL_EUID_V5() == 501 && token->val[5] == (uint32_t)pid &&
        token->val[1] == 501 && token->val[3] == 501 && token->val[7] != 0;
}
static bool ActualNativeTrueV5(SecTaskRef task, CFStringRef name) {
    CFErrorRef error = NULL;
    CFTypeRef value = ACTUAL_VALUE_V5(task, name, &error);
    bool yes = value && !error && CFGetTypeID(value) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value);
    if (error) CFRelease(error);
    if (value) CFRelease(value);
    return yes;
}
static bool ActualPlatformIdentityV5(void) {
    pid_t pid = ACTUAL_PID_V5();
    VM27ActualExecutableImageV1 image = {0}, finalImage = {0};
    if (!ActualOwnedBootstrapCompletedV5 || !ActualChildStartupOwnerV4 ||
        ACTUAL_UID_V5() != 501 || ACTUAL_EUID_V5() != 501 || pid <= 1 ||
        ACTUAL_IMAGE_V5(VM27_CHILD_EXECUTABLE_V5, &image) ||
        memcmp(image.uuid, ActualChildUUIDV5, sizeof(ActualChildUUIDV5))) return false;
    audit_token_t token = {{0}}, after = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    uint32_t status = 0, afterStatus = 0;
    unsigned char digest[20] = {0}, afterDigest[20] = {0};
    if (ACTUAL_AUDIT_V5(&token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT || !ActualAuditIdentityV5(pid, &token) ||
        ACTUAL_CODE_V5(pid, 0, &status, sizeof(status), &token) ||
        (status & VM27_CS_REQUIRED_V5) != VM27_CS_REQUIRED_V5 ||
        ACTUAL_CODE_V5(pid, 5, digest, sizeof(digest), &token)) return false;
    bool nonzero = false;
    for (size_t i = 0; i < sizeof(digest); ++i) nonzero |= digest[i] != 0;
    if (!nonzero) return false;
    SecTaskRef task = ACTUAL_TASK_V5(kCFAllocatorDefault, token);
    if (!task) return false;
    bool platform = ActualNativeTrueV5(task, CFSTR("platform-application"));
    bool noContainer = ActualNativeTrueV5(task, CFSTR("com.apple.private.security.no-container"));
    bool noSandbox = ActualNativeTrueV5(task, CFSTR("com.apple.private.security.no-sandbox"));
    CFRelease(task);
    if (!platform || !noContainer || !noSandbox) return false;
    count = TASK_AUDIT_TOKEN_COUNT;
    return ACTUAL_AUDIT_V5(&after, &count) == KERN_SUCCESS &&
        count == TASK_AUDIT_TOKEN_COUNT && !memcmp(&token, &after, sizeof(token)) &&
        ActualAuditIdentityV5(pid, &after) &&
        !ACTUAL_CODE_V5(pid, 0, &afterStatus, sizeof(afterStatus), &after) &&
        (afterStatus & VM27_CS_REQUIRED_V5) == VM27_CS_REQUIRED_V5 &&
        !ACTUAL_CODE_V5(pid, 5, afterDigest, sizeof(afterDigest), &after) &&
        !memcmp(digest, afterDigest, sizeof(digest)) &&
        !ACTUAL_IMAGE_V5(VM27_CHILD_EXECUTABLE_V5, &finalImage) &&
        finalImage.header == image.header && finalImage.dyldIndex == image.dyldIndex &&
        !memcmp(finalImage.uuid, ActualChildUUIDV5, sizeof(ActualChildUUIDV5));
}
static bool ActualSameFileV5(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_size == b->st_size &&
        a->st_nlink == b->st_nlink && a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static bool ActualResourceAtV5(const char *path, size_t count, const char *expectedSHA,
                              uid_t owner, gid_t group) {
    char resolved[PATH_MAX]; struct stat a, b, current;
    if (!path || !count || count > UINT32_MAX || !realpath(path, resolved) ||
        strcmp(path, resolved)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fstat(fd, &a) == 0 && S_ISREG(a.st_mode) && a.st_uid == owner &&
        a.st_gid == group && (a.st_mode & 07777) == 0600 && a.st_nlink == 1 &&
        a.st_size == (off_t)count;
    unsigned char *bytes = ok ? malloc(count) : NULL;
    if (!bytes) ok = false;
    size_t done = 0;
    while (ok && done < count) {
        ssize_t n = read(fd, bytes + done, count - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        done += (size_t)n;
    }
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; char hex[65];
    ok = ok && fstat(fd, &b) == 0 && lstat(path, &current) == 0 &&
        ActualSameFileV5(&a, &b) && ActualSameFileV5(&a, &current);
    if (ok) {
        ok = CC_SHA256(bytes, (CC_LONG)count, hash) != NULL;
        for (size_t i = 0; ok && i < sizeof(hash); ++i) snprintf(hex + 2 * i, 3, "%02x", hash[i]);
        ok = ok && !strcmp(hex, expectedSHA);
    }
    free(bytes);
    int rc = close(fd);
    return ok && rc == 0;
}
static bool ActualProfileResourceV5(void) {
#if defined(VM27_OWNED_PLATFORM_PREP_TESTING)
    extern bool VM27PlatformPrepTestResourceV5(void);
    return VM27PlatformPrepTestResourceV5();
#else
    return ActualResourceAtV5(VM27_CHILD_PROFILE_V5, VM27_CHILD_PROFILE_BYTES_V5,
        VM27_CHILD_PROFILE_SHA_V5, 501, 501);
#endif
}
static int ActualPreparationErrorV5(char **out, int error, const char *stage) {
    if (out) {
        char *message = NULL;
        if (asprintf(&message, "Owned platform launch preparation %s failed (%d): %s; sandboxProfileApplied=0",
                     stage, error, strerror(error)) >= 0) *out = message;
    }
    errno = error;
    return -1;
}
int VM27OwnedPlatformLaunchPrepareV1(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf) {
    if (errorbuf) *errorbuf = NULL;
    if (!profile || strcmp(profile, VM27_CHILD_PROFILE_V5) || flags != 3 || parameters)
        return ActualPreparationErrorV5(errorbuf, ENOTSUP, "explicit call scope");
    if (atomic_flag_test_and_set_explicit(&PlatformPreparationAttemptV5, memory_order_acq_rel))
        return ActualPreparationErrorV5(errorbuf, EALREADY, "single preparation");
    if (!ActualPlatformIdentityV5())
        return ActualPreparationErrorV5(errorbuf, EACCES, "bootstrap owner or actual identity/permissions");
    if (!ActualProfileResourceV5() || !ActualPlatformIdentityV5())
        return ActualPreparationErrorV5(errorbuf, EACCES, "resource or final identity");
    /* The current Sandbox operation 0 returns ENOTSUP before inspecting any
     * profile. This own function deliberately does not call sandbox_init,
     * sandbox_apply, a compiler, native VM/CPU operations, or a grant helper. */
    dprintf(STDERR_FILENO, "VM27 owned platform launchPrepared=1 sandboxProfileApplied=0 nativeSandboxApplyUnavailable=45 nativeLastDiagnosticErrno=45 policyDeferred=1 trustedGuestOwnedProcess=1\n");
    errno = 0;
    return 0;
}
