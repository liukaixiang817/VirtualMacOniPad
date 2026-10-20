/* Finite HOST model of native query failures plus real own-file checks.
 * Native audit, code flags and SecTask results are mocked, never device proof. */
#define VM27_OWNED_PLATFORM_PREP_TESTING 1
#include "vm27_owned_app_child_premain_v5.c"
#include <assert.h>
static struct {
    uid_t uid, euid; pid_t pid; unsigned auditCalls, codeCalls, imageCalls;
    uint32_t flags; int auditFailure, countFailure, auditPIDFailure, auditVersionFailure;
    int codeFailure, zeroDigest, taskFailure, imageFailure, uuidFailure;
    int changedAudit, changedDigest, changedImage, entitlementMode, entitlementIndex;
    bool resource;
} M;
static unsigned Checks, Cases;
static void CheckAt(bool ok, unsigned line) { ++Checks; if (!ok) { fprintf(stderr, "CHECK_FAILED line=%u\n", line); abort(); } }
#define Check(ok) CheckAt((ok), __LINE__)
uid_t VM27PlatformPrepTestUIDV5(void) { return M.uid; }
uid_t VM27PlatformPrepTestEUIDV5(void) { return M.euid; }
pid_t VM27PlatformPrepTestPIDV5(void) { return M.pid; }
kern_return_t VM27PlatformPrepTestAuditV5(audit_token_t *out, mach_msg_type_number_t *count) {
    ++M.auditCalls; if (M.auditFailure) return KERN_FAILURE;
    *count = M.countFailure ? 1 : TASK_AUDIT_TOKEN_COUNT;
    *out = (audit_token_t){{0,501,501,501,501,(uint32_t)M.pid,0,37}};
    if (M.auditPIDFailure) ++out->val[5];
    if (M.auditVersionFailure) out->val[7] = 0;
    if (M.changedAudit && M.auditCalls > 1) ++out->val[7];
    return KERN_SUCCESS;
}
int VM27PlatformPrepTestCodeV5(pid_t pid, unsigned op, void *out, size_t count, audit_token_t *token) {
    ++M.codeCalls; Check(pid == M.pid && token->val[5] == (uint32_t)pid);
    if (M.codeFailure) return -1;
    if (op == 0) { Check(count == 4); memcpy(out, &M.flags, 4); }
    else { Check(op == 5 && count == 20); memset(out, M.zeroDigest ? 0 : 17, count);
        if (M.changedDigest && M.codeCalls > 2) ((unsigned char *)out)[0] ^= 1; }
    return 0;
}
SecTaskRef VM27PlatformPrepTestTaskV5(CFAllocatorRef allocator, audit_token_t token) {
    (void)allocator; Check(token.val[7] == 37);
    return M.taskFailure ? NULL : (SecTaskRef)CFRetain(CFSTR("host native task fixture"));
}
CFTypeRef VM27PlatformPrepTestValueV5(SecTaskRef task, CFStringRef name, CFErrorRef *error) {
    Check(task != NULL); int index = CFEqual(name, CFSTR("platform-application")) ? 1 :
        CFEqual(name, CFSTR("com.apple.private.security.no-container")) ? 2 :
        CFEqual(name, CFSTR("com.apple.private.security.no-sandbox")) ? 3 : 0;
    Check(index != 0);
    if (index == M.entitlementIndex) {
        if (M.entitlementMode == 1) return NULL;
        if (M.entitlementMode == 2) return CFRetain(kCFBooleanFalse);
        if (M.entitlementMode == 3) return CFRetain(CFSTR("true"));
        if (M.entitlementMode == 4) *error = CFErrorCreate(NULL, kCFErrorDomainPOSIX, EACCES, NULL);
    }
    return CFRetain(kCFBooleanTrue);
}
int VM27PlatformPrepTestImageV5(const char *path, VM27ActualExecutableImageV1 *out) {
    ++M.imageCalls; Check(!strcmp(path, VM27_CHILD_EXECUTABLE_V5));
    if (M.imageFailure) return ENOEXEC;
    *out = (VM27ActualExecutableImageV1){.header=(const void *)&M, .dyldIndex=2};
    memcpy(out->uuid, ActualChildUUIDV5, 16);
    if (M.uuidFailure) out->uuid[0] ^= 1;
    if (M.changedImage && M.imageCalls > 1) ++out->dyldIndex;
    return 0;
}
bool VM27PlatformPrepTestResourceV5(void) { return M.resource; }
static void Reset(void) {
    memset(&M, 0, sizeof(M)); M.uid = M.euid = 501; M.pid = 100;
    M.flags = VM27_CS_REQUIRED_V5; M.resource = true;
    ActualChildStartupOwnerV4 = (VM27OwnedAppChildV1 *)&M;
    ActualOwnedBootstrapCompletedV5 = true;
    atomic_flag_clear_explicit(&PlatformPreparationAttemptV5, memory_order_release);
}
static int Call(const char *path, uint64_t flags, const char *const *parameters, int expectedErrno) {
    char *error = (char *)(uintptr_t)1; ++Cases; errno = 123;
    int rc = VM27OwnedPlatformLaunchPrepareV1(path, flags, parameters, &error);
    Check(errno == expectedErrno);
    if (expectedErrno) { Check(rc == -1 && error && strstr(error, "sandboxProfileApplied=0")); free(error); }
    else Check(rc == 0 && error == NULL);
    return rc;
}
int main(void) {
    Reset(); Call(NULL, 3, NULL, ENOTSUP); Check(M.auditCalls == 0);
    Reset(); Call("/tmp/foreign.sb", 3, NULL, ENOTSUP);
    Reset(); Call(VM27_CHILD_PROFILE_V5, 0, NULL, ENOTSUP);
    Reset(); const char *params[] = {NULL}; Call(VM27_CHILD_PROFILE_V5, 3, params, ENOTSUP);
    Reset(); ActualChildStartupOwnerV4 = NULL; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); ActualOwnedBootstrapCompletedV5 = false; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.uid = 0; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.euid = 0; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.pid = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.imageFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.uuidFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.auditFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.countFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.auditPIDFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.auditVersionFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.flags &= ~UINT32_C(1); Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.flags &= ~UINT32_C(0x04000000); Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.codeFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.zeroDigest = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.taskFailure = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    for (int i = 1; i <= 3; ++i) for (int mode = 1; mode <= 4; ++mode) {
        Reset(); M.entitlementIndex = i; M.entitlementMode = mode;
        Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    }
    Reset(); M.changedAudit = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.changedDigest = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.changedImage = 1; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); M.resource = false; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    Reset(); Call(VM27_CHILD_PROFILE_V5, 3, NULL, 0);
    Call(VM27_CHILD_PROFILE_V5, 3, NULL, EALREADY);
    Reset(); ActualChildStartupOwnerV4 = NULL; Call(VM27_CHILD_PROFILE_V5, 3, NULL, EACCES);
    ActualChildStartupOwnerV4 = (VM27OwnedAppChildV1 *)&M;
    Call(VM27_CHILD_PROFILE_V5, 3, NULL, EALREADY);
    Reset(); M.uid = 0; Check(VM27OwnedPlatformLaunchPrepareV1(VM27_CHILD_PROFILE_V5, 3, NULL, NULL) == -1 && errno == EACCES);

    /* Real local regular-file ownership, mode, SHA, link and path tests. */
    char dir[] = "/private/tmp/vm27-platform-prep-file-XXXXXX";
    Check(mkdtemp(dir) != NULL); char path[PATH_MAX], linkPath[PATH_MAX];
    Check(snprintf(path, sizeof(path), "%s/profile.sb", dir) > 0);
    Check(snprintf(linkPath, sizeof(linkPath), "%s/other.sb", dir) > 0);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    Check(fd >= 0 && fchown(fd, (uid_t)-1, getgid()) == 0 &&
        write(fd, "hello", 5) == 5 && close(fd) == 0);
    const char *sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    Check(ActualResourceAtV5(path, 5, sha, getuid(), getgid()));
    Check(!ActualResourceAtV5(path, 6, sha, getuid(), getgid()));
    Check(!ActualResourceAtV5(path, 5, "wrong", getuid(), getgid()));
    Check(!ActualResourceAtV5(path, 5, sha, getuid() + 1, getgid()));
    Check(chmod(path, 0644) == 0 && !ActualResourceAtV5(path, 5, sha, getuid(), getgid()));
    Check(chmod(path, 0600) == 0 && link(path, linkPath) == 0);
    Check(!ActualResourceAtV5(path, 5, sha, getuid(), getgid())); Check(unlink(linkPath) == 0);
    Check(symlink(path, linkPath) == 0 && !ActualResourceAtV5(linkPath, 5, sha, getuid(), getgid()));
    Check(unlink(linkPath) == 0 && unlink(path) == 0 && rmdir(dir) == 0);
    printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"nativeQueriesMocked\":true,\"realHostResourceFileChecks\":true,\"sandboxApplyCalls\":0,\"nativeVMOperations\":0,\"deviceOperations\":0}\n", Cases, Checks);
}
