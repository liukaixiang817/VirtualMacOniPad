/* Original LWCR and system signature policy are not changed or interposed.
 * ABI source: Apple xnu-8792.41.9 bsd/sys/codesign.h + kern_proc.c.
 * CS_OPS_CDHASH is a read-only20-byte operation; the kernel checks both
 * token.val[5] pid and token.val[7] pidversion before copying its actual hash.
 */
#include "modern_xpc_approved_code.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/message.h>
#include <mach-o/loader.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);
#define MAX_CODE (8 * 1024 * 1024)
#define POLICY_MAGIC UINT64_C(0x564d323743445048)
struct VM27ApprovedCodePolicy {
    uint64_t magic;
    VM27LWCRPolicy *policy;
    char path[4096];
    struct stat file;
    VM27ApprovedCodeInfo info;
};
static _Atomic uint64_t gCreated, gDestroyed, gMessages, gAccepted, gRejected, gCodeQueries, gStatusQueries;
#define COUNT(value) atomic_fetch_add_explicit(&(value), 1, memory_order_relaxed)
static uint32_t BE(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void Hex(const unsigned char *p, size_t n, char *result) {
    for (size_t i = 0; i < n; ++i) snprintf(result + i * 2, 3, "%02x", p[i]);
}
static bool HexValid(const char *p, size_t n) {
    if (!p || strnlen(p, n + 1) != n) return false;
    for (size_t i = 0; i < n; ++i) if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}
static bool Nonzero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return true;
    return false;
}
int VM27ApprovedCodeInspectBytes(const unsigned char *data, size_t count, VM27ApprovedCodeInfo *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof(*result));
    if (!data || count < 32 || count > MAX_CODE) return EINVAL;
    struct mach_header_64 header; memcpy(&header, data, sizeof(header));
    if (header.magic != MH_MAGIC_64 || (uint32_t)header.cputype != 0x100000c || header.filetype != MH_EXECUTE ||
        !header.ncmds || header.ncmds > 256 || header.sizeofcmds > count - sizeof(header)) return ENOTSUP;
    size_t at = 32, end = at + header.sizeofcmds, signatureAt = 0, signatureSize = 0;
    unsigned uuids = 0, signatures = 0;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        struct load_command command;
        if (at > end || end - at < 8) return EINVAL;
        memcpy(&command, data + at, 8);
        if (command.cmdsize < 8 || command.cmdsize & 7 || command.cmdsize > end - at) return EINVAL;
        if (command.cmd == LC_UUID) {
            if (command.cmdsize != 24) return EINVAL;
            ++uuids; Hex(data + at + 8, 16, result->UUID);
        } else if (command.cmd == LC_CODE_SIGNATURE) {
            if (command.cmdsize != 16) return EINVAL;
            struct linkedit_data_command c; memcpy(&c, data + at, sizeof(c));
            signatureAt = c.dataoff; signatureSize = c.datasize; ++signatures;
        }
        at += command.cmdsize;
    }
    if (at != end || uuids != 1 || signatures != 1 || signatureAt < end || signatureAt > count ||
        signatureSize < 12 || signatureSize > count - signatureAt) return EINVAL;
    const unsigned char *signature = data + signatureAt;
    if (BE(signature) != 0xfade0cc0) return EINVAL;
    uint32_t length = BE(signature + 4), blobs = BE(signature + 8);
    if (length < 12 || length > signatureSize || blobs > 16 || blobs > (length - 12) / 8) return EINVAL;
    const unsigned char *cd = NULL, *xml = NULL;
    uint32_t cdSize = 0, xmlSize = 0;
    uint32_t types[16] = {0}, offsets[16] = {0}, sizes[16] = {0};
    for (unsigned i = 0; i < blobs; ++i) {
        uint32_t type = BE(signature + 12 + i * 8), start = BE(signature + 16 + i * 8);
        if (start < 12 + 8 * blobs || start > length || length - start < 8) return EINVAL;
        uint32_t size = BE(signature + start + 4);
        if (size < 8 || size > length - start) return EINVAL;
        for (unsigned j = 0; j < i; ++j) if (types[j] == type || (start < offsets[j] + sizes[j] && offsets[j] < start + size)) return EINVAL;
        types[i] = type; offsets[i] = start; sizes[i] = size;
        uint32_t magic = BE(signature + start);
        if (type == 0) { if (magic != 0xfade0c02) return EINVAL; cd = signature + start; cdSize = size; }
        else if (type == 2) { if (magic != 0xfade0c01) return EINVAL; }
        else if (type == 5) { if (magic != 0xfade7171) return EINVAL; xml = signature + start; xmlSize = size; }
        else if (type == 7) { if (magic != 0xfade7172) return EINVAL; }
        else if (type == 0x10000) { if (magic != 0xfade0b01 || size != 8) return ENOTSUP; }
        else return ENOTSUP;
    }
    if (!cd || cdSize < 88 || BE(cd + 8) != 0x20400 || BE(cd + 12) != 2 ||
        cd[36] != 32 || cd[37] != 2 || cd[38] != 0 || (cd[39] != 12 && cd[39] != 14) ||
        BE(cd + 40) || BE(cd + 44) || BE(cd + 48) || BE(cd + 52) ||
        Nonzero(cd + 56, 8)) return ENOTSUP;
    uint32_t hashAt = BE(cd + 16), identifier = BE(cd + 20), special = BE(cd + 24), pages = BE(cd + 28), limit = BE(cd + 32);
    if (special > 7 || hashAt > cdSize || hashAt < 88 + special * 32 ||
        pages > (cdSize - hashAt) / 32 || identifier < 88 || identifier >= hashAt - special * 32 ||
        !memchr(cd + identifier, 0, hashAt - special * 32 - identifier) || !limit || limit != signatureAt) return EINVAL;
    size_t page = (size_t)1 << cd[39];
    if ((limit + page - 1) / page != pages) return EINVAL;
    unsigned char digest[32];
    for (unsigned i = 0; i < pages; ++i) {
        size_t begin = (size_t)i * page, bytes = limit - begin;
        if (bytes > page) bytes = page;
        CC_SHA256(data + begin, (CC_LONG)bytes, digest);
        if (memcmp(digest, cd + hashAt + i * 32, 32)) return EBADMSG;
    }
    for (unsigned slot = 1; slot <= special; ++slot) {
        const unsigned char *claimed = cd + hashAt - slot * 32;
        const unsigned char *blob = NULL; uint32_t size = 0;
        if (slot == 2 || slot == 5 || slot == 7) {
            for (unsigned i = 0; i < blobs; ++i) if (types[i] == slot) { blob = signature + offsets[i]; size = sizes[i]; }
        }
        if (blob) {
            CC_SHA256(blob, size, digest);
            if (memcmp(digest, claimed, 32)) return EBADMSG;
        } else if (Nonzero(claimed, 32)) return ENOTSUP;
    }
    for (unsigned i = 0; i < blobs; ++i) if ((types[i] == 2 || types[i] == 5 || types[i] == 7) && types[i] > special) return EINVAL;
    if (xml) {
        CFDataRef bytes = CFDataCreate(NULL, xml + 8, (CFIndex)xmlSize - 8);
        if (!bytes) return ENOMEM;
        CFErrorRef error = NULL;
        CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, bytes, kCFPropertyListImmutable, NULL, &error);
        CFRelease(bytes); if (error) CFRelease(error);
        if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) { if (plist) CFRelease(plist); return EINVAL; }
        CFTypeRef value = CFDictionaryGetValue((CFDictionaryRef)plist, CFSTR(VM27_PLUGIN_ENTITLEMENT));
        result->pluginPresent = value != NULL;
        result->pluginIsBoolean = value && CFGetTypeID(value) == CFBooleanGetTypeID();
        result->pluginValue = result->pluginIsBoolean && CFBooleanGetValue((CFBooleanRef)value);
        CFRelease(plist);
    }
    CC_SHA256(cd, cdSize, digest); Hex(digest, 20, result->CDHash);
    CC_SHA256(data, (CC_LONG)count, digest); Hex(digest, 32, result->fileSHA256);
    result->bytes = count; result->codePages = pages;
    result->pagesVerified = result->embeddedSlotsVerified = true;
    return 0;
}
static int ReadOwned(const char *path, unsigned char **result, size_t *bytes, struct stat *state) {
    *result = NULL; *bytes = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    struct stat after;
    if (fstat(fd, state) || state->st_uid != geteuid() || !S_ISREG(state->st_mode) ||
        state->st_nlink != 1 || (state->st_mode & 0022) || !(state->st_mode & S_IXUSR) ||
        state->st_size <= 0 || state->st_size > MAX_CODE) { close(fd); return EACCES; }
    unsigned char *data = malloc((size_t)state->st_size);
    if (!data) { close(fd); return ENOMEM; }
    size_t at = 0;
    while (at < (size_t)state->st_size) {
        ssize_t n = read(fd, data + at, (size_t)state->st_size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(data); close(fd); return EIO; }
        at += (size_t)n;
    }
    bool stable = !fstat(fd, &after) && state->st_dev == after.st_dev && state->st_ino == after.st_ino &&
        state->st_size == after.st_size && state->st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
        state->st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
    close(fd);
    if (!stable) { free(data); return ESTALE; }
    *result = data; *bytes = at; return 0;
}
int VM27ApprovedCodePolicyCreate(const char *path, const char *expectedSHA, const char *expectedCD,
                                xpc_object_t requirement, VM27ApprovedCodePolicy **result) {
    if (!result) return EINVAL;
    *result = NULL;
    if (!path || path[0] != '/' || strnlen(path, 4096) >= 4096 || !HexValid(expectedSHA, 64) || !HexValid(expectedCD, 40)) return EINVAL;
    VM27LWCRPolicy *policy = NULL;
    int status = VM27LWCRPolicyCreate(requirement, &policy);
    if (status) return status;
    VM27ApprovedCodePolicy *created = calloc(1, sizeof(*created));
    if (!created) { VM27LWCRPolicyRelease(policy); return ENOMEM; }
    unsigned char *data = NULL; size_t bytes = 0;
    status = ReadOwned(path, &data, &bytes, &created->file);
    if (!status) status = VM27ApprovedCodeInspectBytes(data, bytes, &created->info);
    free(data);
    if (!status && (strcmp(expectedSHA, created->info.fileSHA256) || strcmp(expectedCD, created->info.CDHash) ||
        !created->info.pluginIsBoolean || !created->info.pluginValue)) status = EACCES;
    if (status) { VM27LWCRPolicyRelease(policy); free(created); return status; }
    created->magic = POLICY_MAGIC; created->policy = policy; strcpy(created->path, path);
    COUNT(gCreated); *result = created; return 0;
}
void VM27ApprovedCodePolicyRelease(VM27ApprovedCodePolicy *policy) {
    if (!policy || policy->magic != POLICY_MAGIC) abort();
    policy->magic = 0; VM27LWCRPolicyRelease(policy->policy); COUNT(gDestroyed); free(policy);
}
int VM27ApprovedCodeCheckReceivedMessage(const VM27ApprovedCodePolicy *policy, xpc_object_t message,
                                        VM27ApprovedCodeMessageResult *result) {
    COUNT(gMessages); VM27ApprovedCodeMessageResult detail = {0}; detail.result = EACCES;
    if (!policy || policy->magic != POLICY_MAGIC) { detail.result = EINVAL; goto done; }
    if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY || !xpc_dictionary_get_remote_connection(message)) goto done;
    unsigned char *data = NULL, digest[32]; size_t bytes = 0; struct stat state;
    int status = ReadOwned(policy->path, &data, &bytes, &state);
    if (status) { detail.result = status; goto done; }
    CC_SHA256(data, (CC_LONG)bytes, digest); free(data); char hex[65] = {0}; Hex(digest, 32, hex);
    detail.filePinMatched = bytes == policy->info.bytes && state.st_dev == policy->file.st_dev &&
        state.st_ino == policy->file.st_ino && state.st_mode == policy->file.st_mode && !strcmp(hex, policy->info.fileSHA256);
    if (!detail.filePinMatched) { detail.result = ESTALE; goto done; }
    /* Original strict result is recorded; its implementation is unchanged. */
    (void)VM27LWCRPolicyCheckReceivedMessage(policy->policy, message, &detail.nativePolicy);
    audit_token_t token = {{0}}; xpc_dictionary_get_audit_token(message, &token);
    detail.auditPID = token.val[5]; detail.auditPIDVersion = token.val[7];
    detail.auditTokenPresent = detail.auditPID > 1 && detail.auditPID <= INT32_MAX && detail.auditPIDVersion != 0;
    if (!detail.auditTokenPresent) goto done;
    unsigned char cdhash[20] = {0}; COUNT(gCodeQueries);
    if (csops_audittoken((pid_t)detail.auditPID, 5, cdhash, sizeof(cdhash), &token)) detail.codeQueryError = errno;
    if (detail.codeQueryError) goto done;
    Hex(cdhash, 20, detail.kernelCDHash);
    detail.codeHashMatched = !strcmp(detail.kernelCDHash, policy->info.CDHash);
    COUNT(gStatusQueries);
    if (csops_audittoken((pid_t)detail.auditPID, 0, &detail.codeStatus, sizeof(detail.codeStatus), &token)) detail.statusQueryError = errno;
    detail.dynamicCodeValid = !detail.statusQueryError && (detail.codeStatus & 1) != 0;
    if (detail.codeHashMatched && detail.dynamicCodeValid && detail.nativePolicy.hasRemoteConnection &&
        detail.nativePolicy.taskCreated && !detail.nativePolicy.entitlementReadError &&
        detail.nativePolicy.entitlementIsBoolean && detail.nativePolicy.entitlementValue) {
        detail.explicitApprovedCodeAccepted = true; detail.result = 0;
    }
done:
    if (detail.result == 0) COUNT(gAccepted); else COUNT(gRejected);
    if (result) *result = detail;
    return detail.result;
}
void VM27ApprovedCodeCopyStats(VM27ApprovedCodeStats *result) {
    if (!result) return;
#define LOAD(field, value) result->field = atomic_load_explicit(&(value), memory_order_relaxed)
    LOAD(created, gCreated); LOAD(destroyed, gDestroyed); LOAD(messageChecks, gMessages);
    LOAD(accepted, gAccepted); LOAD(rejected, gRejected);
    LOAD(codeQueries, gCodeQueries); LOAD(statusQueries, gStatusQueries);
#undef LOAD
}
