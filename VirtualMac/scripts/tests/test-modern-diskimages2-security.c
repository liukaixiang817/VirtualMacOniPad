#include "modern_diskimages2_security_unavailable.h"
#include "di2-security-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic uint64_t Checks, Failures;
static void Check(int value) {
    atomic_fetch_add(&Checks, 1);
    if (!value) atomic_fetch_add(&Failures, 1);
}
static const char *Names[] = {
    "AuthorizationCreate", "AuthorizationFree", "AuthorizationMakeExternalForm",
    "SessionGetInfo", "SecAccessCreate", "SecKeychainCopyDefault", "SecKeychainGetPath",
    "SecKeychainOpen", "SecKeychainItemCopyKeychain", "SecTrustedApplicationCreateFromPath"
};
static const void *Entries[] = {
    (const void *)&VM27AuthorizationCreate, (const void *)&VM27AuthorizationFree,
    (const void *)&VM27AuthorizationMakeExternalForm, (const void *)&VM27SessionGetInfo,
    (const void *)&VM27SecAccessCreate, (const void *)&VM27SecKeychainCopyDefault,
    (const void *)&VM27SecKeychainGetPath, (const void *)&VM27SecKeychainOpen,
    (const void *)&VM27SecKeychainItemCopyKeychain,
    (const void *)&VM27SecTrustedApplicationCreateFromPath
};
static int Identity(void) {
    FILE *file = fopen(ProviderPath, "rb");
    if (!file) return 0;
    unsigned char buffer[8192], digest[32];
    CC_SHA256_CTX state; CC_SHA256_Init(&state); size_t total = 0, count;
    while ((count = fread(buffer, 1, sizeof(buffer), file))) {
        CC_SHA256_Update(&state, buffer, (CC_LONG)count); total += count;
    }
    int valid = !ferror(file) && !fclose(file) && total == ProviderBytes;
    CC_SHA256_Final(digest, &state);
    for (unsigned i = 0; i < 32; ++i) valid &= digest[i] == ProviderSHA[i];
    if (!valid) return 0;
    for (unsigned i = 0; i < VM27DI2SecurityEntryCount; ++i) {
        const void *raw = ptrauth_strip((void *)Entries[i], ptrauth_key_function_pointer);
        Dl_info info = {0}; char actual[4096], wanted[4096];
        if (!dladdr(raw, &info) || !info.dli_fbase || !info.dli_fname ||
            !realpath(info.dli_fname, actual) || !realpath(ProviderPath, wanted) ||
            strcmp(actual, wanted) || (uintptr_t)raw - (uintptr_t)info.dli_fbase != ProviderRVAs[i]) return 0;
        const struct mach_header_64 *header = info.dli_fbase;
        if (header->magic != MH_MAGIC_64 || header->filetype != MH_DYLIB ||
            header->ncmds > 128 || header->sizeofcmds > 16384) return 0;
        const unsigned char *at = (const unsigned char *)(header + 1);
        const unsigned char *end = at + header->sizeofcmds;
        unsigned uuids = 0;
        for (unsigned c = 0; c < header->ncmds; ++c) {
            if ((size_t)(end - at) < sizeof(struct load_command)) return 0;
            const struct load_command *command = (const void *)at;
            if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) return 0;
            if (command->cmd == LC_UUID) {
                if (command->cmdsize != sizeof(struct uuid_command) || memcmp(at + 8, ProviderUUID, 16)) return 0;
                ++uuids;
            }
            at += command->cmdsize;
        }
        if (at != end || uuids != 1 || VM27DI2SecurityCallCount(i)) return 0;
        printf("{\"record\":\"identity\",\"entry\":\"%s\",\"UUID\":\"%s\",\"path\":\"%s\",\"callsBefore\":0}\n",
            Names[i], ProviderUUIDString, actual);
    }
    return 1;
}
static void *Worker(void *unused) {
    (void)unused;
    for (unsigned loop = 0; loop < 64; ++loop) {
        VM27AuthorizationRef authorization = (VM27AuthorizationRef)(uintptr_t)1;
        Check(VM27AuthorizationCreate(NULL, NULL, UINT32_MAX, &authorization) == -60005);
        Check(!authorization);
        Check(VM27AuthorizationFree((VM27AuthorizationRef)(uintptr_t)1, UINT32_MAX) == -60002);
        struct { uint64_t before; VM27AuthorizationExternalForm form; uint64_t after; } external;
        memset(&external, 0xa5, sizeof(external));
        Check(VM27AuthorizationMakeExternalForm((VM27AuthorizationRef)(uintptr_t)1, &external.form) == -60009);
        unsigned char zero[32] = {0};
        Check(!memcmp(external.form.bytes, zero, sizeof(zero)));
        Check(external.before == UINT64_C(0xa5a5a5a5a5a5a5a5) && external.after == external.before);
        uint32_t session = UINT32_MAX, attributes = UINT32_MAX;
        Check(VM27SessionGetInfo(UINT32_MAX, &session, &attributes) == -60502);
        Check(!session && !attributes);
        VM27AccessRef access = (VM27AccessRef)(uintptr_t)1;
        Check(VM27SecAccessCreate(CFSTR("owned diagnostic"), NULL, &access) == -4);
        Check(!access);
        VM27KeychainRef keychain = (VM27KeychainRef)(uintptr_t)1;
        Check(VM27SecKeychainCopyDefault(&keychain) == -4);
        Check(!keychain);
        struct { char before; char path[8]; char after; } path;
        memset(&path, 0xa5, sizeof(path)); uint32_t capacity = sizeof(path.path);
        Check(VM27SecKeychainGetPath(NULL, &capacity, path.path) == -4);
        Check(!capacity && !path.path[0] && (unsigned char)path.before == 0xa5 && (unsigned char)path.after == 0xa5);
        Check((unsigned char)path.path[1] == 0xa5);
        keychain = (VM27KeychainRef)(uintptr_t)1;
        Check(VM27SecKeychainOpen("/no-file-opened-by-provider", &keychain) == -4);
        Check(!keychain);
        keychain = (VM27KeychainRef)(uintptr_t)1;
        Check(VM27SecKeychainItemCopyKeychain((VM27KeychainItemRef)(uintptr_t)1, &keychain) == -4);
        Check(!keychain);
        VM27TrustedApplicationRef application = (VM27TrustedApplicationRef)(uintptr_t)1;
        Check(VM27SecTrustedApplicationCreateFromPath(NULL, &application) == -4);
        Check(!application);
    }
    return NULL;
}
int main(void) {
    printf("{\"record\":\"start\",\"PID\":%d}\n", getpid());
    if (!Identity()) { puts("{\"record\":\"identityFailure\"}"); return 65; }
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; ++i) {
        if (pthread_create(&workers[i], NULL, Worker, NULL)) return 66;
    }
    for (unsigned i = 0; i < 4; ++i) Check(!pthread_join(workers[i], NULL));
    /* Invalid pointer tests use NULL or valid owned buffers, never unreadable
     * addresses. Incoming opaque sentinel handles are never dereferenced. */
    Check(VM27AuthorizationCreate(NULL, NULL, 0, NULL) == -60005);
    Check(VM27AuthorizationFree(NULL, 0) == -60002);
    Check(VM27AuthorizationMakeExternalForm(NULL, NULL) == -60004);
    Check(VM27SessionGetInfo(0, NULL, NULL) == -60502);
    Check(VM27SecAccessCreate(NULL, NULL, NULL) == -50);
    Check(VM27SecKeychainCopyDefault(NULL) == -50);
    char guarded = 'x'; uint32_t length = 0;
    Check(VM27SecKeychainGetPath(NULL, &length, &guarded) == -4 && !length && guarded == 'x');
    Check(VM27SecKeychainGetPath(NULL, NULL, &guarded) == -50 && guarded == 'x');
    Check(VM27SecKeychainOpen(NULL, NULL) == -50);
    Check(VM27SecKeychainItemCopyKeychain(NULL, NULL) == -50);
    Check(VM27SecTrustedApplicationCreateFromPath(NULL, NULL) == -50);
    Check(VM27DI2SecurityCallCount(UINT32_MAX) == UINT64_MAX);
    uint64_t calls = 0;
    for (unsigned i = 0; i < VM27DI2SecurityEntryCount; ++i) {
        uint64_t value = VM27DI2SecurityCallCount(i); calls += value;
        Check(value == 257 + (i == VM27DI2SecKeychainGetPath));
        printf("{\"record\":\"counter\",\"entry\":\"%s\",\"calls\":%llu}\n", Names[i], (unsigned long long)value);
    }
    printf("{\"record\":\"summary\",\"PID\":%d,\"checks\":%llu,\"failures\":%llu,\"providerCalls\":%llu,\"systemSecurityAPICalls\":0,\"frameworkAPICalls\":0,\"AuthorizationRefsCreated\":0,\"keychainObjectsCreated\":0,\"privilegedOperations\":0,\"passed\":%s}\n",
        getpid(), (unsigned long long)Checks, (unsigned long long)Failures,
        (unsigned long long)calls, Failures ? "false" : "true");
    return Failures ? 1 : 0;
}
