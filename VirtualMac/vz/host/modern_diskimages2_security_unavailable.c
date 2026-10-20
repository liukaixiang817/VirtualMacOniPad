#include "modern_diskimages2_security_unavailable.h"
#include <stdatomic.h>
#include <string.h>

enum {
    VM27Unimplemented = -4,
    VM27InvalidParameter = -50,
    VM27InvalidAuthorizationRef = -60002,
    VM27InvalidAuthorizationPointer = -60004,
    VM27AuthorizationDenied = -60005,
    VM27ExternalizeNotAllowed = -60009,
    VM27SessionAuthorizationDenied = -60502
};
_Static_assert(sizeof(VM27OSStatus) == 4, "OSStatus must be signed 32-bit");
_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8, "LP64 ABI required");
_Static_assert(sizeof(VM27AuthorizationExternalForm) == 32, "SDK external form");
#if TARGET_OS_OSX
#define VM27_SDK_TYPE(ours, sdk) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(ours)), \
        __typeof__(&(sdk))), "SDK function type: " #sdk)
VM27_SDK_TYPE(VM27AuthorizationCreate, AuthorizationCreate);
VM27_SDK_TYPE(VM27AuthorizationFree, AuthorizationFree);
VM27_SDK_TYPE(VM27AuthorizationMakeExternalForm, AuthorizationMakeExternalForm);
VM27_SDK_TYPE(VM27SessionGetInfo, SessionGetInfo);
VM27_SDK_TYPE(VM27SecAccessCreate, SecAccessCreate);
VM27_SDK_TYPE(VM27SecKeychainCopyDefault, SecKeychainCopyDefault);
VM27_SDK_TYPE(VM27SecKeychainGetPath, SecKeychainGetPath);
VM27_SDK_TYPE(VM27SecKeychainOpen, SecKeychainOpen);
VM27_SDK_TYPE(VM27SecKeychainItemCopyKeychain, SecKeychainItemCopyKeychain);
VM27_SDK_TYPE(VM27SecTrustedApplicationCreateFromPath, SecTrustedApplicationCreateFromPath);
_Static_assert(VM27Unimplemented == errSecUnimplemented &&
    VM27InvalidParameter == errSecParam &&
    VM27InvalidAuthorizationRef == errAuthorizationInvalidRef &&
    VM27InvalidAuthorizationPointer == errAuthorizationInvalidPointer &&
    VM27AuthorizationDenied == errAuthorizationDenied &&
    VM27ExternalizeNotAllowed == errAuthorizationExternalizeNotAllowed &&
    VM27SessionAuthorizationDenied == errSessionAuthorizationDenied,
    "Pinned public SDK error constants");
#else
_Static_assert(sizeof(VM27AuthorizationItem) == 32 &&
    offsetof(VM27AuthorizationItem, valueLength) == 8 &&
    offsetof(VM27AuthorizationItem, value) == 16 &&
    offsetof(VM27AuthorizationItem, flags) == 24, "SDK LP64 authorization item");
_Static_assert(sizeof(VM27AuthorizationItemSet) == 16 &&
    offsetof(VM27AuthorizationItemSet, items) == 8, "SDK LP64 authorization set");
#endif
static _Atomic uint64_t Calls[VM27DI2SecurityEntryCount];
static void Called(enum VM27DI2SecurityEntry entry) {
    atomic_fetch_add_explicit(&Calls[entry], 1, memory_order_relaxed);
}
uint64_t VM27DI2SecurityCallCount(uint32_t entry) {
    return entry < VM27DI2SecurityEntryCount ?
        atomic_load_explicit(&Calls[entry], memory_order_relaxed) : UINT64_MAX;
}

VM27OSStatus VM27AuthorizationCreate(const VM27AuthorizationRights *rights,
    const VM27AuthorizationEnvironment *environment, uint32_t flags,
    VM27AuthorizationRef *authorization) {
    Called(VM27DI2AuthorizationCreate);
    (void)rights; (void)environment; (void)flags;
    if (authorization) *authorization = NULL;
    return VM27AuthorizationDenied;
}
VM27OSStatus VM27AuthorizationFree(VM27AuthorizationRef authorization, uint32_t flags) {
    Called(VM27DI2AuthorizationFree);
    (void)authorization; (void)flags;
    /* This provider issues no references, so every reference is unknown. */
    return VM27InvalidAuthorizationRef;
}
VM27OSStatus VM27AuthorizationMakeExternalForm(VM27AuthorizationRef authorization,
    VM27AuthorizationExternalForm *form) {
    Called(VM27DI2AuthorizationMakeExternalForm); (void)authorization;
    if (!form) return VM27InvalidAuthorizationPointer;
    memset(form, 0, sizeof(*form));
    return VM27ExternalizeNotAllowed;
}
VM27OSStatus VM27SessionGetInfo(uint32_t session, uint32_t *sessionID,
    uint32_t *attributes) {
    Called(VM27DI2SessionGetInfo); (void)session;
    if (sessionID) *sessionID = 0;
    if (attributes) *attributes = 0;
    return VM27SessionAuthorizationDenied;
}
VM27OSStatus VM27SecAccessCreate(CFStringRef descriptor, CFArrayRef trusted,
    VM27AccessRef *access) {
    Called(VM27DI2SecAccessCreate); (void)trusted;
    if (access) *access = NULL;
    return descriptor && access ? VM27Unimplemented : VM27InvalidParameter;
}
VM27OSStatus VM27SecKeychainCopyDefault(VM27KeychainRef *keychain) {
    Called(VM27DI2SecKeychainCopyDefault);
    if (keychain) *keychain = NULL;
    /* Do not use errSecNoDefaultKeychain: DI2 treats it as a success path. */
    return keychain ? VM27Unimplemented : VM27InvalidParameter;
}
VM27OSStatus VM27SecKeychainGetPath(VM27KeychainRef keychain,
    uint32_t *length, char *path) {
    Called(VM27DI2SecKeychainGetPath); (void)keychain;
    if (!length) return VM27InvalidParameter;
    uint32_t capacity = *length;
    *length = 0;
    if (path && capacity) path[0] = '\0';
    return VM27Unimplemented;
}
VM27OSStatus VM27SecKeychainOpen(const char *path, VM27KeychainRef *keychain) {
    Called(VM27DI2SecKeychainOpen);
    if (keychain) *keychain = NULL;
    return path && keychain ? VM27Unimplemented : VM27InvalidParameter;
}
VM27OSStatus VM27SecKeychainItemCopyKeychain(VM27KeychainItemRef item,
    VM27KeychainRef *keychain) {
    Called(VM27DI2SecKeychainItemCopyKeychain);
    if (keychain) *keychain = NULL;
    return item && keychain ? VM27Unimplemented : VM27InvalidParameter;
}
VM27OSStatus VM27SecTrustedApplicationCreateFromPath(const char *path,
    VM27TrustedApplicationRef *application) {
    Called(VM27DI2SecTrustedApplicationCreateFromPath); (void)path;
    if (application) *application = NULL;
    /* A NULL path names the current application in the official API. */
    return application ? VM27Unimplemented : VM27InvalidParameter;
}
