#ifndef VM27_DISKIMAGES2_SECURITY_UNAVAILABLE_H
#define VM27_DISKIMAGES2_SECURITY_UNAVAILABLE_H

#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#include <stddef.h>
#include <stdint.h>

/* Desktop declarations are absent from iOS. Opaque tags, scalar widths and
 * authorization layouts below mirror the pinned MacOSX27 SDK. No opaque
 * object is manufactured, read, retained, released, or sent to a daemon. */
typedef int32_t VM27OSStatus;
typedef struct __SecKeychain *VM27KeychainRef;
typedef struct __SecKeychainItem *VM27KeychainItemRef;
typedef struct __SecTrustedApplication *VM27TrustedApplicationRef;
typedef struct __SecAccess *VM27AccessRef;
typedef const struct AuthorizationOpaqueRef *VM27AuthorizationRef;

#if TARGET_OS_OSX
#include <Security/Authorization.h>
#include <Security/AuthSession.h>
#include <Security/SecAccess.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecTrustedApplication.h>
typedef AuthorizationRights VM27AuthorizationRights;
typedef AuthorizationEnvironment VM27AuthorizationEnvironment;
typedef AuthorizationExternalForm VM27AuthorizationExternalForm;
#else
typedef struct {
    const char *name;
    size_t valueLength;
    void *value;
    uint32_t flags;
} VM27AuthorizationItem;
typedef struct {
    uint32_t count;
    VM27AuthorizationItem *items;
} VM27AuthorizationItemSet;
typedef VM27AuthorizationItemSet VM27AuthorizationRights;
typedef VM27AuthorizationItemSet VM27AuthorizationEnvironment;
typedef struct { char bytes[32]; } VM27AuthorizationExternalForm;
#endif

enum VM27DI2SecurityEntry {
    VM27DI2AuthorizationCreate,
    VM27DI2AuthorizationFree,
    VM27DI2AuthorizationMakeExternalForm,
    VM27DI2SessionGetInfo,
    VM27DI2SecAccessCreate,
    VM27DI2SecKeychainCopyDefault,
    VM27DI2SecKeychainGetPath,
    VM27DI2SecKeychainOpen,
    VM27DI2SecKeychainItemCopyKeychain,
    VM27DI2SecTrustedApplicationCreateFromPath,
    VM27DI2SecurityEntryCount
};

#if defined(__cplusplus)
extern "C" {
#endif
#define VM27_DI2_EXPORT __attribute__((visibility("default")))
VM27_DI2_EXPORT VM27OSStatus VM27AuthorizationCreate(
    const VM27AuthorizationRights *, const VM27AuthorizationEnvironment *,
    uint32_t, VM27AuthorizationRef *) __asm("_AuthorizationCreate");
VM27_DI2_EXPORT VM27OSStatus VM27AuthorizationFree(
    VM27AuthorizationRef, uint32_t) __asm("_AuthorizationFree");
VM27_DI2_EXPORT VM27OSStatus VM27AuthorizationMakeExternalForm(
    VM27AuthorizationRef, VM27AuthorizationExternalForm *)
    __asm("_AuthorizationMakeExternalForm");
VM27_DI2_EXPORT VM27OSStatus VM27SessionGetInfo(
    uint32_t, uint32_t *, uint32_t *) __asm("_SessionGetInfo");
VM27_DI2_EXPORT VM27OSStatus VM27SecAccessCreate(
    CFStringRef, CFArrayRef, VM27AccessRef *) __asm("_SecAccessCreate");
VM27_DI2_EXPORT VM27OSStatus VM27SecKeychainCopyDefault(
    VM27KeychainRef *) __asm("_SecKeychainCopyDefault");
VM27_DI2_EXPORT VM27OSStatus VM27SecKeychainGetPath(
    VM27KeychainRef, uint32_t *, char *) __asm("_SecKeychainGetPath");
VM27_DI2_EXPORT VM27OSStatus VM27SecKeychainOpen(
    const char *, VM27KeychainRef *) __asm("_SecKeychainOpen");
VM27_DI2_EXPORT VM27OSStatus VM27SecKeychainItemCopyKeychain(
    VM27KeychainItemRef, VM27KeychainRef *) __asm("_SecKeychainItemCopyKeychain");
VM27_DI2_EXPORT VM27OSStatus VM27SecTrustedApplicationCreateFromPath(
    const char *, VM27TrustedApplicationRef *)
    __asm("_SecTrustedApplicationCreateFromPath");
/* UINT64_MAX identifies an invalid entry index. Counters cannot be reset. */
VM27_DI2_EXPORT uint64_t VM27DI2SecurityCallCount(uint32_t);
#if defined(__cplusplus)
}
#endif
#endif
