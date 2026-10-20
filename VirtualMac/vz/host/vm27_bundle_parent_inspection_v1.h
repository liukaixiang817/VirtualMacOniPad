#ifndef VM27_BUNDLE_PARENT_INSPECTION_V1_H
#define VM27_BUNDLE_PARENT_INSPECTION_V1_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* One canonical absolute flat .app path. No symlink, dot component or
     * writable ancestor is accepted. Every string is borrowed and must remain
     * valid and unmodified for the entire synchronous call. */
    const char *bundlePath;
    const char *executableName;
    const char *reviewedExecutableSHA256;
    const char *reviewedExecutableCDHash;
    /* Exact owner of the bundle, executable, Info.plist, signature directory
     * and CodeResources. Ancestors must belong to this owner or root. */
    uid_t expectedOwnerUID;
} VM27BundleParentConfigurationV1;

typedef struct {
    uint32_t formatVersion;
    uid_t actualOwnerUID;
    char executableSHA256[65], executableCDHash[41], executableUUID[33];
    char infoPlistSHA256[65], codeResourcesSHA256[65];
    uint64_t executableBytes, infoPlistBytes, codeResourcesBytes;
    uint32_t codePages;
    bool codePagesVerified, embeddedSlotsVerified;
    bool externalInfoSlotVerified, externalResourcesSlotVerified;
    bool descriptorsAndNamesStable, infoExecutableNameMatched;
    bool codeResourcesIsDictionary;
    /* Signed XML declarations only; not a native entitlement query. */
    bool signedPluginPresent, signedPluginIsBoolean, signedPluginValue;
    /* These remain false. Hashing CodeResources authenticates the seal's
     * metadata, without walking or validating the resources described by it.
     * No Security/XPC/kernel trust or execution API is called by this module. */
    bool wholeBundleResourcesValidated;
    bool appleSecurityChainValidated;
    bool nativeBooleanValidated;
} VM27BundleParentInspectionV1;

/* Independent read-only data inspection; not an execution/trust decision.
 * Flat .app only, thin arm64 MH_EXECUTE, ad-hoc SHA256 CodeDirectory 0x20400,
 * code <= 2 MiB, Info.plist <= 64 KiB, CodeResources <= 1 MiB.
 * Verifies every signed code page, embedded slots 2/5/7, and REQUIRED real
 * external slots 1/3. Other nonzero special slots and unknown blob types fail.
 * All three files must be regular, single-link, exactly owned and not group/
 * other writable. It reads source bytes; executable mode is not asserted.
 * Bounded O_NONBLOCK/O_NOFOLLOW FD reads and final name/metadata checks reject
 * symlinks, FIFOs, replacement and mutation. Output is all zero on any failure.
 * Existing ApprovedCode/V8/large providers remain unchanged and are not called.
 */
int VM27BundleParentInspectV1(const VM27BundleParentConfigurationV1 *,
                            VM27BundleParentInspectionV1 *result);

#ifdef __cplusplus
}
#endif
#endif
