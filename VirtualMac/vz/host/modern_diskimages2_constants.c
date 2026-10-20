// Eight CFString data symbols missing on the old iOS host. Their exact types
// are declared by SDK27 Security/CFNetwork; values were read from the genuine
// macOS27 providers by the owned read-only di2-macos-constant-contract-v1 probe.
// This library provides data only. It never authorizes access, changes a
// keychain or opens a network connection. Bind only reviewed private consumers.
#include <CoreFoundation/CoreFoundation.h>
#define VM27_STRING(variable, symbol, value) \
    __attribute__((visibility("default"))) const CFStringRef variable \
    __asm("_" symbol) = CFSTR(value)
VM27_STRING(VM27HTTPSProxyEnable, "kCFNetworkProxiesHTTPSEnable", "HTTPSEnable");
VM27_STRING(VM27HTTPSProxyPort, "kCFNetworkProxiesHTTPSPort", "HTTPSPort");
VM27_STRING(VM27HTTPSProxyHost, "kCFNetworkProxiesHTTPSProxy", "HTTPSProxy");
VM27_STRING(VM27SecurityAccessKey, "kSecAttrAccess", "acls");
VM27_STRING(VM27SecurityCommonNameOID, "kSecOIDCommonName", "2.5.4.3");
VM27_STRING(VM27SecurityCountryOID, "kSecOIDCountryName", "2.5.4.6");
VM27_STRING(VM27SecurityOrganizationOID, "kSecOIDOrganizationName", "2.5.4.10");
VM27_STRING(VM27SecurityKeychainKey, "kSecUseKeychain", "u_Keychain");
#undef VM27_STRING
