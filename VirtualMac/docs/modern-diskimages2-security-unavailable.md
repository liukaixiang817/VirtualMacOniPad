# DiskImages2 desktop Security availability

`vz/host/modern_diskimages2_security_unavailable.{h,c}` provides ten exact
desktop Security imports for a private DiskImages2 compatibility layer.
The declarations and error constants are pinned to the MacOSX27.0 SDK, and
Mac compilation verifies all ten function-pointer types against those headers.
The iOS build retains their LP64 opaque tags and authorization layouts.

Every call reports a real failure. The provider issues no AuthorizationRef,
keychain, trusted-application or access object, calls no system Security API,
contacts no daemon, and performs no privilege operation. A failed call clears
its owned output parameters. It provides ten atomic counters with no reset API
so a later genuine RAW/ASIF fixture can establish whether these desktop paths
were reached.

| Import group | Result for valid arguments |
| --- | --- |
| AuthorizationCreate | `errAuthorizationDenied` (-60005), null output |
| AuthorizationFree | `errAuthorizationInvalidRef` (-60002); this provider issued no references |
| AuthorizationMakeExternalForm | `errAuthorizationExternalizeNotAllowed` (-60009), zeroed 32-byte form |
| SessionGetInfo | `errSessionAuthorizationDenied` (-60502), zero session ID and attributes |
| Six desktop keychain/access APIs | `errSecUnimplemented` (-4), no CF output object |

Mandatory invalid output arguments return the corresponding SDK invalid
pointer/parameter error. In particular, `SecKeychainCopyDefault` does not return
`errSecNoDefaultKeychain`: the genuine DI2 consumer treats that code as a
special success path. No GUI-session bits or external authorization token are
invented. `AuthorizationFree` does not free arbitrary opaque memory.

The frozen candidate is
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-security-unavailable-build-v1`.
`scripts/development/build-modern-diskimages2-security.py` builds the independent
provider and strong two-level typed probe. Actual Mac execution, PID56584,
wait0/reaped, passed 5,402 checks with 2,571 provider calls, four joined threads,
ten runtime UUID/path/RVA identities, guarded outputs and exact counters.
Root's actual iPad receipt is `di2-security-unavailable-native-v1`, parent PID
37155, observed wait0 and externally absent. It also passes 5,402 checks with
2,571 private provider calls and all ten actual UUID/path/counter identities;
there are zero system Security or DI2 calls and no authorization/keychain
objects. Root's independent validator rejects fifteen malformed Mac receipts.
Only the probe has the four previously authorized scoped
platform/no-container/private-no-sandbox/can-execute-cdhash entitlements.

The probe reads its own provider file for identity; it does not access a guest
disk or call DI2. This independent unavailable-provider result does not prove
DI2 error propagation, plaintext RAW/ASIF disk IO or the complete loader closure.
Nine private quarantine imports remain outside this module; uncertain nominal
return types are not guessed. The old InternetSharing authorization shim's
success/null behavior is not suitable for these DI2 paths.
