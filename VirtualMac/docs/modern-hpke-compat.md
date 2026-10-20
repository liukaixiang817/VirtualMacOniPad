# Private HPKE compatibility module

`vz/host/modern_hpke_compat` contains the HPKE implementation from Apple's
[Swift Crypto 3.0.0](https://github.com/apple/swift-crypto/tree/3.0.0), commit
`629f0b679d0fd0a6ae823d7f750b9ab032c00b80`. Original notices, license and
contributors are retained. `upstream-manifest.json` records original and
adapted file hashes and the precise transformations.

This creates a new private `VM27HPKE` nominal context. It uses existing native
CryptoKit P256/P384/P521/Curve25519 keys, SharedSecret, HKDF and AEAD operations.
The DiffieHellman protocol prefix is retained; its native SharedSecret storage
is used instead of copying another key/secret representation. The other
changes import native primitives and qualify the private KEM result and KDF
helper. No cryptographic algorithm is replaced by an unconditional result.

Fourteen symbols required by genuine macOS 27 DiskImages2 are aliases to real
compiler-generated functions, metadata and witness tables. Two additional
conformance descriptor aliases support the original Apple SDK generic caller.
P256 objects and seven existing DI2 P256 symbols remain from native CryptoKit.
The private descriptors retain the `VM27HPKE` context name. This is a scoped
compatibility contract, not Apple's original CryptoKit 27 binary or its UUID.
Do not exchange private HPKE values or protocol existentials with an unrelated
native HPKE context merely because their layouts match.

Build with `scripts/development/build-modern-hpke-compat.py --output NEW_DIR`.
The builder only creates a local new output directory. Its library is not
automatically signed, deployed or admitted to a VM runtime.

## Evidence and remaining gates

Under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm`:

- `hpke-source-functional-mac-v1` recorded 1121 actual checks, two directions
  of interoperability with genuine native CryptoKit 27, and 257 Apple known
  answer decryptions. This tested the natural private module.
- `hpke-original-sdk-fixture-build-v5` imports only original Apple SDK
  declarations. Mac PID 71940 exited 0 after 512 checks, 64 real authentication
  failure throws, 23 exact entry identities and six metadata/layout checks.
  Generic initialization, sealing, opening, copy and destruction use the real
  typed alias route and retain pointer authentication.
- The iOS caller's twelve functions/accessors/conformance descriptors are
  strong imports from the private provider. LLVM linkage changes only the
  exact private symbols from `extern_weak` to `external`; instructions and
  calling conventions remain identical. Original DI2 imports are untouched by
  this standalone test.
- `hpke-system-inventory-native-v1` recorded iPad PID 38867, exit 0 and external
  process absence. All 187 provider imports exist under their exact owners;
  the fourteen original DI2 HPKE symbols are absent. This is symbol presence
  evidence with zero crypto or metadata accessor calls.
- `hpke-original-sdk-independent-review-v1` pins 147 files and rejects eight
  malformed saved receipts. Its strict validator is
  `scripts/tests/validate-modern-hpke-original-sdk.py`.
- `hpke-original-sdk-native-v1` recorded actual iPad PID 39993, exit 0 and
  external process absence: 512 checks, 64 real authentication failure throws,
  23 exact entry identities and six metadata/layout checks. P256 types are
  from old native CryptoKit UUID `63c2cd6b57b93d7a92cca3fda099451e`; HPKE types
  are from the private module below. `hpke-native-independent-review-v1`
  independently validates the complete transcript and all 147 unchanged pins.

The final iOS library is UUID `af63a8db64443dc29da7ab5274b6fd12`, and has no
entitlements. Only the independent caller has the four previously authorized
probe entitlements: platform, private no-container, private no-sandbox and
private can-execute-cdhash. This proves the scoped original SDK crypto caller
on iPad. It does not prove genuine DI2 load/open/write or a complete macOS 27 VM.
