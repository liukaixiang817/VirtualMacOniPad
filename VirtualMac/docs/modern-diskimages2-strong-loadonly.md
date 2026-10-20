# Genuine macOS 27 DiskImages2 strong load-only candidate

`scripts/development/build-modern-diskimages2-strong-loadonly.py` prepares an app-private genuine DiskImages2 candidate. It retains UUID `a456d4a4d6ab3549965d0400f3552de3` and every code/data section byte from the reconstructed image with the five corrected RTTI imports. It does not return old DI2 classes or emulate disk-image success.

The current frozen build is `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimages2-strong-loadonly-build-v3`. Its manifest SHA-256 is `3ea4e655da484fa0853cc5752f38fe64072b169e97193755b875ae7e84ed4daf`. Build-v1 is incomplete: the original standalone Swift lookup install ID required an explicit route in the new consumer. Build-v2 remains frozen; build-v3 changes only the probe to flush complete stdout lines before potentially failing in the loader.

## Exact binding policy

The 818 chained imports use Apple's addend format 2. There are 770 strong imports and 48 weak imports restored from the exact original nlist contracts. Every ordinal is positive. The newly reconstructed 21 CryptoKit optimization rows remain strong because a weak dependency command alone does not establish that an individual optimized binding was weak.

The five misnamed RTTI destructor imports are corrected to real libc++abi vtable exports plus their 16-byte address-point addends. Their positive owner remains `/usr/lib/libc++abi.dylib`. All 1,189 original RTTI data-pointer PAC words remain unchanged with the original DA0 contract. No destructor implementation or fabricated RTTI object is supplied.

The 31 existing dependency commands remain present with their original load/re-export/weak attributes. Their Mac framework paths are flattened for iOS. Shorter path commands and a private install ID free header space without moving a section, code VA, or data pointer. One new strong dependency, ordinal 32, loads `@loader_path/VM27DI2Compat.dylib`.

That independent compatibility umbrella re-exports six precise private providers for 45 missing imports:

| Imports | Provider |
| --- | --- |
| 13 C++ APIs | `VM27CxxABICompat.dylib`, with all three frozen runtime dependencies retained |
| 4 typed allocator APIs | `VM27DiskAllocatorProvider.dylib` |
| 8 exact CFString globals | `VM27DiskImageConstants.dylib` |
| 10 unsupported desktop Security APIs | `VM27DI2SecurityUnavailable.dylib`, which returns explicit failures |
| 9 quarantine APIs | Genuine UUID `7fd4ae2286ef382b83f5adf9336c1160` in `Libquarantine27.dylib` |
| 1 mangled-name lookup | `VM27SwiftLookup.dylib`, previously tested within its finite fixture scope |

All nine provider files are copied byte for byte from their earlier frozen candidates. The lookup provider retains its original standalone install ID. Only the new umbrella's exact re-export route changes to `@loader_path/VM27SwiftLookup.dylib`, and the probe requires its actual private UUID and canonical path. This is an explicit compatibility routing contract, not preservation of the original Mac provider ordinals.

The 679 native symbol-presence results do not prove every original consumer ABI or service behavior. Added optimized import routes likewise require actual native loading and functional testing. In particular, successfully loading the unavailable Security provider does not establish authorization, keychain, or DI2 plaintext-disk support.

## Probe and independent validation

`vz/host/modern_diskimages2_loadonly_probe.c` accepts only `--load-only`. It rejects any already loaded DiskImages2 image before mapping the candidate, checks all 11 library files by size/SHA-256, and preserves flushed start/error output. A failed genuine DI2 `dlopen` exits 67 and records the actual `dlerror` on stderr.

Only after genuine DI2 loading does it inspect the 45 private export UUID/path identities, five class identities and global class-registration agreement, and eight original method encodings/IMP RVAs. It invokes no DI2 method, disk-image API, quarantine API, VM, or GPU operation. Dropping loader references does not claim to unload registered Objective-C classes; child process exit is the lifecycle boundary. External child absence and the observed wait status must be recorded by the native runner.

The probe has only the previously authorized platform/no-container/private-no-sandbox/can-execute-cdhash entitlements. All libraries have no entitlements. The frozen probe expects `/var/root/VirtualMac2/testing/diskimages227-strong-loadonly-v1`; its generated header pins this exact layout.

The independent entry point is `scripts/tests/validate-modern-diskimages2-strong-loadonly.py`, with `--candidate-json`, `--expected-candidate-sha256`, and a new `--output` directory. It independently parses the signed Mach-O import table and load commands, checks every original section and dependency, verifies all twelve signatures, CDHashes, dyld validation and exact entitlements, and rejects six corrupted ordinal/addend/code/UUID/dependency fixtures. It performs no `dlopen` or device operation.

The first independent result is `diskimages2-strong-loadonly-independent-review-v1/verification.json`. Its consumer plan contains all twelve file names, byte sizes, SHA-256 values, CDHashes and entitlements. The plan SHA-256 is `517f76f6a2ce41733ff1c026b0111131cd83038e54c38db90232e9aa6d4fc457`; the 25-file freeze SHA-256 is `4c0b37d1ce8c9ad576a257d3127b14ff20368d137c059131fc173c0aecb993b7`.

## Next functional acceptance step

Original static evidence is in `di2-raw-open-contract-v4`. A disposable unencrypted RAW file can be opened through `DIOpenParams initWithURL:openMode:error:`, then `openWithError:`, then `DIImageHandle fileDescriptor`. These external calls have original scalar/reference Objective-C encodings; private C++ `expected<>` aggregates remain inside the genuine framework.

The original mode table converts public mode 2 to internal mode 1. The exact original FileLocal route passes POSIX `O_RDWR` (2) to `open`. The different internal mode 2 permits an EACCES fallback to read-only; it is unsuitable for proving writes. A functional fixture must use public mode 2, require `fcntl(F_GETFL) & O_ACCMODE == O_RDWR`, verify the returned descriptor names the owned RAW inode, perform bounded writes/reads, close the genuine objects, and reopen/read back the data. It must separately report any unavailable Security-provider calls and must not touch a guest disk.

The current candidate has not yet loaded or invoked original DI2 on iPad. RAW/ASIF functionality, Apple libuio/io_rings integration, VMM block-device wiring, and the complete macOS 27 CPU/VMM/Virtualization backend remain unverified.
