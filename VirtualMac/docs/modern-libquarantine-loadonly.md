# Genuine macOS 27 libquarantine load-only closure

This module reconstructs the genuine macOS 27 `/usr/lib/system/libquarantine.dylib` for an app-private dependency of the modern DiskImages2 candidate. It does not replace quarantine operations with stubs. The original image UUID is `7fd4ae2286ef382b83f5adf9336c1160`.

The current frozen candidate is `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/libquarantine-loadonly-build-v3/candidate.json`. Its SHA-256 is `97dc99027984367a1343c00c029a4528c52057166ff24d4ff6891dfe3666fc67`. The incomplete build-v1 and rejected iOS build-v2 are retained as diagnostic evidence and are not deployable candidates.

## Reconstruction and strong routing

The fresh, privately owned extraction and symbol cache are in `libquarantine-reconstruct-v2`. Its reconstructed Mach-O SHA-256 is `cc83b14701fd2fa8a851870d298e9af76da3ccfc1051770bdcbd18a0999380e2`. The original cached-image audit is in `libquarantine-genuine27-contract-v1/contract.json`.

All 42 imports have positive, non-weak ordinals. The original eight system dependencies remain strong. Each original optimized import owner is recovered from the new cache snapshot, including libsystem platform implementations and kernel wrappers. On iOS, two allocator imports bind strongly to the separately validated private `VM27DiskAllocatorProvider.dylib`. `_reallocf` explicitly binds to native iOS libsystem C, following the actual iPad symbol inventory. These are recorded compatibility routes, not claims that the original Mac ordinal contract is unchanged.

The genuine library advertised both macOS and Mac Catalyst. The iOS derivative declares only iOS 16.1; its Catalyst build-version command is removed because dyld rejects the iOS/Catalyst pair. No dependency is removed or weakened. The install name becomes `@rpath/Libquarantine27.dylib`. All 11,651 bytes in the non-zerofill sections remain identical to the reconstructed library, and the 16-byte BSS definition is preserved. The candidate has no initializer command/section, Objective-C or Swift section, or interpose section.

## Probe scope and identity gates

Source and build entry points:

- `vz/host/modern_libquarantine_loadonly_probe.c`
- `scripts/development/build-modern-libquarantine-loadonly.py`
- `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/libquarantine-independent-review-v1/review.py`

`--inventory` requests only the eight already loaded system libraries with `RTLD_NOLOAD`. It resolves all 42 exact imported symbols, records each actual image UUID and RVA, and closes its loader references. Missing symbols are reported; this mode does not load the private quarantine library.

`--load-only` first rejects any missing non-allocator import or missing image identity. On iOS it verifies the byte size and SHA-256 of the private allocator and checks both allocator export UUIDs and canonical paths. It then verifies the quarantine file size and SHA-256 before `dlopen`. All nine DI2-required quarantine exports must match the original UUID, private canonical path, and original reconstructed RVA. It closes the library references without invoking any quarantine export.

The iOS probe has exactly `platform-application`, `com.apple.private.security.no-container`, `com.apple.private.security.no-sandbox`, and `com.apple.private.amfi.can-execute-cdhash`. The library has no entitlements. Neither `get-task-allow` nor broad runtime hooks are added. File hashes are read for identity; no disk-image API, VM, GPU, or original quarantine function is called.

| iOS file | Bytes | SHA-256 | CDHash |
| --- | ---: | --- | --- |
| `libquarantine27-loadonly-probe` | 51984 | `af6e380abd3c8437040faaad678c2bc12eb30d229cc816e56bad92892c54037b` | `5bfd2de2eca4966d8aa61e29cb1af8e6f6c9933b` |
| `Libquarantine27.dylib` | 99728 | `41d6e97349c5627c820b070987d60ae335331e710cb90bb1993604da8deeb3d7` | `e9306e67843cc772f4277bf623cd9210440148f0` |
| `VM27DiskAllocatorProvider.dylib` | 50640 | `5c5f4a403525b04b980ef7e572f759afed58624c003d2afb1872fab8d861ec8b` | `c74792f2a4fd22b54985ce70019e5954538f5d21` |

The frozen iOS probe expects `/var/root/VirtualMac2/testing/libquarantine27-loadonly-v1`. Its generated header pins those exact private files. Copying the probe to a different directory requires a new build and freeze.

## Actual evidence and remaining work

Mac inventory child PID 61235 exited 0 with all 42 symbols present and zero identity failures. Mac load-only child PID 61237 exited 0 with all nine genuine quarantine export identities and zero quarantine/API/disk-image/VM/GPU calls. Both children were reaped. The build manifest and stdout contain these receipts.

The independent review re-parses the signed candidates and verifies section bytes, ordinals, dependency commands, UUIDs, actual entitlements/CDHashes, strict signatures, dyld validation, source freezes, and exact receipt PIDs. Its result is `libquarantine-independent-review-v1/verification.json`. This review does not load any framework or touch the device.

Root's actual iPad inventory is `libquarantine-system-inventory-native-v1`: child PID 37365 exited 0 and was externally confirmed absent. All 40 non-allocator symbols were present with actual native owner/UUID/RVA identities; only `malloc_type_calloc` and `malloc_type_malloc` were absent, as expected for their explicit private routes. The actual iPad load-only receipt is `libquarantine-loadonly-native-v1`: child PID 37462 exited 0, was externally absent, and loaded the genuine UUID with all nine exact private export UUID/path/RVA identities. There were zero original qtn, disk-image, VM, or GPU API calls. The library and probe bytes were unchanged from build-v3.

`libquarantine-native-independent-review-v1/verification.json` independently checks both exact native stdout/result/plan receipts, the two PIDs and external absence, all 42 symbol rows, the nine original export RVAs, and all 73 files in Root's freeze. The freeze SHA-256 is `3be2fa7fdce566c5b5969be95acb8bfb07de1bc03363932e2e7dc1a1888dd28b`. These local receipt checks perform no device operation.

The original code uses macOS quarantine/kernel policy interfaces. Successfully resolving their function addresses does not prove the old iPad kernel supports every quarantine operation or policy payload. No original qtn API has been executed, and private nominal qtn signatures are not invented. Loading this library also does not prove that genuine DiskImages2 can open, read, or write an image. The next functional acceptance step is a genuine DI2-owned disposable unencrypted RAW open/close and read/write fixture, followed by modern VMM block-device integration. Full macOS 27 CPU/VMM/Virtualization remains incomplete.
