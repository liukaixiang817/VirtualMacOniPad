# Original DI2 owned RAW diagnostic

`vz/host/modern_diskimages2_owned_raw_probe.m` is a bounded caller of genuine
macOS 27 DiskImages2, UUID `a456d4a4d6ab3549965d0400f3552de3`. It implements no
replacement DI2 class or disk engine. It uses the original scalar/object
Objective-C contracts established by the 29-function static audit in
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-raw-open-contract-v4`.
It does not declare or guess the private C++ `expected<>`/ownership aggregates.

Before any DI2 call or temporary-file creation, the probe rejects an existing
DI2 image or conflicting class, pins all twelve private library files, and
checks actual provider/class image UUIDs and the eight original method
encodings and implementation offsets. Private library bytes are identical to
`diskimages2-hpke-loadonly-build-v1`; the standalone executable adds no changes
to those files or iPadOS.

The only disk input is a new 0600 `mkstemp` regular file under its own fixed
diagnostic directory, capped at 128 KiB. Original `DIOpenParams` public mode 2
must map to strict internal read/write mode 1. The returned real
`DIImageHandle` descriptor must identify the same device/inode and remain
`O_RDWR`. Three reads and one write are each 4096 bytes. `fsync` uses the real
iOS SDK declaration. The test releases both original framework objects and
their autorelease pool, observes `EBADF`, opens again through original DI2 and
verifies persisted data. It also requires an actual NSError for a nonexistent
owned sibling path and verifies that no file was created there.

The probe never closes a borrowed framework descriptor directly. Two
`@finally` blocks release its objects/pools on Objective-C exceptions; real
C++/kernel failures still terminate the child and are not reported as a
successful lifecycle. All ten private desktop Security entry counters must
remain zero before and after. No attach, guest image or VM/GPU call is made.
CPU limits are 3 seconds soft/4 hard and the wall alarm is 10 seconds. The
parent must record actual wait and external process absence, and verify or
perform only this diagnostic's own-file cleanup after abnormal exits.

Build with `scripts/development/build-modern-diskimages2-owned-raw.py --output
NEW_DIR`. The final local candidate is `diskimages2-owned-raw-build-v4`, with an
88-file freeze and thirteen-file plan in
`diskimages2-owned-raw-independent-review-v1`. The success-only saved receipt
parser is `scripts/tests/validate-modern-diskimages2-owned-raw-native.py`;
`diskimages2-owned-raw-parser-selftest-v1` tests its syntax with synthetic data
and ten rejected malformed logs. These are not actual RAW executions.

Execution remains pending. Actual DI2 load-only PID 40242 exited 67 before any
API call, after advancing past HPKE to a missing strong Foundation
`String.data(using:allowLossyConversion:)` entry. RAW must not run until the
real dependency closure passes. Even a successful owned RAW test would prove
original DI2 object/descriptor IO only; ASIF, Apple libuio/io_rings, modern VMM
block-device integration and the complete macOS 27 backend remain separate
functional gates.
