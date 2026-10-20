# Genuine27 EFI memory-store contract

The selected private candidate is the immutable
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/efi-owned-nvram-v1/build-v5`.
It contains genuine27 `EfiSupport` and its three real DXE companion modules,
the separately verified native RTTI adapter, a bounded probe and an own legal
128 KiB store created by the Mac system's `VZEFIVariableStore` initializer.
No production or Tahoe3 NVRAM was copied, opened or changed.

The earlier genuine `CreateEfiVariableStoreRuntimeFromMemory` failure was preserved
as a real EFI error. `DYLD_PRINT_APIS` established that its internal relative
`dlopen` could not find `libPcdDxe.dylib`. Supplying genuine Pcd, VariableRuntime
and FaultTolerantWrite DXE modules closes that actual runtime dependency; no status
code or blank-store format was changed to manufacture success.

The modules retain all thirteen original strong positive libSystem imports.
Two compact reconstructions had a zero-sized inserted `__got` section header
incorrectly moved beyond its inserted segment. The builder verifies and repairs
only those section address/file-offset fields. Existing bind pool, authenticated
chain words and all reconstructed file-backed code/data bytes remain equal.

`test-modern-efi-nvram.cpp` strongly imports creation, destruction, get, set,
enumeration, variable-info and current-state functions. It copies the read-only
oracle to an exclusive own file, creates the real runtime, writes and replaces
an own vendor-GUID variable, checks bounded read/error/enumeration contracts,
destroys and flushes the runtime, then reopens/remaps the file. The second runtime
must retrieve the persisted value, delete the variable, return `EFI_NOT_FOUND`,
destroy and remove all own files, mappings and file descriptors. All EFI results
are actual function returns.

Actual iPad evidence is `efi27-owned-nvram-native-v1`: direct child PID 32039,
observed wait exit 0, reaped and absent; 562 checks, zero failures, 28 EFI calls,
two real creates and two real destroys. Persisted reopen, deletion and own-file
cleanup passed. A separate Root post-check found no `owned-nvram.*` temporary
directory. The independent transcript verification is
`efi-owned-nvram-v1/native-owned-nvram-verification.json`; it compares all six
supporting-file SHA pins before/after and the probe's single preflight SHA record,
fourteen actual API identity records and six actual companion-module entry RVAs.
The separately executed Mac fixture, PID 29742 and observed wait 0, passed
561 checks. It is separate host evidence, not a substitute for the iPad run.

The independent CLI has exactly platform-application, no-container, no-sandbox
and can-execute-cdhash. Libraries have no entitlements. CPU and wall time are
bounded, and no Virtualization/Hypervisor/VMM/PVG loading or GPU/VM work is allowed
in this process. Only its private diagnostic directory is writable.

`consumer-api-ledger.json` records twenty-four distinct original VMM/VZ imports.
Six consumer APIs are exercised here, plus the current-state diagnostic query;
the remaining APIs, Secure Boot/policy/NvramToc2 contracts and full original VMM
execution remain unverified. This smoke establishes a genuine persistent EFI
variable-store lifecycle, not the complete macOS27 backend.
