The versioned lifecycle, initialization and system sources accept native ISA1
and ISA2 for the existing iPadOS 16.1.1 version-0e context contract. Requests
must still match the ISA of their actual VM. ISA3, unknown selectors, EL2 and
VHE remain rejected. The serialized guest-format conversion stays separate:
serialized zero maps to native ISA2; merely recognizing native ISA3 does not
permit a VM with that selector.

Use the three `_v2.c` sources instead of the three unversioned implementations
when building `VM27KernelContextProfilesV2.dylib`. They export the same typed
helper ABI and must not be linked alongside the original implementations.
The old project files remain intact because earlier device evidence pins them.
The explicit builder is `scripts/development/build-modern-kernel-context-profile-v2.py`.
The provider uses the existing caller-supplied lifecycle operations. It does
not link or export a native trap entry; the consumer must supply its validated
driver and memory reader/writer, as required by the typed helper contract.

The existing owner, generation, real context version, typed field bounds,
partial-write poisoning and same-owner cleanup rules are unchanged. Registers
requiring an unavailable native synchronization still fail without changing
the output. A successful creation-policy slice is not a complete reset.

Initialization now repeats the existing owner/live/version check after the
last write callback returns, before reporting a completed slice. A callback
that invalidates the boundary fails and poisons further writes; the same-owner
cleanup handle remains usable without repairing the context version. The local
regression is `scripts/tests/test-modern-cpu-initialization-boundary-v2.c`.
All public CPU handle operations now retain a shared atomic lifetime exclusion
before calling currentThread, readMemory, writeMemory or nativeTrap. Reentrant
access, destroy and free return BUSY. CPUCreate publishes its real handle after
the version callback returns, including the live cleanup handle on validation
failure. VM create/destroy/free use a separate handle exclusion; the native VM
destroy callback runs outside the mutex, so reentrant VMFree cannot deadlock.
Errors release the acquired exclusion without clearing mutation poisoning or
claiming a failed native destroy removed its resources. The host-only before
ASan reproducer and fixed regression are
`scripts/tests/test-modern-cpu-callback-lifetime-v3.c`; its verification runner
also runs the existing boundary and typed ISA1/ISA2 models with ASan/UBSan.

The saved validation reuses the lifecycle, initialization and SYS failure
models for each selector, with ASan/UBSan, and adds cross-VM ISA, ISA3 and unknown
selector rejection. These are local C mocks; they do not establish guest
instruction execution. The new provider has not been deployed or connected to
the original macOS27 VMM. Its full-guest run gate remains unavailable until
native execution and original consumer integration are proved.
