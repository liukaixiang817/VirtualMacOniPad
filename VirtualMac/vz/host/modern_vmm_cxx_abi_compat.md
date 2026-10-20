# Original VMM C++ import providers

`VM27CxxABICompat.dylib` supplies thirteen precisely named original macOS27 VMM
imports. Nine floating-point `to_chars` overloads use the retained LLVM21.1.3/Ryu
implementation. Four typed new/delete overloads use the SDK's LP64, 64-bit type
descriptor ABI and forward to real native throwing new/delete. The descriptor is
advisory here; this adapter does not implement the new allocator's type telemetry.
Native allocation failures, object ownership and deallocation remain observable.
Build with `-fno-typed-cxx-new-delete` to avoid recursive typed lowering.

The iOS wrapper reexports the unchanged `VM27CxxProvider.dylib`, which depends on
the unchanged `ModernCPURuntimeCompat.dylib`. The wrapper itself has no generic
symbol fallback, framework stubs, exception-header emulation or GPU/VM calls.
All three libraries have no entitlements. The independent executable uses exactly
platform-application, no-container, no-sandbox and can-execute-cdhash, without
get-task or Hypervisor privileges.

## Native evidence

The selected immutable source and thirteen-API build are
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/vmm-loader-closure-v2/cxx-build-v6`.
The selected signature control is its sibling
`probe-signature-controls-v1/four-can-execute`.

The actual iPad run is `vmm-cxx-native-v1`: direct child PID 30514, observed wait
exit 0, reaped and absent; 180 checks with zero failures. All thirteen APIs were
called through strong positive, two-level imports. Eight allocations were
released, provider file SHA/UUID/RVA remained equal before and after, and no
VMM/VZ/Hypervisor/PVG images were loaded. Test cases include finite and exceptional
floating-point formats, precise parse-back, buffer errors and canaries, two
descriptor values, zero allocation and genuine `bad_alloc` on `SIZE_MAX`.
`vmm-cxx-native-v1/result.json` records actual runner PID/wait and unchanged files.
The independent validator rejects weak, flat, wrong-provider and missing imports
and incomplete/failing/PID-inconsistent runtime transcripts.

The separate actual Mac fixture, PID 17876 and observed wait 0, also passed 180
checks. It is retained as host-side behavior evidence, not as iPad execution.

## Original executable boundary

The immutable `twenty-bindings-v3` VMM artifact routes these thirteen imports and
four earlier selected C++ imports to its existing dependency ordinal 51. The
remaining three earlier selected imports retain allocator ordinal 52 and Swift
ordinal 53. The dependency name at 51 becomes `@rpath/VM27CxxABICompat.dylib`,
whose explicit reexport preserves all seven exports of the old C++ provider
(including three atomic exports not among the four selected original imports).
Original import/addend/weak/PAC records,
file-backed code/data bytes and all other dependency ordinals are retained.
The executable's source SHA is
`c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422`.

This artifact still has unresolved macOS framework dependency paths and has not
been executed as an original VMM. Its frozen README correctly describes the
knowledge available when it was created; subsequent native C++ evidence is
recorded here rather than changing that frozen artifact.

The separate `modern_cxa_primary_exception_compat` module now implements and has
native iPad lifecycle evidence for `__cxa_init_primary_exception`. Its positive
run passed 722 checks; its saved-terminate negative control actually exited 79.
It is not yet reexported by this wrapper or routed in the twenty-binding artifact.
Assembly of a new complete, exact loader closure remains necessary before an
original27 VMM launch or full CPU/VMM/Virtualization success can be claimed.

## Subsequent native aggregate

The immutable `vmm-runtime-aggregate-v1/build-v4` assembles a new private wrapper
with a real strong reexport to the byte-identical primary-exception provider.
The thirteen original iOS function bodies and all earlier backing exports remain
unchanged. The new unsigned original VMM routes only the exception initializer's
import245 and matching nlist byte from14 to51: two bytes change, with original
platform/LC_MAIN/code/data/PAC unchanged. Eighteen selected C++ bindings use51;
the allocator's two and Swift lookup's one retain52/53, total21. The partial
original VMM remains excluded from deployment and has never been executed.

Actual iPad aggregate consumers passed independently:

* `runtime-aggregate-cxx-native-v1`: PID32733, observed wait0, child absent;
  180 checks/0, thirteen APIs and eight owned allocations released.
* `runtime-aggregate-cxa-native-v1`: PID32892, observed wait0, child absent;
  724 checks/0, seventy initializations,68 genuine objects/destructors,
  66 rethrows, two native cleanups and four joined workers.
* `runtime-aggregate-terminate-native-v1`: PID33051, actual wait79, child absent;
  nineteen checks and the saved-handler event. The changed current handler
  would have exited80.

The C++ imports and initializer/native factory bind through the wrapper's
positive ordinal1. Actual provider UUID/RVA checks and real lifecycle calls
therefore verify the new explicit reexport chain. Root staged only four private
libraries and two bounded CLI tools. Independent transcript results and receipt
hashes are in `vmm-runtime-aggregate-v1/native-aggregate-verification.json`.
The standalone module tests still do not establish complete original VMM closure.
