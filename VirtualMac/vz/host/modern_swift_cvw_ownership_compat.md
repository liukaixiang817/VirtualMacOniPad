# Scoped VZ27 compact ownership provider

The provider implements the five additional C ABI ownership entries imported by
the original macOS27 Virtualization image. Its supported contract is the genuine
`VZLinuxRosettaDirectoryShare.CachingOptions` type in VZ UUID
`418efc4809d93606918eb6f95baeffdc`. It is an application-private candidate and is
not linked to a running VM, globally interposed, installed, or trusted on iPad.

The implementation covers default copy-initialization, destruction,
copy-assignment, take-assignment, and inline value-buffer copying. The complete
112-byte original layout program is authenticated and checked, as are the true
value-witness flags (size17, stride24, alignment8, flags`0x02210007`), original
three-instruction tag getter, and VZ/Swift image UUIDs. Metadata, layout, and VWT
must all belong to that exact VZ image. Data PAC is authenticated at its original
slot with discriminator`0x8b65`/`0x2e3f`; relative getters are signed IA0.

Copies retain the original tagged Bridge word through the real stock
`swift_bridgeObjectRetain`; destruction uses the matching real release entry.
Same-tag assignment follows upstream release/retain ordering. A different-tag
assignment destroys the old value and copy-initializes the replacement.
Take-assignment destroys its initialized destination and transfers source bytes
and ownership, leaving the source consumed. No guessed heap header, no-op
destructor, fake success, or recursive native-VWT fallback is used.

The checked `VM27CVWOwnershipQuery` rejects unsupported metadata before value
operations. The ABI witness exports trap before ownership mutation when metadata
is unsupported or buffers overlap. Initialization destinations must be
uninitialized; assignment destinations initialized; every taken source must be
excluded from subsequent destruction. This is a narrower contract than all
Swift CVW callers. Do not globally route unknown types or aliasing callsites to
this provider simply because all five symbol names are present.

The implementation adapts the exact vendored official Swift commit
`5ea0a2a5d8e126628da27747739e8d017c1d4882`, with Apache2/Runtime Library Exception
notice retained. Relevant source is `BytecodeLayouts.cpp` Bridge destroy/copy/
assign handlers, assign-with-take, and inline buffer-copy; the ABI is C_CC in
`Swift-RuntimeFunctions.def:3076–3135`. The original VZ full layout and getter
code come from the existing frozen `modern-swift-cvw-closure-audit-v1` evidence.

Build without installation or execution:

```sh
python3 -B VirtualMac/scripts/development/build-modern-swift-cvw-ownership.py \
  --output /private/tmp/new-cvw-build
```

2026-10-08 actual local Mac verification used real public VZ enum constructors
and authenticated native VWT entries for comparison. Both the original witnesses
and candidate completed40 scenarios (80 total), with323 checks and no failures.
All four source/destination tag combinations, short and independently allocated
long Strings, owner destruction before reading surviving copies, allocator
pressure, take consumption, explicit destruction and buffer canaries passed.
Genuine `Int` and null metadata were rejected by the checked query. Separate
unsupported/overlap processes terminated at the deliberate BRK with SIGTRAP5.
The initial negative oracle incorrectly expected SIGILL4; the saved raw exits
were reevaluated with the corrected Darwin BRK mapping and were not rerun.

The final libraries are in `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/
swift-cvw-build-v3/`: Mac SHA`99f3edc8360078e23a473626405403a8faa44789c33a68f3b4cb70dd0404b395`,
iOS SHA`dc3378eef373b40e8b1ef7b9382e87ac71dd0165f363eda8e1e32018984f24f8`.
The final actual results are `swift-cvw-ownership-v1/actual-v3-results.json` and
its bound stdout files. Both libraries passed arm64e compile, signature and dyld
checks; the iOS library has not executed on iPad.

This result does not prove String leak freedom, VZ27 iPad loading, full CVW
ownership, compatibility-override registry, the EFI nested Data layout, other
Swift bytecode handlers, full Swift27 or guest execution. The original EFI
program requires additionally proven ObjC and NativeStrong ownership semantics
and genuine Data/EFI fixture evidence. Complete default interpretation has23
handlers, with generic/resilient/existential and weak/unowned contracts that are
not supplied by this scoped provider. A full VZ strong-import closure must also
resolve its Swift array helpers, DI2/io_rings and other providers, and replace the
Ventura-only GOT/RPC offsets in the frontend before booting a modern VZ stack.
