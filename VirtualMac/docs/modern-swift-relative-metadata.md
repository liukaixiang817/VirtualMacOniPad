# Swift relative metadata and per-slot authentication

`scripts/development/swift_relative_metadata.py` relocates bounded Swift
singleton, protocol conformance and reflection schemas after dyld-cache
extraction. It uses the pinned Swift ABI schema commit
`5ea0a2a5d8e126628da27747739e8d017c1d4882`. Unresolved external edges block an
apply operation. The scanner does not infer all metadata layouts or turn an
unchanged opaque symbolic reference into a validated functional schema.

The pointed-to ABI type matters independently of the mangled symbol spelling.
Swift's relative `MethodDescriptor` and `ProtocolRequirement` aliases are
different concrete types. A `Tq` suffix alone does not identify which pointer
authentication contract a slot needs. A compiler produced enum/CaseIterable
oracle and a genuine DIKit witness PAC crash confirmed this distinction.

`audit-swift-cache-indirection-auth.py` reads original GOT slots directly from
the local cache. It checks the input route SHA, cache UUID, mapping and actual
slide-info-v5 chain membership before recording raw words, target addresses,
DA/IA key, diversity and address diversity. It never loads a library, writes the
cache or queries a symbol-cache sidecar. It records symbol names from the pinned
route inventory; it does not claim independent symbolization of decoded target
addresses. Authentication policy is decoded per slot.

For the genuine Virtualization 27 image, the frozen oracle is
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/vz-original-slot-auth-oracle-v3/contract.json`.
All 17 protocol-requirement slots use DA/address diversity/`0x7d4c`. The remaining
23 protocol/context slots use DA/address diversity/`0xae86`. Class method
descriptors use a separate `0x675a` contract and are not accepted in this scope.
The tracked builder validates each original slot against the exact schema label,
symbol, owner and ordinal before emitting a new strong GOT binding.

`vz-resilient-schema-root-v1/build-v5` replaces the earlier incorrect plain
requirement slots. Compared with frozen v4, only the 17 requirement PAC words
differ before the code signature. All other payload bytes, code, original bind
words and relative relocations are identical. The independent review passed 40
positive slot contracts and rejected 160 controls covering plain pointers,
class-method diversity, wrong slot identity and absent chain membership.

The v5 candidate fixes 55 external edges with 40 new strong data imports and
nine internal relative fields, with no unresolved edge in the selected schemas.
Its source still has the documented prior weak/flat semantics. It has not been
loaded or invoked as Virtualization on iPad and is not a complete strong closure
or a runnable macOS 27 backend. The actual DIKit fixture is functional evidence
for the protocol-requirement PAC rule; actual VZ witness execution remains an
independent acceptance step.
