# Typed V2 consumer in the independent provider graph

The earlier V9/V2 graph linked the frozen V1 `VM27LargeConsumer.dylib`.
Consequently the ordinary strict-result implementation and its typed V2
consumer had no route into the actual factory dependency graph. V1 strict
result storage still lacked the outer kernel CDHash needed by the factory.

`modern_xpc_original_instance_transport_v10.c` compiles the entire unchanged
V9 implementation with explicit versioned type/function mappings. Its factory
accepts `VM27LargePrivateServiceConsumerV2 *` and calls the exact V2
`CheckMessage` and `CopyState` functions. It never casts a V2 opaque handle to
V1. `vm27_owned_startup_coordinator_v3.c` applies the same method to the entire
unchanged V2 lifecycle and exposes the typed V2 consumer at its parent boundary.
The previous sources, signatures, graphs and evidence remain unchanged.

This integration preserves every existing gate. Strict mode runs the original
native received-message check before the real audit-token CDHash/CS_VALID
queries; each refusal returns without trying another mode. Actual spawned
child PID/PIDversion/reaped checks, registry file rechecks, exact nonce/service
guards and remote connection requirements retain their previous behavior.
Neither new adapter has executable statements outside its included old body.

`scripts/development/build-modern-vmm-owned-xpc-v10-provider-v1.py` creates
13 iOS provider files in a new output directory. Eight old providers are byte
exact copies. The five new unsigned providers are the combined V2 consumer and
strict-result implementation, unchanged bundle reader, V10 transport, V3
coordinator, and zero-instruction V10 reexport aggregate. The new graph has no
V1 consumer image or V9 transport. It shares the same single CheckIn and
ClientRegistration providers. All app-private dependencies are checked against
the exact included install IDs and compatibility versions.

The build parses Mach-O imports and verifies the strong two-level routes
V3 -> V10 -> V2 consumer. It also verifies that the V2 consumer really imports
the existing native policy, audit-token getter and `csops_audittoken` entry
points. No unsigned iOS provider is loaded. The only local execution is eight
existing coordinator state/lifetime scenarios per ordinary and ASan/UBSan
flavor, with explicit transport doubles and two actual CheckIn instances,
plus the existing strict-result implementation's explicit positive/refusal
and query-corruption doubles. These tests establish ordinary wiring and
cleanup behavior. They perform zero real native policy or kernel-code queries.

This graph removes the disconnected V2 consumer implementation problem. It
does not establish native strict-mode acceptance, deliver an original VMM
handler, integrate trusted preparation before original Main, rewrite the
original VMM route, sign or deploy any new provider, repair CPU execution, or
complete the original VMM/VZ strong-load closure. It must be used alone in a
fresh process; no V9/V2 and V10/V3 singleton mixing is supported.

The separate `build-owned-v3-preparation-ipad-v1.py` creates a signed ordinary
parent/child fixture package from the frozen V10 graph. It signs four new
provider copies and two owned executables with the exact already used
entitlement payload; six older libraries retain all their bytes and signatures.
The manifest's invocation ends in the mandatory literal `strict`. An explicitly
requested `explicit-approved` invocation selects that existing diagnostic mode
from the beginning. No error can change either choice.

The new fixture prints the actual typed V2 received-message result before
V3/V10 rechecks the same message. Strict native refusal closes its own control
IPC, drains final INVALID, and naturally reaps its direct child. The parent
retains the actual factory refusal and exits78; it creates no service client
or title registration on that path. A child in this strict diagnostic can
clean up after final INVALID with zero title commits, which grants no service
authorization. A positive run follows the prior one-title-commit protocol and
still starts no original handler or listener. The package builder does not
deploy it or execute iOS code. Root review and bounded owned-process-group
supervision are required before any device execution.
