# Owned reverse service factory diagnostic

The tracked private-service-factory probe composes the native-validated frozen
Registry, typed Consumer, Endpoint, ApprovedCode and original StrictPolicy
modules. The actual registered child creates a real listener and transfers its
native endpoint via XPC serialization. The parent becomes a real client of that
child listener; both sides check every received kernel audit identity and actual
kernel code hash/status against reviewed signed self bytes.

The iOS diagnostic requires actual plugin Boolean true and the exact explicit
approved code gate before child handlers are reached; original strict native
validation is kept separate and unchanged. The Mac transport-only diagnostic
can exchange only its reviewed exact-code capability, and the original strict
gate still refuses all service handler requests because its plugin is missing.
That branch exists solely in the test; it is not a generic original API provider.

Frozen candidate: `xpc-private-service-factory-v1/build-v4`. Actual Mac native
normal/invalid-nonce-handshake/missing-handshake-timeout runs pass764checks in
total, with every child exited/reaped/absent and every owned temporary bundle
deleted. Normal has65 actual reverse request/reply pairs and66 actual peer
code/status queries on each side. The two failures perform no service requests
and clean up every owned process/object/port. The twelve native invalid-endpoint
controls are also run in each parent. Independent signature/import/receipt
checks preserve exact before/after identities of all five providers.

Actual iPad runs are now independently reparsed from Root's three native
receipts: normal parent36519/child36520 passed584checks, deny-handshake
parent36729/child36730 passed126checks, and timeout-handshake
parent36939/child36940 passed122checks. Every actual parent and child wait was0;
Root's separate exact-PID checks confirmed both processes absent and each exact
owned temporary bundle removed. Normal delivered65 reverse request/reply pairs,
64 child handler calls and1 protocol denial; each peer performed66 real kernel
audit/code/status checks. The denied and timed-out handshakes made0 service
requests and recovered their own resources. Original strict native validation
remains false; the separately authorized exact-code gate is the positive path.

The independent review checks all20 provider path/UUID/SHA/RVA records per run,
all98 frozen payload pins plus the manifest identity (99 total frozen files),
54 strong bindings and216 invalid-binding controls. Fifty newly damaged native
receipts are refused. Evidence is in
`service-factory-native-independent-review-v1/result.json`; the frozen candidate
and Root's actual native receipts were not changed.

Original macOS27 VZ/VMM caller service identifiers and factory protocol still
require integration, and no original
`xpc_add_bundle_with_lwcr` export, original VMM execution or complete backend is
claimed. Root is the sole device operator. All existing frozen packages remain
unchanged.
