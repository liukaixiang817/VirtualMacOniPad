# Original27 plugin LWCR policy

`modern_xpc_lwcr_policy.c` implements the actual original27 private-plugin
constraint as an app-private typed policy and per-message native signature gate.
It accepts only `{"entitlements":{"$query":[[1,"com.apple.private.virtualization.plugin"],[5,true]]}}`.
Apple's official launch-constraint documentation defines 1 as selecting a
dictionary key and 5 as matching a Boolean. Integer 1, strings, missing keys,
false, extra facts and additional/unknown query operations are rejected.

Policy creation produces an immutable typed snapshot. It does not retain a
mutable caller-owned graph; later changes to that graph cannot weaken a policy.
Reference ownership is atomic, bounded by `UINT_MAX`, and requires an existing
owner while retaining/using a policy. Final release destroys only that policy.

`VM27LWCRPolicyCheckReceivedMessage` is intended for **each received dictionary
before a private service forwards it to its application handler**. It rejects
local dictionaries without a native remote connection. Apple's official
`SecTaskCreateWithXPCMessage` obtains that specific message's kernel audit token;
`csops_audittoken` in the native Security implementation associates subsequent
signature reads with it. This avoids the cached-connection/PID identity problem
explicitly described in Apple's `SecTaskPriv.h`. The task, entitlement and any
native error are released on every completed check. Native validated entitlements
and an actual CFBoolean true are required. Missing, false, integer values,
unvalidated signatures and failed native reads fail closed. A message-body
`com.apple.private.virtualization.plugin=true` has no authority.

This is an actual parser and authentication module, **not a completed replacement
for bundle registration**. The original27 `xpc_add_bundle_with_lwcr(path,flags,lwcr)`
packages the requirement into a bootstrap registration RPC. The old iPad
`xpc_add_bundle` performs registration without that requirement. Calling it and
discarding the requirement would not be equivalent. A future private bundle
registry must commit real bundle/service records, constrain the code it launches,
and use this gate at every consuming connection/message boundary before the
original strong function can be routed to a successful private registration.
This module therefore does not export `xpc_add_bundle_with_lwcr`, call either
registration function, interpose system APIs, or modify iPadOS/launchd.

The independently collected old iPad libxpc UUID is
`7a0ca8d2728537ddae972efaa1de763e` (PID 33273, actual wait 0, child absent,
six bounded reads, zero registration calls). At RVA `0x1092c`, the old
`xpc_connection_set_peer_code_signing_requirement` is exactly `mov w0,#45;ret`,
so it cannot provide this authentication. The old audit-token getter copies
32 bytes under a native connection lock; its result is a cached connection
identity. The old entitlement-copy entry delegates to an internal helper; this
module does not guess its return-object ABI and does not call it. Exact native
hex, disassembly and hashes are in `xpc-lwcr-compat-v1/native-abi-v1`.

The local Mac missing-entitlement fixture uses a real anonymous listener,
endpoint, client, 64 request/reply messages and four joined ownership workers.
It separately exercises pure owned-dictionary true/false/type/malformed-query
cases. The native negative run passed 1482 checks; all 64 tasks were released,
every received message was rejected, and the provider UUID/RVA/file pins matched
before and after. This is a genuine negative authentication test. It does not
claim a trusted positive native peer: the ad-hoc Mac signature is unvalidated.
A Mac counterpart signed with private plugin=false was killed before main;
the checks were not removed or bypassed to make that variant launch.

The iOS candidate contains one private strong provider and four copies of the
same compiled CLI payload: missing, Boolean false, integer 1 and Boolean true.
Only signatures differ; file-backed code/data/PAC sections and import tables
remain identical within that role. Each CLI has platform/no-container/no-sandbox/
can-execute-cdhash, plus its listed plugin test value; the library has no
entitlements. There is no get-task-allow, HV, GPU or other-process-memory work.
The CLI enforces CPU 5 seconds, wall 15 seconds, exact self/provider SHA+size,
provider UUID, and absence of VZ/HV/VMM/PVG images. The native true run is counted
as a positive authentication test **only if the actual native validated flag is
true and 64 messages reach the application handler**. An unvalidated true
signature being refused is a negative test, not positive coverage.

Build with tracked `scripts/development/build-modern-xpc-lwcr-policy.py` and
validate with `scripts/tests/validate-modern-xpc-lwcr-policy.py`. The validator
checks CodeDirectory pages, actual typed entitlements, arm64e ABI0/min+SDK16.1,
positive strong two-level imports to the actual private provider, and 192
weak/flat/missing/wrong-provider negative binding controls. It accepts native
transcripts only with the runner's observed child PID and wait status. No
original27 VMM, guest CPU or bundle registration is executed by this scope.

The four actual iPad runs subsequently passed independently: missing PID33488,
false PID33635, integer PID33772, true PID33910; all observed wait0 and absent
after reaping. Together they performed 5928 checks, 256 real XPC messages and
256 balanced SecTask lifecycles. The Boolean-true value was read from the real
kernel signature, but **all four `SecTaskEntitlementsValidated` results were
false**, so every native message was refused. The parser/native-read/negative
authentication module is verified; native trusted-positive authentication is
not. Receipts and independent validation are in
`xpc-lwcr-compat-v1/native-policy-verification.json`. The frozen candidate was
not altered to remove this check. An explicitly approved app-private code
identity route, if added later, must separately prove the actual message audit
token and exact approved native CodeDirectory hash; it cannot turn this
unvalidated native LWCR result into an unrestricted success.
