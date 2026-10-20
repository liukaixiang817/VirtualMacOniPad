# Typed private service plan consumer

This module couples the actual private bundle registry to a real owned child
launcher. It copies an immutable registered plan, reopens its pinned files,
authenticates the complete executable CodeDirectory/pages/embedded slots and
compares both caller-reviewed SHA256 and CDHash. The original non-null plugin
LWCR and flags2 are kept exactly; additional constraints are refused.

The private consumer starts that registered path once. It borrows only a native
owned endpoint capability and installs it in child registered slot2 with the
official spawn attribute, preserving the parent table. Arguments are bounded
and `argv[0]` must be the registered path. `DYLD_*` overrides are refused.
Every message rechecks registered file pins and its actual kernel audit
PID/version against that spawned child. Only then does the selected original
strict native gate or explicit approved-code gate run. The explicit gate still
requires actual kernel CDHash/status, native plugin Boolean true and exact
approved code; it does not change native validation or accept body assertions.

Actual `waitpid` owns the one child. Nonblocking wait returns EAGAIN while it
runs; another spawn is refused, and release refuses an unreaped active child.
Callers must bound blocking waits and drain their message queue before release.
Successful release frees the copied registry plan and approved policy. No task
port, other-process memory, bootstrap/launchd mutation or automatic killing is
used. The seven API entry points are scoped and do not export the original
`xpc_add_bundle_with_lwcr` API.

`xpc-owned-service-launch-v1/build-v3` actually runs a registered, byte-identical
owned service clone on Mac: parent 53660 and child 53680 exit zero, the child is
reaped and absent, all 608 checks pass, 65 real requests/replies are refused by
the original strict gate, five plans and one consumer are released, and the
entire owned temporary bundle is removed. Missing service, wrong SHA/CDHash,
extra requirement, null endpoint, wrong execution path, DYLD override, changed
plist, repeated spawn/reap and active-child release have real negative tests.
Twelve exact signed binaries, 84 strong bindings, 336 invalid bindings and 13
altered receipts have independent checks.

The iOS candidate contains the four previously native-validated frozen
Registry/Endpoint/ApprovedCode/LWCR binaries unchanged, plus the new typed
consumer and probe. Only the probe has the same four private mapping rights and
exact plugin Boolean. No extra library entitlements or get-task-allow are used.
Root subsequently ran this exact frozen build on iOS: actual parent36214 and
registered ServiceExec child36215 both exited0, were reaped and externally
confirmed absent;672checks/0,65real requests/replies,64authorized handlers and
one nonce refusal passed. All20 exact provider path/SHA/UUID/nlistRVA records
matched. Four plans and one consumer were released, and the actual temporary
bundle was removed and externally confirmed absent. Independent reparse is
recorded in `xpc-owned-service-launch-v1/native-verification.json`, with all126
frozen files unchanged. This confirms the child-client to parent-listener
diagnostic direction; the original parent-client to child-service factory/API
has not been proven by this test. The existing 2MiB registry code bound is kept;
the original 5MiB VMM is not part of this probe. Complete original bundle/service
semantics, original VMM execution and a full independent backend remain outside
this scoped result.
