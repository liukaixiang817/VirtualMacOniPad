# Original macOS27 XPC transport ABI

`modern_xpc_original_transport.c/.h` supplies the original C entry points
`xpc_connection_create(identifier, queue)` and `xpc_main(C_peer_handler)` within
an explicitly linked app-private diagnostic module. It routes only
`com.apple.Virtualization.VirtualMachine` through an authenticated owned child
endpoint. Other identifiers/anonymous creation use exact native libxpc via an
explicit provider handle. It exports no registration API and modifies no
bootstrap/launchd or iPadOS configuration.

The exact VM client returns an actual inactive native connection on the real
caller queue. Server delivery invokes the borrowed-connection original C handler
once on the real queue after actual peer audit PID/version, kernel CDHash/CS_VALID,
reviewed parent code bytes, and native SecTask+native connection Boolean gates.
Only actual `com.apple.private.virtualization` or `com.apple.security.virtualization`
can produce original mask bit0; plugin is a separate registration policy. Actual
SecTaskEntitlementsValidated is recorded separately and never changed.
Compiler-native arm64e ABI0 typed pointers retain PAC for invocation; stripping
is used exclusively for provider identity/code-pin inspection.

The system libxpc UUID/path and first64 bytes of its audit/entitlement getters
are frozen to existing real iPad PID33273 receipt. Strong SecTask imports match
Apple SecTask.h names and exact Security provider UUID/path. Unknown runtimes
fail closed. Parent code files are bounded to the unchanged2MiB old inspector.
Native final INVALID plus queue drain precedes listener storage destruction;
timeout retains storage for a bounded retry. Endpoint allocation happens before
binding a callback that borrows server storage.

Frozen candidate: DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/
xpc-original-transport-v1/build-v5. Build/test/validator are the tracked
`build-modern-original-xpc-transport.py`, `test-modern-original-xpc-transport.c`
and `validate-modern-original-xpc-transport.py`. The candidate contains7 iOS
files, including5 byte-identical frozen native-tested dependency providers,
and a new original transport library/CLI. Only the CLI has4 previously proven
launch permissions plus plugin=true/private.virtualization=true. Libraries have
empty entitlements. 167 payload pins+freeze.json=168 files.

Local evidence is14 exact signed binaries,92 critical strong bindings,272
corrupted-binding refusals and31 corrupted genuine receipt refusals. Mac actual
parent/child runs65220/65236 (normal),65237/65238 (deny-handshake) and65239/65240
(timeout) all returned0 and reaped/cleaned own objects/temp. Mac entitlement gate
was false, so all denied and invoked0 original peer handlers; each child truly
called original xpc_main and exited its dispatch_main lifecycle. This is negative
and cancellation evidence only.

Actual iPad v5 evidence now exists: normal parent/child38051/38052,
deny-handshake38289/38290, timeout38527/38528. Each actual parent and child
returned0 and external checks found both absent and the exact owned temp removed.
Normal287+316checks/0 produced65 reverse replies,64 child handlers, one original
C callback and one real original xpc_main; actual native connection Boolean
base mask3 and SecTask/kernel identities matched. Strict validation stayedfalse.
The other variants delivered0 application messages/peer callbacks.

Independent local reparse in original-xpc-three-native-independent-review-v1
rechecked all24 provider paths/UUID/SHA/RVA per run, actual waits and external
cleanup claims, rejected29 damaged actual receipts, and verified all168 frozen
bytes unchanged. This demonstrates only this original create/main transport leaf.

The CLI is not the original27 VMM. Original VMM partial closure remains
prohibited execution. Original VZ's uuid_generate/set_oneshot_instance step is
not yet exercised by this leaf; preserving an inactive connection is an API
prerequisite, not proof of that setter. Original VM serialized message protocol
and returned framework objects also remain untested. PluginLoader/Installation
identifiers use native forwarding and have no app-private factory integration
in this module. The2MiB fixture inspector does not validate the original VMM's
larger signed image; any exact pinned expansion needs a separate candidate.

The next independently frozen one-shot UUID candidate is
xpc-original-instance-transport-v1/build-v3 using
modern_xpc_original_instance_transport.c/.h. Native Mac setter on an owned
handler-inactive endpoint actually trapped (PID68902/wait-5) because its native
transport is already live; the exact old iPad setter code independently has the
same live check. Native setter was not called on iPad. The new candidate
authenticates a real UUID control request and child ack before the original
callback, without overwriting libxpc fields; its iPad positive remains pending.
