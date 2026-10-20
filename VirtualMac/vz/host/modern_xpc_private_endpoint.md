# App-private owned endpoint bridge

This scoped provider carries an anonymous listener endpoint to one exact owned
child through `posix_spawnattr_set_registered_ports_np`. It does not modify the
parent's registered port table, bootstrap namespace or launchd configuration.

`VM27PrivateEndpointCopyABI` accepts only the actual system libxpc path and the
two independently observed libxpc UUIDs. The endpoint field at `+0x18` comes
from the original project's `vz/development/probes/epprobe.m`. Access requires
an official native endpoint type and a live Mach send right with positive
references. `CopySendRight` returns one explicit owned reference. The receiving
child creates its own fresh endpoint shape; only that object is modified. Its
original send reference is released, and the transferred reference is released
with the shape after native `xpc_connection_create_from_endpoint`.

The API borrows a send capability supplied by this private launcher. It cannot
prove arbitrary callers obtained a port from an owned endpoint; callers must
retain that provenance. It never reads another process's memory or obtains a
task port. Unsupported UUIDs, null/wrong objects and invalid/non-send/dead rights
are refused. It is not an exported substitute for `xpc_add_bundle_with_lwcr`.

The local candidate under `xpc-private-child-launch-v1/xpc-build-v4` actually
executes an exact same-code child and 65 cross-process XPC requests/replies on
Mac. It retains the frozen strict LWCR and explicit approved-code providers.
Both processes verify actual loaded files, UUIDs and strong import providers
before and after. The receiver checks every message's real kernel audit token;
only the exact actual child PID is accepted. On iOS the exact approved self
CodeDirectory and real kernel code hash/status are required before the 64 valid
requests reach a private handler; one nonce error must be rejected. The strict
native validation result remains a separate unchanged field.

Mac has no plugin entitlement, so all 65 real messages are denied by the strict
gate and none reaches a handler. Root subsequently executed the frozen iOS
candidate: parent PID 35898 and owned child PID 35899 both exited zero, were
reaped and externally verified absent. All 603 checks passed (381 parent,
222 child), including 65 cross-process XPC requests/replies, 65 actual child
kernel CDHash/status queries, 65 native SecTask creation/release pairs, 64
authorized private handler calls and one invalid-nonce rejection. The strict
native validation result stayed false; it was not rewritten or represented
as native LWCR success. All twelve exact loaded provider path/SHA/UUID/RVA
records match the frozen binaries; the parent registered table is unchanged.
This agent independently reparsed Root's actual wait-based receipt and verified
all frozen files unchanged in `native-xpc-verification.json`. No complete
bundle/service registration or original macOS27 VMM execution is claimed.

The fixture signs only the one probe with the already validated private mapping
rights (`platform-application`, `no-container`, `no-sandbox`, and
`can-execute-cdhash`) plus the exact plugin boolean. Libraries have no additional
entitlements. Parent and owned child are bounded by CPU 5 seconds and wall 15
seconds, and the parent must reap the child and prove it absent.
