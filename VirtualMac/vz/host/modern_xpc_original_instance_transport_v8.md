# Version8: register the real frontend before one-shot delivery

This is a separate integration design. The frozen version7 source/candidates
remain unchanged. The original VMM wire protocol, native CPU execution and full
macOS27 framework closure remain pending.

The original VMM asks `_LSCopyMatchingApplicationsWithItems(-2,1,pid,clientPID)`
at RVA0x21b3c and copies `LSDisplayName` at0x21b84. The client PID comes from its
actual native connection, rather than the VMM's own title identity. Therefore
the title registry must authenticate and store the actual frontend process.

The existing version7 child gate already checks the real expected parent PID,
kernel CodeDirectory hash/CS_VALID, SecTask Boolean and native connection Boolean.
It also preserves the separately reported `SecTaskEntitlementsValidated` value.
Version8 adds private registration to that gate and does not replace it.

1. The child creates its own inactive service listener as version7 does. A new
   typed preparation API takes its existing actual expected parent PID/CDHash
   and nonzero bootstrap nonce. It configures
   `VM27ClientRegistrationConfigureV1(parentPID,parentCD,nonce)` once. The child
   exposes neither the parent's identity fields nor a mutable registry to wire
   callers. Configuration errors leave the service unable to accept a client.
2. The frontend copies a real nonempty string from its own main CFBundle's
   localized `CFBundleDisplayName`, falling back to actual `CFBundleName` only
   when the first key is absent. Wrong type, empty text or UTF8 over4096bytes
   fails. There is no hard-coded default title. The name snapshot belongs to
   the pending private request and survives asynchronous completion/timeout.
3. Before committing the one-shot instance, the frontend sends exactly the
   existing bridge's three fields on the already-owned control channel:
   `privateMethod=VM27.register-client-title.v1`, the UINT64 bootstrap nonce,
   and `clientDisplayName`. It sends no claimed PID/UID/audit token/CDHash.
4. The child accepts this message only on its actual serial control queue. It
   first uses the existing `GateInstanceMessage` with both actual native token
   and connection checks, then calls `VM27ClientRegistrationReceiveV1` on the
   same original received dictionary. The bridge rechecks full token equality,
   effective UID, PID version and current kernel CDHash/CS_VALID. Only a real
   success sets `clientRegistered` under the transport lock.
5. The reply must be a real native reply dictionary from that control peer.
   The frontend applies the existing reverse `GateInstanceMessage`, verifies
   an exact typed status/nonce/method tuple, and continues only on status0.
   It then sends the existing one-shot bind request. The child rejects that
   bind unless registration already succeeded. It must also require both
   `clientRegistered` and `instanceBound` before delivering the original peer.
   Before bind and each delivery it obtains and releases the registry's real
   retained nonempty title. This query rechecks the stored full token/current
   kernel PID version, so a sticky flag or recycled same-code PID cannot stand
   in for the live registered frontend.
6. A registration or transmitted binding failure, or timeout, cancels the private connection and leaves
   `ClientInstanceReady=false`. Existing inactive original caller handler/
   activation and final INVALID draining requirements remain. No code writes
   private libxpc object fields or forges an audit token/native connection.

The one-shot function rejects a zero UUID before any control message, and
rejects a second bind with EALREADY before another title/bind request. These
local precondition errors preserve an earlier genuine binding; they do not
masquerade as IPC failures or cancel a successfully authenticated connection.
Actual registration/reply/timeout and request-allocation failures still cancel
and invalidate the frontend generation without committing success.
One-shot and registration transactions each reserve a unique nonzero tag under
the transport lock before releasing it. One-shot owns registration through bind;
registration ownership covers bundle copying and allocation as well as IPC.
Counter exhaustion returns EOVERFLOW without sending or reusing a tag. Clear and
actual failure invalidate both reservations atomically with the generation.
The registration lock also rejects a competing caller with local EALREADY
without cancelling the first caller's in-flight transaction. The one-shot entry
checks both registration and instance reservations, and checks again before
allocating its instance request; therefore two callers which crossed the first
check cannot both bind. Actual failure cleanup changes flags only when both its
connection identity, reservation tag and captured generation still match the
current epoch. A completed failure cannot release a newly installed generation's
flag or a different transaction's reservation.

The transport and registry locks must never be held together while calling the
other component. A preparation flag plus an existing callback/lifetime retain
protects the server across configuration. Start/bind/stop reject a pending
preparation; the serial control queue orders registration, reply and bind. The
pending frontend request has independent caller/callback references, retained
native control and queue/semaphore storage, copied identity/nonce/title, and a
bounded reply deadline. Timeout cannot free callback-owned storage. Version7's
real final INVALID/queue-drain behavior remains unchanged.

Registry configuration is an immutable singleton with an own-process guard and
no reset API. A process which configured one server cannot Stop and Create a
different server/nonce/peer: Create returns EALREADY even after Stop. A fresh
service requires a fresh process. The committed-process flag also survives a
transport error after the underlying registry committed. Old registration flags
are never inherited by a new server or frontend generation, and late callbacks
may release their own storage but cannot commit a different generation.

The next local candidate should export version8-specific typed lifecycle and
diagnostic state APIs, with the exact original four XPC entry-point ABIs only
inside its private provider. It must strongly retain the unchanged bridge and
all existing security/factory dependencies. A new diagnostic uses only its own
anonymous endpoint and real parent/child processes. Its main-bundle metadata is
real diagnostic bundle metadata, not a synthetic replacement for production
frontend metadata. The diagnostic is kept separate from original VMM launch.

Required real tests: successful genuine parent title registration precedes bind
and original diagnostic handler delivery; live client query returns that exact
parent's retained string; registration missing, wrong nonce/type/peer, wrong
reviewed hash, changed title, malformed/rejected/late reply and timeout fail
without handler delivery; same-name registration is idempotent; unregistered
and reaped/recycled PID queries fail; independent private sessions do not merge
state; all owned endpoint/request/CF objects and exact child processes have
bounded cleanup. Original strict plugin/native Boolean gate denial stays denial.
No VM/CPU/GPU or operating-system service/registry/policy mutation belongs here.
