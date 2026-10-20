# Owned startup coordinator v1

This ordinary user-space module prepares an inactive private V8 service. It is
not an original VMM launcher, framework closure, native CPU implementation or
guest-boot proof. Existing V8, CheckIn and their frozen candidates stay unchanged.

The actual original VMM calls `_LSApplicationCheckIn` at RVA `0xbfac` with the
borrowed result of `CFBundleGetInfoDictionary(CFBundleGetMainBundle())`. It ignores
the return. Its `_xpc_main` call at `0xc04c` passes the original C handler. The
original VZ VirtualMachine path at `0x153ff4` creates a connection, binds a real
stack UUID at `0x154014`, then installs its callback and activates. No getter call
was observed in these consumer images. The coordinator adds none.

`ChildPrepare` takes explicit reviewed parent path, SHA256, CodeDirectory hash,
expected PID and nonce. It checks the actual main bundle through the existing
private CheckIn helper, owns a retained five-field state record, and verifies its
current PID/UID/CFUUID and actual bundle information. This is a private process
record, not an OS LaunchServices ASN. The eventual original CheckIn import must
use this exact provider singleton; linking a separate copy is not equivalent.

It creates an actual serial dispatch queue, calls unchanged `CreateServer`, then
`RequireServerInstance`. It returns the existing three-field endpoint hello.
It does not call `StartServer`, since original `_xpc_main` performs that step;
starting early would cause its EALREADY exit. It does not send a hello or guess
control activation state. The caller owns its real child/parent control channel,
obtains the retained control queue, sends this hello, and waits for its actual
authenticated factory acknowledgement before proceeding. Merely obtaining a
hello is not acknowledgement or authority to execute an original service.

The child routes original received dictionaries on that actual serial queue:
only exact title-registration and one-shot-bind methods are accepted. The
unchanged V8 gates recheck real native peer identity and return owned replies.
The caller sends any returned reply over that same actual incoming connection
and releases it, including refusal replies. Unknown/application methods are
not handled here. The coordinator introduces no original handler wrapper.

The parent wrapper requires exactly `serviceEndpoint`, `serviceIdentifier` and
`nonce`, with native types and expected values. It then calls unchanged
`InstallClientFactoryMessage` on the actual registered consumer. It never takes
a PID, token or code identity from a message body. The small-consumer interface,
unchanged parent inspector's 2 MiB bound, genuine entitlement Boolean and original
policy remain. Larger actual code needs separately reviewed integration; this
module does not weaken limits or bridge large and small consumer state.

The current production frontend's binary size is below 2 MiB, but its nonzero
CodeDirectory external Info.plist/CodeResources slots are unsupported by the
unchanged embedded-only inspector; it returns ENOTSUP. The actual original VMM
is 5,195,312 bytes (about 4.955 MiB) and exceeds this small-consumer capacity. Neither issue is resolved
by the coordinator. The older large transport lacks V8's registration gate and
cannot be substituted as equivalent. These are explicit integration blockers,
not permission or policy errors to suppress for a test.

A validated preparation attempt reserves the process once. Partial preparation
returns an owned context even when the hello cannot be returned. A committed
registry cannot be reset; a new attempt needs a fresh process. Preparation's
outputs are not accessible concurrently before the call returns. The caller
keeps the original configuration's strings live and unmodified for that call.
Fork children reject inherited state before touching inherited mutexes.

`ChildStop` closes new control admission, then calls the existing bounded service
stop off its queue. In-flight control calls, another stop, timeout or wrong queue
retain context/endpoint/queue for retry. A successful service stop proves only
its listener's final INVALID and barrier. It does not prove the external control
connection stopped. `ChildRelease` is separate and requires the caller to cancel
and receive final INVALID for that actual external channel, drain its queue, and
prevent all future/concurrent context calls. That ordinary lifetime prerequisite
is not a supplied success Boolean. Underlying providers must not be unloaded
while their own inactive-listener rollback or late callbacks may remain.

The local test links explicit transport test doubles to validate state ordering,
refusal handling, real CoreFoundation CheckIn state and cleanup retry. Its real
anonymous XPC endpoint belongs only to the test. These tests do not authenticate
an original consumer, execute V8 gates, execute an original VMM/VZ handler,
establish native iPad readiness or prove the whole backend. iOS validation is
compile-only; no new device probe, signing, deployment or trustcache occurs.
