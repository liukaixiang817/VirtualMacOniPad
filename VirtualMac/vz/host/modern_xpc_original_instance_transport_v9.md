# V9: typed parent inspection and large owned child

This new provider derives from the frozen V8 source. Its graph replaces V8 for
one fresh owned process; the old graph stays a reference. Do not load V8 and V9
as competing default original-XPC exports or mix their typed state. Precise
original-consumer import routing and complete VMM/VZ/CPU closure remain separate
prerequisites. No original framework is executed by the source derivation.

`CreateServerWithParent` requires format version 1, a trusted expected parent
PID and an explicit kind. All selected configuration strings must remain live
and unmodified throughout the synchronous call. Invalid selection does not read
the other union branch. There is no caller-supplied validated-result flag.

The `CodeOnlyDiagnostic` branch retains V8's exact bounded 2 MiB `ParentFile`
implementation and embedded-slot rules. It is reserved for an explicitly owned
code-only diagnostic and cannot substitute for a production bundled frontend.

The `FlatBundle` branch directly calls `VM27BundleParentInspectV1` on the actual
canonical flat bundle with the explicitly configured file owner. Required real
Info.plist/CodeResources external slots, every code page, embedded slots, file
descriptor/name stability and executable-name match must pass. It checks the
actual returned SHA/CD/owner and validation fields before storing the returned
CD in the server. An error has no fallback to the diagnostic reader. File-owner
validation is not a native peer-eUID claim. In the actual iPad installation,
trusted configuration must use the physical canonical path rather than following
`/var/jb` and must use the observed file owner, not assume the frontend UID.

The reader only validates the resource seal's metadata, not every resource it
describes. Whole-resource, Apple Security chain and native Boolean fields remain
false. Inspection and the new separate inspection statistics do not authorize
execution. An owned local flat data mirror of a normally signed Mac bundle can
prove those files' slots and byte identities; it does not prove that the mirror
was the running CFBundle or has a valid whole-App signature. Native peer PID,
PID version, current kernel CDHash/CS_VALID and both genuine entitlement Booleans
are still checked independently by the unchanged transport gates.

The client factory accepts only `VM27LargePrivateServiceConsumer *`. It checks
the original received three-field endpoint hello, calls the actual large
consumer's message gate and copies that same consumer's live child state. The
large registry's executable limit is 8 MiB; the parent reader remains 2 MiB.
There is no cast or adapter from the small opaque consumer, and V9 never selects
or changes a consumer policy mode. Large native-strict `CheckMessage` currently
does not return a kernel CDHash in its outer approved-code result. Even if that
strict gate returned success, the unchanged factory's mandatory Hex check would
reject it with EACCES. V9 does not populate that missing field from reviewed
bytes, metadata, a message body or an assumed hash to make it pass.

The four original C ABIs are retained. The original transport, registration
stats, true title-registration then one-shot binding order, immutable peer/nonce,
live registered-token query, typed ACK, callback ownership, epoch reservations
and bounded Stop/final-INVALID cleanup remain the V8 implementation. The parent
inspection result has its own typed stats struct; it is never appended to the
old stats layout. Filesystem inspection occurs without the transport lock, and
the original concurrent publication and inactive-listener rollback still apply.

Ordinary local fixtures and compile checks cannot establish original VMM wire
compatibility, genuine capability acceptance on the iPad, original handler
execution, native CPU progress or a fully independent macOS27 guest boot.
