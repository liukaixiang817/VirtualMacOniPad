# Owned startup coordinator v2

This independent version connects V1's ordinary preparation and cleanup contract
to V9's typed parent configuration and actual Large consumer interface. V1 and
all its source snapshots and outputs remain unchanged.

`VM27OwnedStartupConfigurationV2` contains the V9 parent configuration plus the
nonzero bootstrap nonce. Format/PID/kind and the selected branch's string shape
are checked before the one-process attempt is spent. All configuration and
selected borrowed strings must remain stable for the full synchronous call.
The coordinator then calls the real V9 `CreateServerWithParent`; no caller's
validated-result Boolean exists. V9 itself performs the file/slot inspection.
The state reports the expected PID from this trusted typed parent configuration.

The exact original V1 real main-CFBundle CheckIn input, same provider singleton,
retained-state verification, serial queue ownership, control routing and cleanup
lifetimes remain. Stop does not release the context. Release still requires the
actual external control channel's final INVALID and queue drain, and the absence
of all existing, pending, future or concurrent context calls. Partial failures
retain their owned context for explicit cleanup; an attempted process is not
silently reset.

The parent factory accepts only a `VM27LargePrivateServiceConsumer *` and routes
the exact received hello to V9. It does not reinterpret a small consumer, select
a policy mode or populate missing native facts. Large strict mode's absent outer
kernel CDHash therefore remains a real fail-closed EACCES limitation. A flat
parent's file-owner validation, seal metadata and false whole-resource/native
flags do not become permission to run or a peer identity claim.

V2 neither starts the service nor invokes Main, original handlers, CPU or original
frameworks. Only one V9 provider graph belongs in a fresh process; V1/V8 state
cannot be mixed into it. Local state tests use explicit transport doubles and
two actual private CheckIn state instances for rejection checks. Those tests are
separate from real V9 fixture integration and do not claim bundle-reader,
Large-consumer, native Boolean, iPad or guest-boot execution.
