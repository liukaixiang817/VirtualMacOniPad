# Explicit approved-code message gate

This opt-in app-private gate authorizes only one explicitly approved executable
CDHash and full-file SHA256. It does not alter the original strict LWCR module,
the OS signature-validation flag, trustcache policy, system libxpc or launchd.
It exports scoped `VM27ApprovedCode*` APIs; no original XPC registration symbol.

Creation verifies the actual caller-owned executable. The bounded parser accepts
thin arm64 `MH_EXECUTE`, one UUID, SHA256 ad-hoc CodeDirectory20400,12/14-bit
pages, no scatter table or external bundle-resource hashes. It checks every
code page, embedded requirements/XML/DER entitlement slots, exact authenticated
file SHA and CDHash, and an authenticated Boolean true plugin entitlement. Both
hashes must be supplied explicitly by the approving caller. These pinned hashes
must come from a reviewed manifest in production; accepting arbitrary peer input
as the approval list would defeat the intended security boundary.

For each actual received XPC dictionary, the gate first rechecks the approved
file's identity/content and calls the unchanged native LWCR policy. It then
reads **that message's** kernel audit token and uses read-only
`csops_audittoken(pid,CS_OPS_CDHASH,buffer,20,&token)` and `CS_OPS_STATUS` queries.
The kernel validates both PID and PIDversion, preventing reuse of an old PID.
Approval requires the actual process CDHash to match, dynamic `CS_VALID`, and
the unchanged policy's SecTask to have copied an actual Boolean true entitlement
without error. A caller's message body or cached connection PID is not authority.

This is an explicitly authorized-code compatibility route when an ad-hoc,
app-private program's restricted entitlement is not system-validated. It does
not report that the original strict native policy passed. Both outcomes are
reported separately. An otherwise identical program with Boolean true and an
unapproved signing identifier/CDHash must still be denied.

ABI provenance is pinned Apple `xnu-8792.41.9`, `bsd/sys/codesign.h`:48/72 and
`bsd/kern/kern_proc.c`:3170-3233/3331-3352, in
`xpc-approved-code-v1/official-source-v1`. The kernel's20-byte code hash query is
not restricted to Root but remains subject to the MAC policy; query errors fail
closed. The scoped module does not request new kernel permissions or mutate
process code-sign flags. Exact SecTask prototypes and original27 query are the
previously validated strict-policy module's contract.

Local `build-v3` actual Mac execution passed833checks/0,128 concurrent complete
CodeDirectory verifications in4 joined workers,8 page/XML/bounds/format negative
controls, and64 real messages queried through the actual kernel ABI. Its sender
is not the approved iOS true executable, so66 checks (one spoof, one altered own
clone and64 messages) all reject; no application handler runs. The only file
modified is an owned temporary executable clone, which is removed afterward.
The actual approved input, self executable and libraries are not changed.
Mac true-signature runs remain skipped after the previously proven AMFI refusal.

The five same-payload iOS controls are missing/false/integer/true and
true-unapproved. The last control isolates the CDHash constraint while keeping
Boolean true. The two libraries have empty entitlements; CLI permissions remain
the four platform/no-container/no-sandbox/can-execute-cdhash markers, with only
the declared plugin value changed. No get-task-allow/HV/GPU entitlement is added.
Actual iPad runs subsequently passed and were independently revalidated in
`xpc-approved-code-v1/native-five-verification.json`:missing/false/integer/true/
true-unapproved PIDs34652/34831/35010/35189/35368 each observed wait0/reaped/absent,
4227checks total. True approved code accepted64 real messages and rejected the
unsigned spoof and altered file. True-unapproved had an actual native Boolean
true but rejected all64 messages because its real kernel CDHash differed.
The other variants also rejected all messages. Across5 runs,320 real kernel
CDHash/status queries and320 SecTasks completed,20 workers joined and owned
temporary files were deleted. Strict SecTask validation remainedfalse in every
case; the opt-in explicit authorization did not change that system result.

This gate is not yet coupled to the registry's plan, a spawned child or an actual
cross-process endpoint handoff. Every eventual application message must consume
the approved plan through this gate before invoking the genuine service handler.
No complete originalVMM load or macOS27 guest has been executed by this module.
