# Persistent Hibernate

The user's2026-10-23 priority is a saved VM session that survives App termination,
as requested in [upstream issue39](https://github.com/nfzerox/VirtualMacOniPad/issues/39).
Ordinary native pause/resume was already implemented; it does not persist RAM.

Current development build is App274/Runtime174/CPU98/GIC19/MD27/GPU24.
Normal317 restored a genuine completed save into a freshly launched App,
resumed native state2->1, and retained the original guest boot-session UUID,
PID648/start time and anonymous-memory-only nonce. Normal320 automatically
saved/stopped on an actual UIKit background event. Normal321 accurately
SIGKILLed only the idle App after all VMM/GPU processes had exited; the saved
state survived. This test exposed an unreachable auto-resume launch branch,
fixed in App274. Normal322 then reopened App274 without a start URL, found the
completed save, restored it and consumed the marker before native Resume.
The same original boot/PID/anonymous nonce was read again over SSH22222.

Normal323 exercised rapid real front/background transitions in App274 and
completed one2,818,576,384-byte save/stop/commit. Normal324 then SIGKILLed only the idle saved App79758 and reopened App274
without a start URL. App79859/VMM79861 restored paused state2, resumed state1
and consumed the saved marker. The original boot-session/PID648/anonymous
nonce matched again in normal324-background-kill-memory-after-v1. These are M2/iPadOS16.1.1 results,
not acceptance on other supported device/OS combinations.

The complete27runtime exposes the genuine `saveMachineStateToURL:completionHandler:`
and `restoreMachineStateFromURL:completionHandler:` methods. On Normal292,
App262 called `validateSaveRestoreSupportWithError:` on the actual creation
configuration. It returned YES with no error. Current disk/network/audio/GPU/
input/sharing/socket devices were retained. This is admission, not a successful
save or restore.

The first App261 diagnostic queried a nonexistent public VM configuration
getter and therefore had no configuration to validate. That negative diagnostic
was corrected by passing the actual configuration directly in App262.

App263 is the initial native save/restore execution candidate. Its HUD has a
Hibernate action. It pauses through the existing input-drain/native lifecycle,
saves into a new owner-only generation under the VM bundle's`.VM27HibernateV1`,
then calls native stop. Only a successful file write/flush and stop can publish
`Current.plist`. That record binds the runtime, VM options, machine identity and
current disk identity. A fresh VM start checks the saved record before choosing
restore rather than cold boot. A successful native restore lands paused; the
record is consumed before native Resume can change the disk. Restore failures
retain the saved state and report an error.

The framework's saved file contains encrypted guest memory. It is not logged or
included in the normal diagnostic archive. Apple's API binds saved files to the
original host and requires a compatible configuration. See the SDK headers and
[save documentation](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/savemachinestateto(url:completionhandler:)).

Manual native save/stop/relaunch/restore and anonymous-memory continuity
passed. Background saving, a per-VM switch, a Saved Session library label,
Resume action, confirmed discard action and English/Simplified Chinese UI are
implemented in App274. File ownership, truncation, symlink/path rejection,
stale-record rejection and directory flush were tested locally; native iPad
save and marker consumption also completed. Physical interaction of all new
library controls, lock-race stress and other device/OS combinations remain
additional acceptance work. An arbitrary
SIGKILL cannot execute a final save: background protection must complete before
termination. Do not promise recovery of unsaved changes after an interrupted
save or restore a state against a disk that has advanced independently.

## First actual save and current blocker

Normal293/App263/Runtime165 reached real native pause(state2), then submitted
the real save method at22:41UTC. The VMM PID75805 trapped in its original fatal
assertion atRVA0x40fe88, through the snapshot handlerRVA0x2a9adc. The specific
caller0x2ab760 is reached when SecItemDelete at0x2a9f4c returns neither success
nor errSecItemNotFound. The OSStatus itself has not been logged; do not claim a
specific numeric error was observed. No completed snapshot was produced and
the RAM continuity test has not passed.

The actual native query builder uses Secure Enclave keys and the fixed access
group`com.apple.Virtualization.snapshot.encryption.keychain-access-group`.
The existing15VMM entitlements lack that group. Runtime166 adds only that exact
group, leaving native VMM sections/imports and all CPU/GPU files unchanged;
146signed images and the runtime preflight passed locally. App264 carries its
manifest anchor. Its3-file/2-CDHash installation scope is frozen in
`hibernate-keychain-device-v241-attempt1/scope.json`.

The user explicitly approved this Keychain security boundary. App264/Runtime166
was installed at22:57UTC, with the exact3-file scope and2trust hashes. A new
actual save on Normal294 advanced past the earlier Keychain assertion and
then failed atRVA0x2fffb4: `hv_gic_state_create()` returned NULL. The current
CPU93 provider explicitly leaves GIC state serialization unsupported. This is
now the observed execution blocker; no completed snapshot or restored RAM
continuity is claimed.

CPU94 adds versioned, pointer-free software GIC capture/import. It records real
distributor and per-CPU interrupt/priority/active-stack state, rebinds CPU slots
by affinity, rebuilds indexes and drops transient caches. Host pointers, native
slots, epochs and thread identities are never serialized. Local tests cover a
round trip into reordered fresh CPU slots, active interrupt rebinding, immutable
capture, malformed/truncated data rejection and running-CPU refusal. Native
save/restore acceptance is still pending.

Evidence under the diagnostics directory: Normal292 native admission receipt,
`normal293-hibernate-vmm-crash.json`,
`normal293-hibernate-save-handler-full.txt`,
`normal293-keychain-query-builder.txt`, and the Runtime166/App264 candidates.

Sources: `vz/host/vm27_hibernate_native_v3.inc`,
`vz/host/vm_native_vm_pause_v6_hibernate_guard.inc`,
`vz/host/portable_app_v1/host/VirtualMacApp_complete_dual_v77_native_hibernate.m`.

## Native save passed, restore diagnosis

App265/Runtime167/CPU94/GIC19 successfully captured101096bytes of actual GIC
state, completed the native save, stopped the VM and committed a2751467520-byte
file plus Current.plist on Normal295. App PID76220 and VMM PID76225 ended their
VM session normally. Relaunch created App76348/VMM76353 and submitted native
restore against that exact file. Restore returned VZErrorDomain12, invalid
argument, after creating four vCPUs; no RAM continuity acceptance yet. The
snapshot is retained. This is persistent save proof, not complete Hibernate.

App266/Runtime168 adds GIC restore admission logs and the tested truncated-file
check. It blocks full13 cold start while a27state exists. A compatibility helper
admits only identical manifests or the exact167->168 diagnostic pair: the GIC19
and factory objects,26other CPU objects, original VMM instructions and every
other device file are unchanged. The proof is normal295-runtime167-to168-state-
compatibility.json. The encrypted saved file and Current.plist are not rewritten.
Native restore remains under investigation. Existing LLDB/debugserver attempts
did not obtain a usable stack and are not evidence about the restore failure.

On Normal297, unified logging emitted native error identifier
0x7c5e66f7000000ea. Static native control flow maps this exact identifier to
hv_gic_set_state failure atRVA0x300d08/0x300d18. App266's own log confirmed
size=101096, sizeOK=1, output-disjoint=0. The restore source is read-only input;
it must not use write/output-range exclusion. CPU96/Runtime169/App267 removes
that incorrect input restriction, retains finite mapped-readable validation,
copies the source privately and then performs the same stopped-engine format
and affinity checks. GIC19/factory/26otherCPU objects and serialized format are
whole. The exact Runtime167->169 compatibility proof is recorded separately.
Local Mach tests accept read-only pages and reject write access and unmapped
tails. Actual restore acceptance remains pending.

The next raw-call observation candidate is App268/Runtime170/CPU97. Only one
original VMM thunk instruction atRVA0x3a59a4 branches to the existing authenticated
capability stub. CPU97 recognizes a real original BL to that thunk in the exact
owned VMM image, then executes the original movx16,-5/svc80/ret once, in the same
process and thread. Ordinary capability calls retain their prior implementation.
No packet content is read; failure logs are capped at two per operation. All
GIC/factory/state objects remain byte-identical. This is observation, not a
change that makes unsupported kernel operations return success. Restore is
still not accepted. The first saved state remains protected and retained.


## Runtime171 restore boundary correction

Normal302's calibrated hardware breakpoint at original VMM RVA0x300d0c
observed actual hv_gic_set_state returning0xfae94003. Its same-run log showed
mapped-readable input but the restore transfer failed. CPU98 corrects the
remaining factory layer: restore input uses finite mapped-read validation;
capture retains the complete write/output exclusion boundary. The engine still
validates the entire versioned blob before mutation. Serialized GIC format and
all CPU register state objects are unchanged.

App269/Runtime171 was installed with unchanged App/VMM entitlements and a
7-file/4-hash scope. Normal304 imported GIC successfully even with the original
input's output-disjoint test false: factory readable=1, controller=1,
admitted=0, transfer=0; public status=0. The native restore still returns the
later generic VZErrorDomain1, so Hibernate is not accepted.

Normal305's bounded process debugger observed genuine PG
restoreWithSavedState:error: returning1 to VMM RVA0x152a08 and
willResumeWithSuspendState:error: returning1 to RVA0x147060. Neither return was
changed. These methods are therefore not the observed failing step. Subsequent
error-path diagnosis is in progress. The original2.75GB saved file remains
retained. Debugger disconnect messages alone are not native failure evidence.


## Native VMM exit and restore-only VT import

Normal312 compared the actual native XPC error singleton and identified
XPC_ERROR_CONNECTION_INTERRUPTED. A read-only process-exit observer on
Normal315 then observed VMM79032 exit with signal11, without a debugger;
no memory-pressure, code-signing or decryption exit flag was set. A nearby
non-fatal memory warning and RootDomain sandbox denial are not established
causes. No new system rights were added for those messages.

App271/Runtime173 repairs the old diagnostic log identity check: it validates
the existing owned stderr descriptor's path, owner, type, mode and link count,
rather than a stale device/inode pair. Its one-shot handler records registers
and restores the default SIGSEGV disposition; it never resumes faulting code.
Normal316 installed the handler and captured a branch to NULL with original
VMM returnRVA0xdf6c0. The preceding BL at0xdf6bc uses authenticated slot
0x4c62c0, whose genuine weak import is
VTParavirtualizationHostSessionCreateTerminateAllSessionsMessage. The missing
native VT host endpoint was already reported unavailable by the existing
Create/Deliver gate. The restore-only call had bypassed that gate.

App272/Runtime174 adds that third call to the same complete native endpoint
check. With no real endpoint, it returns unimpErr and a NULL message; it does
not invent a video session or a success result. When the complete genuine
endpoint exists, it forwards the call. Only the one import metadata row is
rebound to the owned provider; original VMM sections/authenticated pointer
words, CPU98/GIC19/GPU24 and serialized state layout remain whole. Local
signature/import/preflight checks passed; actual restore acceptance is pending.


## Background save and launch ownership

`vm27_hibernate_native_v12_relaunch.inc` starts a real background task when an
eligible macOS27 VM leaves the foreground. It waits for the existing lock-state
notification gap, then invokes the same native Hibernate sequence while the
device is unlocked. The new HibernateOnBackgroundEnabled option defaults on
for27; the control is unavailable on13 and changes apply at the next VM start.
This host-only option is excluded from saved native-device configuration
comparison. Corrupt non-dictionary options are rejected rather than copied.

Old foreground-transition callbacks cannot end the task of a newer transition;
expiration is bound to the actual task identifier. A failed/incomplete save is
never published as Current.plist. The metadata write is atomic, and state,
stage and marker-directory flush precede completed-save reporting. The restore
marker directory is flushed before Resume can advance the disk.

A completed save sets an owned pending-resume preference. App274 admits that
specific validated record through its independent launch branch and waits for
application-active before starting actual native restore. It does not consume
the older package's global auto-boot or installation request files. A failed
restore retains its file and does not cold-boot over it. The library offers an
explicit destructive confirmation to discard the saved RAM while preserving
the disk; only a stopped session's validated owned generation is removed.

Locking continues to use native in-memory pause: Apple's snapshot key policy
requires an unlocked device, and locked-device Hibernate is not claimed. A
save interrupted by arbitrary SIGKILL cannot preserve the latest unsaved RAM;
only a save that completed before process termination is recoverable. No new
Keychain or platform entitlement was added after the explicitly approved
snapshot access group. Public beta4-r1 has not been replaced with this work.


## Current accepted sequence

- Normal317: native restore of the first Runtime167 save after the GIC and VT
  fixes; original anonymous RAM nonce/PID/boot session retained.
- Normal318/319: a fresh Runtime174 save and App273 restore passed.
- Normal320: genuine UIKit background -> native pause/save/stop/commit passed.
- Normal321: completed save survived accurate idle-App SIGKILL; this exposed
  the old independent-launch early return, without losing the saved file.
- Normal322: App274 active-launch fix automatically restored that retained
  state, with no start URL; original anonymous RAM continuity passed.
- Normal323/324: same-build App274 rapid foreground transitions -> one real
  background save -> idle-App SIGKILL -> automatic reopen/restore passed.
  Original guest boot UUID, PID648/start time and RAM-only nonce retained.

The final running development session is App274/Runtime174, App79859 and
VMM79861 at01:56UTC. The old committed generation was consumed, not left
available for a later stale-RAM restore. Guest SSH22222 still works. The
original VM disk/model/identifier were retained throughout. Full-process
background save takes several seconds; the12-second observer windows are not
measurements of exact save duration. No iPad reboot was required.


Beta5 final-package follow-up (2026-10-23): App275/Runtime175, native save2751467520bytes, App death after completed save, no-URL reopen/automatic restore, original anonymous-RAM/process/boot-session continuity and consumed-marker checks passed. The test probe was cleaned and the guest left running.
