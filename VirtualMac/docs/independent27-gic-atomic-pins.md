# Physical timer callback completion pins

GIC12 / CPU76 keeps IRQ arbitration under the same native unfair lock. The
physical timer batch previously reacquired arbitration after its native boundary
and deadline scheduler solely to release callback pins and publish owner-local
completion state. Actual Normal194 and Normal198 native profiles show this hot
path competing across four vCPUs.

Callback counters are now native lock-free 32-bit atomics. The actual boundary
and scheduler still execute outside the arbitration lock with both lifetime pins
held. On completion, the owning thread publishes `deadlineQuiesced`, releases
its CPU pin, then releases the controller pin last. Reset/destroy cannot observe
zero controller callbacks before preceding completion writes; owner-only detach
and quiesce still refuse a pinned attachment. Identity, generation, priority,
affinity, pending interrupts, native return values and deadline scheduling are
unchanged. The other 28 linked CPU objects and original native imports are whole.

Validation before installation included actual IRQ/state differential checks,
native-boundary failure, reentrant closing, four-owner concurrency and concurrent
reset. The ordinary run passed 53,806 checks; ThreadSanitizer passed 54,486 checks
(the concurrent observer makes totals variable). Actual iOS strict compilation,
linking, 155 export names/kinds, four native loads and unchanged import semantics
were verified. The 800,000-operation four-owner host benchmark is recorded under
`gic12-host-atomic-pins-v1/benchmark-results.json`; it is not a guest speed claim.

Runtime133 / App187 was installed as Dev174 (seven own files, four new trust
hashes, same permissions). Normal198 actual start returned zero with native
advancing frames and explicit ownership ACK/COMMIT. Native USB after login showed
complete General main/sidebar icons, wallpaper, menu bar and Dock. The original
user icon service remained PID615, runs1, never exited at 03:45:23 UTC. The
existing two user-native graphics compatibility options remained zero.

Startup remains incomplete: first frame appeared between 41 and 46 seconds in
this diagnostic boot, which included one three-second native stack sample.
Complete Ready within approximately 30 seconds is not proven. The actual sample
still shows contention at physical-route entry, virtual-timer routing and
aggregate line reads. This patch removes completion reacquisition; it does not
claim to eliminate all GIC contention or solve cold-login latency.

Evidence under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

- `cpu-gic-atomic-pins-source-local-v76-attempt1/`: source delta, actual build,
  unchanged objects and native interface evidence.
- `gic12-host-atomic-pins-v1/`: host checks and benchmark.
- `independent27-gic-atomic-pins-device-v174-attempt1/receipt.json`.
- `independent27-app187-gic-atomic-pins-normal-guest-lifecycle-v198-attempt1/`.
- `normal198-native-boot-phase15-symbolized-v1.txt`.
- `independent27-guest-normal198-cold-native-gui-job-v1/receipt.json`.
- `independent27-vnc-input-v38-normal198-gic-atomic-pins-gui-v1/`.

Native pause completed with state2, sameOwner1, nativeError0 and verified1 in
`independent27-normal198-native-pause-after-cpu76-v1/receipt.json`. Resume completed with state1, sameOwner1, nativeError0 and verified1 in
`independent27-normal198-native-resume-after-cpu76-v1/receipt.json`; the guest
clipboard agent reconnected with actual HELLO. Subsequent normal shutdown was
confirmed by the native guestDidStop callback and exact App/VMM/GPU cleanup in
`independent27-normal198-before199-off-v1/receipt.json`. Broader
GUI, physical input, audio and advanced GPU features retain separate acceptance
requirements. Publication remains deferred.
