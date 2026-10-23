# GIC18 wake-notification subset optimization

Development candidate: CPU93 / Runtime163 / App257,2026-10-23 local.

`WakeAttachedMaskV15` formerly computed complete IRQ/FIQ priority arbitration
and then evaluated `(lines.irq || lines.fiq || WakePendingV30(...))`.
Every IRQ/FIQ selected by `Lines` already requires an enabled, pending interrupt
routed to that CPU. `WakePendingV30` covers that full set, and also covers work
which must wake WFx even though PMR, group/preemption, active or sleeping state
prevents injection. The notification condition is therefore exactly the
existing `WakePendingV30`, without the redundant priority walk.

The patch changes only this notification condition. `Lines`, `Highest`, actual
IRQ/FIQ injection, CPU ownership/running exclusions, attachment/closing checks,
callback pins/error propagation, timer/deadline and snapshot rules are unchanged.
The full preceding source is preserved as GIC17; GIC18 is a separate versioned
source. No structure, public API, imports, or exports were added or removed.

## Validation boundaries

-12000 randomized controller states and4 CPUs:168000 checks cover the subset
  relation, actual notification masks, callback failures and drained callback
  pins. Random cases include priorities, groups, sleeping/closing, active
  interrupts, private/shared routing and extra enable-index bits.
- The existing real four-owner pthread fixture passed246 checks of local ICC,
  private/shared EOI, SGI targeting, running-owner exclusions and callback errors.
- The existing timer/snapshot/four-owner concurrency fixture also passed.
- The actual portable provider replaces one GIC object and preserves28 other
  CPU objects. Export flags, imports and load semantics match the preceding CPU.
- Local notification microbenchmarks exercise synthetic sparse/dense pending
  states. They measure this helper only and are not whole-guest speedup claims.

Evidence under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:
`cpu-gic-wake-subset-v93-attempt1/`,
`independent27-signed-runtime-gic-wake-subset-v163-attempt1/`, and
`complete-dual-signed-app-v257-attempt1/`.

## Device trial

Normal284 CPU92 baseline used20 actual Mission Control key toggles spaced650ms
apart,with the same temporary input server limited to1 screenshot/second.
Its12.593-second finite window delivered910frames. Native arrival gap p50 was
11.728ms,p95 was23.369ms,max was84.415ms,with20 above33ms. Host CADisplayLink
p50 was8.338ms,max9.084ms; measured main-to-submit maximum was.196ms.

The baseline is under `ipad-gated-native-profile-normal284-gic18-before-mc-frames-v1/`
and `independent27-vnc-input-v53-normal284-gic18-before-and-after-v1/`.
The new seven-file/four-hash installation is backed up by the exact scoped
controller in `gic-wake-subset-device-v234-attempt1/`. Installation completed20:03:51UTC and Normal285 booted with AppPID73717,
VMM73722. The first matched20-toggle frame sequence delivered779frames in
12.015seconds: arrival p50=14.963ms,p95=31.785ms,max=147.476ms,33 above33ms.
Host callback p50=8.337ms,max=9.094ms and main-to-submit max=.193ms.
This cold run was worse than the preceding warm baseline; no whole-guest
performance gain is established. The official boids simulation had restarted
with a different particle distribution, and the original icon service had
crashed during this cold boot. These differences prevent attributing the whole
frame result to GIC18. The actual source-level redundant-work removal remains
separately proven; the user-visible pacing issue is not solved.

After evidence: `ipad-gated-native-profile-normal285-gic18-after-mc-frames-v1/`.
Guest Tools and all three original native graphics preferences still matched
at20:06:07UTC; a new original service crash report has been preserved as
`independent27-guest-root-normal285-new-icon-crash-v1/`.
The fault is `CGSImageDataHandleRelease+24` via cache eviction, invalid0x151,
which also occurred in earlier runtimes before this GIC optimization.

The parallel VMM/GPU profiler experiment records identical native timestamps
06:57:52.079–55.082. Keyboard input began06:57:54.116,so only its final second
covers the animation. Guest samples cover06:57:54.286 onward. These are useful
stacks but are not a complete synchronized3-second bottleneck comparison.
The subsequent finite frame comparison is the relevant regression observation.
