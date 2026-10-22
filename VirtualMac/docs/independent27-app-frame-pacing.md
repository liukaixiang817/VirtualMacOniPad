# App and display frame pacing

The user clarified on 2026-10-22 that Safari and other Apps already work; the
remaining problem is stutter and dropped animation frames. Opening a web page,
HTTPS success, or low idle CPU is not performance acceptance.

Normal244 used Runtime151 / App214. A local finite Safari page continuously
scrolled text and colored rows for12 seconds while a CSS transform animated.
The actual visible Safari document reported721 rAF intervals over12,001ms:
p50=17ms, p95=17ms, maximum31ms, zero intervals over33.5ms or50.5ms.
Viewport1366x829, guest screen1366x1024, scale2. This tests the guest browser's
animation scheduling, not iPad presentation cadence or real trackpad latency.
The first title read encountered the guest's normal Safari automation consent;
it timed out and is not the result receipt. After the actual consent UI was
handled, the native document title read returned the metrics above.

App215 adds an opt-in12-second metadata capture, maximum four per process,
using fixed2048-row storage. It records original nonempty frame arrival,
UIKit delivery, transaction submission, CA callback and the existing main ACK.
It does not copy pixels, change IOSurface leases, alter readiness, acknowledge
a frame earlier, or log each frame. Timing is dormant unless the exact running
VM/display owner admits the own frame-timing URL. Native frame spacing and CA
completion are explicitly not physical display FPS.

Next: correlate active Safari scrolling and actual calibrated window dragging
with this capture. Profile the specific producer/CPU/GPU path if arrival stalls,
or the App main queue/transaction path if display delivery stalls. Preserve the
manually accepted startup behavior and avoid unrelated cold boot benchmarks.

## Apple website reproduction

Normal245 / App215 / Runtime151 also tested the real Apple.com page with
repeated vertical scrollbar motion, after native USB calibration confirmed
both scroll direction and thumb coordinates. The original40Hz test helper was
a limiter and is not treated as evidence of a rendering ceiling. A revised
absolute-deadline helper sent1080 real pointer packets in9.327 seconds, with
within-drag intervals p50=8.316ms, p95=9.934ms, max=10.700ms. This exercises
real guest scrolling but does not reproduce the physical Magic Keyboard
finger/momentum stream.

The12-second native capture overlapping that input recorded490 frames,
489 intervals, p50=16.775ms, p95=34.232ms, max=67.253ms, and48 intervals over
33.5ms. The window includes short idle periods around the nine-second gesture;
these aggregate counts are not a physical display FPS measurement. Arrival-to-
main p95=.021ms, main-to-submit=.110ms, submit-to-CA-callback=.112ms,
callback-to-main=.005ms. The stalls are already present before UIKit delivery.

A subsequent observer-affected, three-second native VMM profile during the same
high-rate Apple.com input recorded2.944 CPU seconds. Its display PGFifoThread
spent0.598 CPU seconds, including a large stack under native PG+0x27b90
creating an IOSurface-backed Metal texture. The strict handshake observation
also still walks Mach metadata on each call. A separate three-second actual
GPU-child sample completed. These are concrete optimization targets, not proof
that one call is the sole cause of all stutter.

The bounded texture-view cache experiment (Normal247 / Runtime153 / App217)
was rejected. It actually matched native RGBA16Float surfaces and recorded
at least7168 hits, but the same-page capture recorded368 frames, p95=34.712ms,
max=79.393ms and91 intervals over33.5ms. Main/CA stage p95 stayed below.153ms.
This is one short comparison, with content/warmup variation, and not a broad
statistical result; it establishes no scrolling improvement and suggests a
regression. Restore the previously signed Runtime151 / App215 before further
profiling. Do not ship either experimental surface-cache provider.

Normal248 restored Runtime151 / App215 and reproduced the real Apple.com
scroll with430 frames, p95=34.600ms, max=67.331ms and40 intervals over33.5ms.
The subsequent concurrent three-second guest profiles explicitly matched
Safari's responsible PID and excluded unrelated software-update WebKit jobs.
WebContent main was in its normal run-loop wait in203/215 samples. The active
GPU remote-rendering queue was in its semaphore wait in262 samples. Safari's
UI/scrolling profile also completed separately. WindowServer used original
Metal composition, with occasional IOGPU submission waits. These snapshots
show no sustained JavaScript saturation; they do not identify a sole cause.

Runtime154 / App218 removes repeated executable-path and Mach image UUID
walks from the owned display observer after full admission. A bounded16-record
process-local cache holds immutable PID/dyld-generation/image-base records.
Every dyld add/remove invalidates old records; fork PID mismatch and capacity
saturation fall back to full admission. Fresh UID/eUID, PID, code-sign flags,
native Metal profile, exact caller, receiver class, method argument/return
types and original IMP checks remain. Native textures, GPU commands, present
and completion ordering are unchanged. Concurrent-reader, fork, invalidation,
stale-publication and saturation tests pass with ASan/UBSan. Actual iOS link,
namespace closure and signed product checks passed. The first post-login sample had351 frames and92 long intervals and is not
accepted as an improvement. Later, in the same App/VMM process, a1FPS remote
observer produced425 frames/50 long intervals; restoring5FPS produced479
frames/46 long intervals, p95=34.563ms and max=67.452ms. This is close to the
original490-frame/48-long-interval baseline. There is no demonstrated overall
Safari improvement and no clear warm-state regression. Changing observer
frequency alone does not explain the stalls. A subsequent native profile no
longer sampled repeated Mach UUID reads on the display path; it still sampled
native IOSurface texture creation and native display synchronization.

These scrollbar tests cover rendering under real page motion, not the physical
trackpad stream. The actual27 input queue batches at60Hz but currently preserves
every changed pan packet separately, unlike adjacent pointer motion. Next:
coalesce only adjacent pan changes by summing deltas, preserve every lifecycle
and input edge, and add a bounded own scroll diagnostic through the same copied
packet/native VZ sender path. No synthetic test is physical gesture acceptance.


## Copied-pan comparison candidate

App220 uses Packet5 to sum only adjacent, unleased pan changes. The newest
sequence, position and receipt timestamp are retained. Began, ended, cancelled,
key/button events, generation changes and acquired leases remain barriers.
An out-of-range sum falls back to separate packets. The prior pointer-motion
regression checks and scroll distance/lifecycle/lease checks pass (268 checks)
with AddressSanitizer and UndefinedBehaviorSanitizer.

A development-only own URL can run a finite copied-pan sequence through the
same adapter, queue and original VZ sender as the actual scroll route. It
requests120Hz but records actual callbacks, lasts7.5 seconds, allows at most
three runs per surface, and cancels on real input or teardown. A10-second
process deadline cancels an overdue test; if iPadOS suspends the App, the first
overdue tick cancels on resume rather than delivering late scroll input. The baseline route disables pan merging only on an empty, unleased queue;
it automatically restores the default policy on finish/cancel. Zero-delta
terminal cleanup is also allowed after the App becomes inactive. It never creates
a UIKit hardware event. Same-session baseline/merged comparison is pending.
The remote screenshot server must be stopped before either timed sequence.


Normal250's first finite pan run published903 packets,901 actual callbacks in
7.506 seconds (maximum callback gap8.514ms), terminal and policy restore both
returned OK, but the native frame window received zero frames. The merged run
also produced zero frames. This is not scrolling performance acceptance. A
native guest cursor snapshot confirmed the real cursor at(666.488,524.496),
inside the actual Safari document. The first guest scroll-only tap worked but
its nine-second observation did not overlap the second host trigger; its zero
event count therefore does not establish lack of delivery.

The current primary is native Mac trackpad with an auxiliary USB pointer.
The owned Mac HID monitor still reports disabled event translators. Next is a
config-only USB-primary comparison, retaining the native trackpad auxiliary,
with the same App220 and Runtime154. This tests device routing before further
rendering optimization. Restore the user's original choice after the causal
trial or explicitly implement the needed original scroll sender selection.

The finite copied-pan routes are development instrumentation. They must be
compiled out or require a fresh, private one-time admission before any beta3
release; they are not a product-facing control API.


Normal251 changed only the primary pointer to USB, retaining the Mac trackpad
auxiliary. The same finite pan sequence still produced no native frame arrivals.
A correctly overlapping18-second guest scroll-only tap also reported zero
scroll events. The original MacTrackpad plist was then restored byte-for-byte
(SHA256 e1f0319402112d75c0aec2230bea0f5730c2dfa9d3cf847903e32245566d0ba2).
This config experiment is not a product change.

The actual consumer log confirms that its first64 calls entered the original
VZ scroll sender and returned OK. The902 producer publications are not proof
that all902 reached the sender or guest. Inspecting the consumer found no
settings bypass. The copied UIKit pan path did, however, pass screen x/y
directly to the private wheel constructor, unlike the established full13
screen mapping (-y,x). App221 applies that mapping only to copied UIKit pans;
native HID getter inputs retain their original order. A targeted host check
covers vertical/horizontal/reversed deltas, lifecycle, rejection without output
mutation and native HID separation under ASan/UBSan. Device delivery and
performance acceptance remain pending.


**App221 axis experiment rejected.** The user immediately observed physical
vertical two-finger scrolling becoming horizontal. The full13 constructor
mapping was not a valid assumption for the actual UIKit recognizer coordinate
convention. The host tests verified an assumed transform, not physical device
semantics. No finite pan test was triggered in Normal252. Roll back the exact
already-trusted App220 main and retain the original recognizer/VZ mapping.
Do not ship the copied-pan axes header, receiver3 or App221 builder.


## Beta4: cursor-only refresh activity

The user reports intermittent pointer lag accompanied by a sharp refresh-rate
drop. Beta3 App241 / Runtime155 was retained as the published baseline. A
12-second desktop Mission Control capture delivered279 frames, with producer
gap p95=19.736ms and max422.270ms; its650ms trigger spacing includes static
intervals and cannot establish a rendering ceiling. Arrival-to-main p95 was
.027ms, main-to-submit .087ms, CA callback .118ms and callback-to-main .005ms.
The first earlier window was the guest idle/login screen and is excluded from
Mission Control acceptance.

Inspection found the host CADisplayLink activity deadline updated only by full
IOSurface frames. Genuine guest cursor updates use a separate callback and
never refreshed that deadline. A synchronized9.345-second cursor-only sequence
sent1080 pointer moves (actual interval p50=8.280ms,p95=11.280ms,max=12.438ms).
Its actual finite window4 received no full-frame arrivals and no host refresh
interval summary. Inspection of the native after-screenshot shows that the
guest cursor did not leave its prior position: remote move packet publication
was not established as genuine guest cursor delivery. This experiment is not
a valid cursor-refresh acceptance result. The missing activity update is a
source-level defect; it still requires a real cursor-callback comparison and
does not establish that every reported stall shares this cause.

App242 / display16 adds the same existing activity wake to genuine cursor
updates. Guest-authoritative position/hotspot, IOSurface ownership, native
completion/ACK order, selected60/120Hz policy and quarter-second idle stop are
unchanged. Compiled/signed candidate passed and App242 was installed as a one-file
development update; unchanged15 entitlements and Runtime155 were retained.
No Beta3 release artifact is replaced by this development candidate.

Read-only guest sampling showed no swap use, load average0.63 at that instant
and no new crash reports in the sampled20-minute window. Host pressure state
was1; these snapshots do not rule out transient CPU, GPU or memory stalls.

The corrected device test uses the guest public CoreGraphics cursor-warp API
for9 seconds and reads the actual cursor location18 times. All18 matched the
requested points, and the original cursor position was restored. It does not
generate keys/buttons, change accessibility permissions, or test physical
Magic Keyboard forwarding. The exact temporary guest helper was removed.

App242's synchronized12.092-second host window received one full-frame update
and1108 CADisplayLink intervals: p50=8.337ms,p95=8.479ms,max=8.758ms,zero above
33.5ms. Thus genuine cursor-only activity now keeps the selected120Hz host
reservation alive even without full-frame updates. These are refresh callbacks,
not physical panel FPS or an old/new measured end-to-end latency claim. The
invalid remote-move baseline is excluded. Other transient rendering/input stalls
remain under investigation; overall smoothness is not marked complete.
