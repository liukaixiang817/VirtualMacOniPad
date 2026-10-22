# Independent27 trackpad gestures

Surface13 adds a separate hardware-trackpad contact path. A UIKit scroll pan
has zero UITouches, so requiring three UITouches does not identify a Magic
Keyboard three-finger swipe. Surface13 copies `_trackpadFingerDownCount` only
from a real UIHoverEvent delivered to its active own input window. It keeps no
UIEvent/HID object and installs no global HID monitor or SpringBoard hook.

A three-contact hint must be fresh when the actual scroll pan begins. Only
that sequence is consumed for a one-shot Control-arrow action. Ordinary
two-finger scrolling remains on the existing adapter. Changing to a different
nonzero contact count cancels the shortcut; a normal lift before the final pan
packet is allowed. Small/ambiguous movement, invalid values, cancellation,
stale contact hints, inactive windows and held hardware keys do not trigger a
shortcut. Pause/close/layout recovery resets this scalar state. Direct-screen
three-finger swipe recognition remains separate.

The source classifier test checks ordinary scroll admission, one-shot behavior,
stale hints, contact changes, lift, cancellation and invalid values. App212
recompiled only object17; all other38 App objects and all Runtime150 bytes are
whole. It has no added strong imports. Device195 installed the single App file,
then Normal241 booted, logged in and displayed wallpaper and Settings. Native
USB-calibrated pointer movement and a real Settings-window drag completed.

These remote actions do not reproduce physical Magic Keyboard multi-contact
events. The current evidence does not yet establish that iPadOS delivers the
required three-contact hover/scroll sequence. Actual physical three-finger
up/left/right acceptance remains open; do not mark it complete from host tests,
a keyboard shortcut, VNC input or compilation alone. The bounded contact/swipe
receipts distinguish an event-delivery gap from a shortcut-publication failure.

Evidence: `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/` under
`independent27-trackpad-contacts-device-v195-attempt1`,
`independent27-app212-trackpad-contacts-normal-guest-lifecycle-v241-attempt1`
and `independent27-vnc-input-v53-normal241-trackpad-contacts-gui-v1`.

## Native trackpad and transform follow-up

The user's physical App212 test failed. A subsequent read of the actual own
window receipts nevertheless showed real contact counts 0/1/2/3; contact
recognition alone was insufficient. Do not count App212 as an accepted fix.

App213 Main51 creates the original `VZMacTrackpadConfiguration` and a USB
compatibility pointing device, with the VM setting selecting the primary.
The actual guest `hidutil list` in Normal242 identified `Virtual Trackpad`
over `AppleVirtualPlatformHIDBridge`. Surface14 additionally reads only an
actual `UITransformEvent` delivered to its admitted own window, with runtime
selector type checks. Three fresh contacts, a dominant translation and a
complete lift are required for a one-shot Control-arrow action. It does not
invent UIEvents or monitor global HID.

Normal243 booted and logged in with this same input configuration. Its native
16-second post-Return capture showed wallpaper, menu bar and Dock; Safari
subsequently rendered the Apple website and HTTPS returned 200. These samples
do not establish frame-rate, complete cold Ready timing or physical three-finger
acceptance. The physical Magic Keyboard three-finger path remains open.

Normal242's much later login stopped after owned GPU task creation was refused.
The fault was traced to a separate 2 MiB log-length spawn gate; see
[log growth and GPU startup](independent27-log-growth-crash.md).


## Input delivery latency

App222 retains the physical pointer and two-finger axis mappings. The adapter
notifies a DATA_ADD dispatch source after successful copied-packet publication,
after its mutex has been released. Dispatch coalesces pending wakeups; delivery
still occurs on the exact original VM main queue with the existing identity,
state, generation and device checks. Adjacent motion/distance coalescing and
all button/key/gesture lifecycle barriers remain. Close removes the publication
callback before closing admission, and retains the original asynchronous source
cancellation/drain lifetime. There is no periodic60Hz input polling timer.

Normal254 recorded64 actual UIKit hover pointer events, all with successful
original native sender returns: receipt-to-consumer wait median0.135ms,
p950.216ms, maximum0.476ms. The old timer's earlier19 touch samples had5–13ms
waits; these are different input samples, not a controlled end-to-end latency
comparison. The user reported improved responsiveness. Native pause(state2)
and resume(state1) completed with the same owner and verified results; guest
SSH and the advancing clock worked afterward. This does not establish physical
display latency or completion of all desktop stutter work.

The development copied-pan scroll URL actions and finite input producer were
removed from App222. The unrelated App221 axis experiment was rejected and
rolled back; do not ship its receiver3, axis header or builder.

## Remaining native trackpad and icon defects

Normal253 still enumerated a Virtual Trackpad AVP service with generic usage1/2
and no AppleMultitouchDevice. The actual Settings UI exposed Mouse and no
Trackpad page. Apple staff confirms that `VZMacTrackpadConfiguration` supports
guest gestures but is not configurable in guest System Settings; the absent
page therefore does not prove a missing device. See the
[official answer](https://developer.apple.com/forums/thread/738569).
A device name alone is also insufficient gesture acceptance. The separate
private VZ multi-touch configuration describes AVP/USB **touchscreens**; it must
not be added as a supposed trackpad fix. Full Magic Keyboard three/four-finger
event delivery remains open. VirtualMac provides the configurable gesture
options; creating a guest Trackpad settings page is not a native VZ requirement.

Normal253's original icon service exited with SIGSEGV in objc_release /
__NSSetM dealloc / CI::PrecompiledKernels and DAGPrecompiledKernels teardown;
launchd reported three runs. The later healthy service in Normal254 is not
proof the recurring Settings icon defect is repaired. Evidence is in
normal253-icon-crash-summary-v1.json and normal254-input-queue-latency-proof-v1.json
under the device diagnostics directory.

## Per-VM gesture options

App223 adds independent three-finger and four-finger system gesture switches
to the virtual machine Input settings. Missing keys default to enabled for
existing VMs; changes persist with the normal VM configuration save and apply
at its next start. Up/down map to Mission Control/app windows; left/right map
to the standard Control-arrow space shortcuts. The actual guest shortcut
configuration still governs their effect.

Surface18 retains App222's event-driven input consumer and original two-finger
axes. It classifies only three or four contacts, shares a one-shot action flag
between the pan and transform routes, and allows an active transform sequence
to continue beyond the initial contact-hint timeout. Host sanitizer checks cover
contact changes, lift, cancellation, stale hints, long gestures and ordinary
two-finger exclusion. These checks do not establish delivery of physical Magic
Keyboard gestures; on-device contact and action receipts remain necessary.

The App223 resource delta consists of the main executable, its resource seal
and three localized string tables. Runtime154 is unchanged.

## Actual three/four-contact sampling

Normal256 with App224 captured 96 real own-window motion events during the
user's Magic Keyboard test. All were UIHoverEvent with digitizer/pointer
children; the pointer positions stayed fixed within each sampled sequence.
Three and four contacts were reported, but no pan/transform action was logged.
The UIKit route currently supplies contact information without the required
gesture movement. Control-Up sent through the normal input path did open
native guest Mission Control; its actual USB screenshot is
`independent27-vnc-input-v53-normal256-control-up-mission-control-v1/native-after.png`
under the diagnostics directory. This verifies the manual shortcut target,
not physical gesture forwarding.

Further investigation uses a bounded read-only native HID service inventory,
then an exact service match for trackpad motion. The diagnostic never writes
HID events and excludes keyboard/Unicode payloads. This is still investigation,
not an accepted three/four-finger implementation.

## Native copied-contact mapping

The bounded native probe found the Magic Keyboard's separate Apple AID
touchpad service (primary usage13/12, capability13/5) and keyboard service
(usage1/6). An exact touchpad match yielded192 actual events, including91
packets with three finger children and69 with four. Their normalized contact
positions changed throughout movement. This upstream data is absent from the
UIKit hover events described above. Service registry IDs must be converted
from the API's returned CFNumber, not treated as an integer return value.

App225 Surface20 uses an owned native iPad monitor matched to Apple AID
touchpad services only. It validates one matching service, touchpad capability
and exact event sender. It copies active finger identifiers/positions and
requires coherent three/four-finger movement. It allows a three-to-four finger
landing transition before firing, rejects identity changes/pinches/stale data,
and fires once until a full lift. Original mouse and two-finger routes remain
unchanged. Hardware pan/transform shortcut fallbacks yield to the admitted
native route to avoid duplicate actions. Direct screen gestures remain separate.

The callback uses a weak owner, is scheduled on the main run loop, and is
unregistered/unscheduled when the input session closes. The surface checks
its actual current VM window/session and foreground state before publishing
any shortcut. Native HID events are read only and never retained or injected.
The App's only additional entitlement is
`com.apple.private.hid.client.event-monitor`. Physical acceptance and mobile
monitor admission still require on-device results.
