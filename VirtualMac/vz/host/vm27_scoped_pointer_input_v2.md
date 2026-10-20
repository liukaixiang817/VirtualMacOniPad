This app-private ARC adapter binds the existing owned UIKit lock lifecycle to
the actual `GCMouseInput.mouseMovedHandler`. It does not export SL/SLS symbols
or replace any original VZ call. Its input sink receives real raw mouse deltas.

Construct it on the main thread after registering the pointer controller's
real window and generation. Bind before acquiring lock. The mouse must already
use the main handler queue; this adapter never changes that shared queue. The
previous motion handler is preserved and receives deltas only while the same
registered scene is known unlocked. While acquisition or restoration is pending
or unknown, deltas are withheld. Nonfinite values are discarded.

Future frontend integration must use this adapter's `originalGrabReady` before
original mouse grab. That gate combines the v1 controller's actual scene lock
readback with the exact current mouse, its profile and the installed handler
identity. A replaced handler or a different mouse cannot deliver relative motion
through this adapter. The callback rechecks that gate for every delivery; a
saved successful gate is not future permission. A mouse event from an unexpected
queue cannot touch UIKit or the adapter's mutable state. The caller must still
bind the sink to its actual guest input view and suspend absolute UIKit hover
while capture is active; this module cannot prove those downstream operations.

Cleanup order is: release lock through the v1 controller and observe restoration,
detach this adapter, then detach the v1 controller. Adapter detach restores the
old handler only while its exact installed handler is still owned. If another
owner has replaced it, admission closes and Busy is returned without overwriting
the replacement. Deallocation attempts restoration only on the owner thread
with real unlocked readback; an unknown or active lock does not enable an old
absolute input path. Explicit cleanup is required for reliable restoration.

Compiler validation proves ABI and availability only. No iPad pointer movement,
handler setter/getter identity behavior, original grab/release, backend input
delivery or host visibility effect is established by the local object build.
The three cursor imports and all other SkyLight imports remain unresolved.
