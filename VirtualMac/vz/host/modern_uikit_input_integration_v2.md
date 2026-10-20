# Independent 27 own input source integration

This source compiles a separate window, input surface, copied packet session and
atomic sink. It does not change the current app, enable a backend, export Apple
event APIs, or load UHK/Virtualization. The current macOS27 availability gate in
`VZBackendSelection.m` remains necessary.

`VirtualMacApp.m` currently creates `UIWindow` at line 5731 and `VZInputView` at
5764. The latter's gesture/touch/press handlers call legacy `_VZ*` objects. The
independent route must use `VM27UIKitInputWindowV2` at launch and install
`VM27UIKitInputSurfaceV2` in place of the legacy receiving view only after the
independent backend and its original caller ABI are validated. The 13 input
view, old GameController handlers, private raw-scroll recognizer and software
keyboard must be disconnected from the active display first. Changing only
`sendPointer` or `sendPresses` would leave other legacy producers active.

The actual compiled activation API is:

```objective-c
VM27UIKitInputSessionV2 *session = [surface activateWithSink:independentSink
    epoch:sessionEpoch coordinateGeneration:coordinateGeneration capacity:128];
```

The surface must already be attached to its own input window. It publishes only
copied scalars/contacts. A backend retains this returned session on its consumer
thread and calls `consumeNextCopiedPacket`; its own `VM27CopiedInputSinkV2`
implementation returns unsupported for fields it cannot honestly consume. No
sink implementation for original UHK is supplied here. The lease's sink call
holds the same C admission mutex used by close; an `isCurrent` observation is
not used for delivery. A sink is synchronous and bounded and must not reenter
the queue/session or wait synchronously for UIKit. An Objective-C exception is
caught before it can escape the locked C callback.

The app's stop entry is `finishVMAndShowLibraryWithError:` at line 4177. It must
close this own surface before releasing native input/backend objects, join its
producer/consumer threads, and then release the backend's retained session.
`applicationWillResignActive:` at line 5972 must also close; the own source
already observes that real notification. Reactivation creates a new nonzero
epoch and coordinate generation. Bounds, frame, transform, hidden state and
window changes close admission before the mutation. These hooks do not prove
screen-to-guest calibration or external display transforms.

The own window binds one real `UIEvent` only for synchronous `sendEvent:`. Each
gesture recognizer records a stamp only when its public touch callback received
that exact event during that session's dispatch. A delayed callback, a changed
session, or a hover delivery without such a public touch callback is rejected.
No `CACurrentMediaTime` or synthetic event supplies an input timestamp. Actual
UIKit dispatch/gesture behavior remains to be run on the device.

Current capabilities are contact copies, HID usage page 7 hardware keys, direct
two-finger processed pan, additive pinch and rotation in radians. This does not
supply Mac keyCode, repeat, rich/raw/accelerated CGEvent fields, sender identity,
hardware momentum, smart magnification, Pencil pressure or relative hardware
pointer motion. Own point deltas and timestamps do not prove native IOHID event
units or the original 17-getter UHK protocol. Original AppKit/SkyLight imports
remain unsupported; there is no fake NSEvent/NSTouch/SL class.

The C lifetime contract requires all already-entered calls to finish and all
producer/consumer threads to stop before destroy. Closed/no leases alone is
not sufficient for concurrent C destruction. The ObjC session and lease keep
the adapter owner alive through their calls; the adapter's final deallocation
destroys its own closed queue after these references have drained.
