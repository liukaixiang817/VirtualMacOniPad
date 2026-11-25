# Native touchscreen on macOS 27.2 and later

The independent macOS 27 backend can expose an original Apple virtual
touchscreen associated with the guest display. Direct iPad finger contacts
then reach macOS as screen touches. AppKit handles compatible controls,
single-finger scrolling and native application gesture recognizers.

The option is enabled by default for guests with a saved compatible OS build.
New installations save their restore build before their first desktop boot.
Existing audited macOS 27.2 guests also qualify through their saved Apple
Account build. Unknown builds and older systems retain the existing input
path. The App's Touch settings include **Native Touchscreen (macOS 27.2+)**;
restart the guest after changing it. Application and macOS gesture settings
still determine which actions a particular gesture performs.

`vm27_native_touchscreen_v1.m` creates the original
`_VZAppleTouchScreenConfiguration`, assigns matching `displayUUID` properties
to the touchscreen and display before boot, then binds the VM's original
`_VZMultiTouchDevice`. The display identifier is derived deterministically
from the guest's saved machine identifier. Guest identity and disk data are
preserved; no guest touch helper or additional guest permission is required.

The UIKit surface gives direct fingers to this device and excludes them from
the legacy pointer/gesture adapter. Hardware pointer, keyboard, Pencil and
trackpad input retain their existing routes. Contacts keep their assigned
indices until lift or cancellation. Allocation uses a verified pool of 16 low
transducer indices, with a 70 ms retirement interval: the broader range accepted by the
VZ touch initializer caused guest touch loss in physical-device testing.
Layout changes, backgrounding, closure and interaction with host controls
release active native contacts. Surface admission recovery requires a new
finger-down instead of fabricating a continuation of an interrupted stroke.

The display-association and contact-lifetime design was informed by
[Henge PR #32](https://github.com/Leviidev/Henge/pull/32), reviewed at
`1e016c290c02be702ba9bb5d41d4466928740b63`. Its USB/CoreHID implementation
is different from this project's original VZ device route; no Henge source
was copied into the product. Henge PR #90 describes an absolute pointer,
which does not provide native multi-contact screen touches.

Native AppKit touch acceptance must be checked with direct-touch gesture
recognizers, not a global event monitor. See
[Apple TN3212](https://developer.apple.com/documentation/technotes/tn3212-adopting-gesture-recognizers-for-sidecar-touch-support).
The physical-device validation record is linked from the release notes.
Recognition of screen touch does not establish identical display latency,
touch hardware or every application interaction to a physical MacBook Pro.
