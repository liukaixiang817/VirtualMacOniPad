This separately versioned ARC module implements a private, owned UIKit pointer
lock lifecycle. It is not integrated into the application, exports no SL
function, and changes no original VZ consumer or old frontend source.

The deployment floor is iOS 16.1. Apple headers mark UIViewController pointer
lock and UIScene.pointerLockState as available since iOS 14, and the host mouse
profile since iOS 14. GCEventViewController is unnecessary: pointer lock is a
UIViewController API. [Apple's mouse talk](https://developer.apple.com/videos/play/wwdc2020/10617/)
describes lock as hiding the system pointer and providing relative mouse use.
The lock request is discretionary. The scene must be foreground active and
full screen; system UI, multitasking or another presented controller can revoke
it. [Apple's pointer lock documentation](https://developer.apple.com/documentation/uikit/uiviewcontroller/preferspointerlocked)
requires checking the genuine lock state instead of trusting the preference.

Install this controller as the actual root of an application's own main-screen
window through future frontend integration. The module never installs itself,
reparents a window, changes a global system setting or edits a guest overlay.
Its concrete root view calls back when detached. Register only after the root
view is actually attached to that same real window and scene. A missing scene
or missing lock state is unavailable. It cannot assume that the current legacy
UIApplicationDelegate window has a usable scene. Owner identity is a nonzero
caller-assigned identifier, bound to the construction PID and main pthread.
Every registration requires a strictly increasing nonzero generation.

The original pre-grab integration must perform these steps:

1. Verify the actual guest display/input view is active and associate it with
   this registered root/window. Require a genuine relative-input path bound to
   the same current GCMouse profile; this module reads that profile but never
   replaces its input handlers. Suspend the existing absolute hover path while
   captured. Profile presence alone is not proof of downstream delivery.
2. Call acquire with a timeout from 10 through 2000 milliseconds. The immediate
   return is Pending. Only the completion result Confirmed indicates observed
   lock; the completion may run inline. The preference BOOL is never evidence.
3. On the main thread immediately recheck originalGrabReadyForOwner:generation:
   before entering the original VZ grab path. Never defer a successful snapshot
   into another asynchronous task without rechecking. The predicate requires
   the registered root/view/window/scene, active/key state, exact mouse profile,
   owned request, ready phase and genuine system locked readback.
4. The mandatory loss callback must close the original grab mode and suspend
   its relative input. The module drops its preference on scene/app
   deactivation, key-window loss, root disappearance, mouse changes or actual
   system lock loss. It never automatically reacquires after foreground return.
   Guest display hiding/library presentation must explicitly initiate release;
   the root being visible does not prove a nested guest view is unobscured.
5. Release or detach before removing or discarding the controller. A pending
   acquisition is canceled first. The canceled callback cannot reacquire inside
   the release transaction. Release is Confirmed only after the same genuine
   system lock state reads false. Timeout or missing state remains unknown.
   Detach retains unresolved scene/readback evidence and refuses re-registration
   until that actual old lock can be confirmed false. Nil is never false proof.

Timers run on the main queue and use a monotonic deadline. A stalled main queue
can deliver callbacks late; this code promises not to accept late lock success,
not a hard real-time scheduling guarantee. Weak timer/observer captures avoid
retaining the controller; teardown cancels those resources without claiming
restoration. UIKit objects must be live and the caller must obey main-thread
lifetime rules. Public session methods fail owner/thread/generation mismatch;
this is not protection against arbitrary forged Objective-C objects or running
UIKit after fork.

Snapshot has a fixed 32-byte ABI and is an instantaneous copy. Failure leaves
the caller output untouched. Its copy result is not a claim of capture.
Registration Confirmed likewise means registration, not effect. No tests here
execute UIKit on an iPad; compiler success cannot prove actual pointer behavior.

The original proven imports remain exactly
`_SLAssociateMouseAndMouseCursorPosition`, `_SLDisplayHideCursor` and
`_SLDisplayShowCursor`. Original grab passes low32 zero then display hide;
release passes low32 one then display show. Both ignore returns. Their complete
private prototypes and all global hide-count/error behavior remain unclosed;
public CG declarations do not prove identical private SL prototypes.

This module implements a coupled owned lock/hide request and its relinquishment.
It does not implement independent cursor hiding, WindowServer global
association, cursor warp or process/global hide-count nesting. UIKit
hiddenPointerStyle only styles the hovered region and has no independent
readback proving global visibility. The existing frontend always returns that
style for its input view, so unlocking alone cannot claim that every existing
custom pointer style is cleared. No three-name route is permitted until actual
frontend pre-grab/loss/restoration and original ABI scopes are separately closed.

Compile with ARC, explicit UIKit/GameController/Foundation linkage and no
implicit SDK autolink. Current verification uses the installed iOS 27.1 SDK
with arm64e-apple-ios16.1 and strict availability diagnostics. The object is an
unsigned MH_OBJECT, not a deployed executable or tested iOS 16.1 runtime.
CPU/VM/GPU operations and original framework execution are outside its scope.
