# Input admission recovery for the independent 27 App

UIKit coordinate/view changes intentionally close the old copied-packet session.
The previous App could retain a non-nil, already closed VM queue and never
re-establish admission. Main48 and input surface12 notify the owner only for a
known view/coordinate invalidation. After UIKit finishes its current layout,
the actual owner drains its old queue, releases held native input, increments
session/coordinate generations and creates admission against the current view.
Hidden or detached views wait until they are eligible again. Native sender,
thread and ownership errors do not become automatic retries.

A real terminal/cancelled UITouch can remain retained by UIKit after a missed
view callback. Physical hover now prunes only those actual terminal contacts
(or contacts belonging to another window); active direct contacts still retain
priority. A received touch/hover restores the actual input surface as first
responder. Close clears the active pan owner. The original copied-packet queue,
60 Hz latest-motion coalescing, original VZ27 device ownership and button/key
release semantics remain in use. At most sixteen physical/key receipt records
per process contain status only, with no key contents or clipboard payload.

App191 changes only Main48 and surface12 objects over App187. Runtime133 / CPU76
and the other 36 App objects are preserved; there is no macOS13 fallback.
The actual signed one-file App update was installed as Dev177. The repeatable
builder is `scripts/development/build-independent27-input-recovery-app-v191.py`.
Earlier versioned input sources remain for reproduction of the diagnostic
candidates; the current builder explicitly selects surface12.

Normal203 initialized with original advancing frames and explicit handoff.
A calibrated real direct pointer reached the native sender with queue times
0.930 and 1.405 ms, and the actual guest cursor reported the new position.
Normal202's calibrated title click activated Settings and a real drag moved its
window approximately 147 by 100 rendered pixels. These do not establish frame
rate or physical Magic Keyboard operation. RFB text injection does not exercise
all physical UIPress/hover paths, and its Command-Q did not close Settings.
Normal204 also retained the exact running VM through a controlled switch to
iPad Settings and back; the original input surface again became first responder.
App192 retains Main48/surface12 alongside experimental CPU77/GIC13. Its
Normal205 original Pause and Resume completions both reported sameOwner=1,
nativeError=0, verified=1; guest SSH on iPad port 22222 worked after resume.
A calibrated drag moved the actual Settings window. These do not establish
physical Magic Keyboard behavior or frame rate. Physical input acceptance and
window-drag performance remain open.

Wallpaper delay, guest rendering lifetime faults and a complete approximately
30-second Ready desktop remain unresolved. The final standalone beta3 package
must include the tested implementation and guest provisioning, rather than
requiring the development guest's manual preferences or Virtual Mac1.2.3.
