# Native graphics compatibility for the observed Tahoe guest

2026-10-21 continuation: the two-option policy below is not a complete fix.
Normal201 subsequently crashed in `RenderBox` / `RBDrawable` teardown. A trial
that removed the global raster option and set it only for the icon-service App
also failed in Normal203: `CI::StitchableKernels` / `PrecompiledKernels` teardown,
with blank Settings sidebar icons in the actual native screenshot. That trial
has been restored to the prior global policy. Do not ship the scoped-raster
helper as an accepted fix. The native `CI_ENABLE_FUNCTION_STITCHING=0` option
has now been added by `configure_native_graphics_pipeline_v2.sh`, preserving
both prior options and native Metal rendering. Normal204 kept its original
icon-service PID 538 alive for about fourteen minutes, but Normal205 then
failed in `DAGPrecompiledKernels` teardown at 05:20:32 UTC, with sidebar icons
disappearing in the actual native screenshot. The three-option policy is also
not a complete fix. A further native `CI_ENABLE_METAL_GPU=0` software-fallback
trial failed in Normal206: opening the original System Settings left most
main-area and sidebar icons blank. Its exact prior absence was restored at
05:37:56 UTC. Do not enable `CI_ENABLE_METAL_GPU=0` in the package; the
observed explicit native GPU icon path has no usable software fallback. Native `launchctl kickstart` refused this Apple agent with SIP
error 150; no SIP setting or protection was changed. A normal guest restart
applies the option instead.

Normal208 also crashed in native CoreImage teardown and displayed missing
Settings icons. Its additional async-compile preference trial was restored to
its original absence at 06:10:42 UTC. It is not an accepted GUI fix.

System Settings could leave the General header, About, Software Update,
Storage or sidebar icons blank. Actual native icon-service crash reports showed
two different resource-lifetime paths, while the affected image resources were
present and could be generated through the original asynchronous icon service:

- CoreGraphics raster image-cache eviction: `CGSImageDataHandleRelease+24` /
  `RIPImageDataRelease`, invalid address `0x150` or `0x151`.
- CoreImage DAG kernel teardown: `objc_release`, `__NSSetM dealloc`,
  `CI::DAGPrecompiledKernels::~DAGPrecompiledKernels()`.

Isolated successful image generation did not prove the actual Settings UI or
its long-lived icon service worked.

## Current compatibility policy

| Native user suite | Key | Value |
| --- | --- | --- |
| `com.apple.coreimage` | `CI_ENABLE_METAL_DAG` | integer `0` |
| `com.apple.CoreGraphics` | `RIP_ENABLE_IMAGE_CACHE` | boolean `false` |

The lowercase CoreImage suite was confirmed in the actual native configuration
initializer (image UUID `0943679d-ff88-3f18-be4b-d8b4827ab0b5`). Its original
integer getter checks the environment and then the native NSUserDefaults suite;
the original DAG default is 1. The CoreGraphics preference route was likewise
read from the actual guest framework. These choices select existing native
rendering paths. Native Metal GPU rendering and the independent macOS 27 CPU/VMM
backend remain in use.

This is a compatibility workaround for the observed lifetime failures. It does
not implement advanced DAG resource lifetime support or alter Apple system
frameworks. Disabling the raster cache can affect performance; no speedup is
inferred from the GUI result.

`vz/guest/configure_native_graphics_pipeline_v1.sh` accepts `status`, `apply`,
and `restore`. It runs as the guest user and admits only the observed
`VirtualMac2,1` / macOS 26.6.2 build `25G83`. It checks both options before
writing either, preserves existing user options, reuses the owned absent-key
backups, and refuses to replace later manual changes. Restoration deletes only
the owned unchanged options. The earlier private cache backup contains only the
word `absent` and used mode 0644 inside a 0700 directory; both 0600 and that
existing mode are admitted with matching owner and one hard link. New backups
use 0600. No signals or system-program writes occur.

A normal guest restart is needed after a change. Preferences persist in the
current guest; App186 does not yet automatically provision this helper into
new guests.

## Actual device validation

Normal195 with the raster cache option alone crashed in DAG teardown.
Normal196 with the DAG option alone crashed in raster-cache eviction (PID 595),
and the actual General header was blank. Earlier warm-only results were not
sufficient. `CI_DISABLE_LOADING_ARCHIVES=true` was ineffective and remains
restored to its original absence.

Normal197 cold-started the same installed Runtime132 / CPU75 / App186 product
with both options. Native USB screenshots confirmed complete visible General
main-area and sidebar icons, About, Displays and Menu Bar pages, wallpaper,
menu bar and Dock. Actual Cmd-Q followed by clicking Settings in the Dock and
returning to General preserved the icons. The original icon service remained
PID 530, runs 1, never exited at 03:22:13 UTC, more than twelve minutes after login.
The actual Apps panel showed its visible icon grid; Calculator opened with all
controls visible and real clicks produced `2+2=4`. Settings window dragging
changed its native position while preserving icons. The helper's actual repeated
application passed with no guest writes.

Evidence is under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

- `independent27-vnc-input-v38-normal197-cold-dual-native-gui-v1/`:
  native General, About, Displays, Menu Bar and quit/reopen screenshots.
- `independent27-guest-normal197-native-gui-final-job-v1/receipt.json`:
  actual original service state after those interactions.
- `independent27-guest-normal197-dual-native-idempotence-v2/receipt.json`:
  repeated application with zero writes.
- `normal196-cold-native-dag-crash-v1.json`:
  counterexample to the earlier DAG-only policy.

This is one cold GUI regression run, not proof that every application and GPU
feature is fault-free. First frame appeared between 44 and 50 seconds; complete
Ready desktop within approximately 30 seconds remains unmet. Advanced native
DAG lifetime support, startup performance, all-app GUI stability and physical
multi-finger behavior retain separate acceptance requirements.
