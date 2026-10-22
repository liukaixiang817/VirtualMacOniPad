# Local ICC invalidation and native exit reads

The user accepted the current startup speed and absence of the gray desktop on
2026-10-21. Startup is no longer held open solely to match an earlier numerical
baseline. The next priority is App launch and window motion, followed by Magic
Keyboard gestures, audio/network/clipboard/pause and complete VM settings.

CPU91 combines three object changes over the installed CPU88 baseline:

- GIC16 gives local ICC/private acknowledge/EOI/DIR changes a per-CPU snapshot
  generation. They already notified only that owner; invalidating the shared
  generation also made other CPUs repeat arbitration and contend on the GIC
  mutex. Shared IRQ, SGI, routing and topology changes keep global invalidation.
- Production22 reads the genuine native9 exit reason and, only for reasons
  1/6/8, its three native detail fields as one finite owner snapshot. Actual
  mapping PID/epoch, version, pthread, CPU lifetime and permissions are checked
  before and after. It neither writes context nor enters the kernel.
- Life78 keeps reason-only exits on their original path. After the original
  guarded reason read, only an exact Production owner can select the detail
  snapshot. Generic callbacks and refused admissions retain sequential reads.
  The private post-return token, final ownership boundary and reducer remain.

No snapshot survives its call. The other 26 CPU objects, GPU/display/input and
all non-CPU runtime providers remain whole. The first Life77 prototype also
grouped reason-only exits; it was superseded locally before device installation.

Four-owner host tests cover local/global GIC invalidation, SGI/shared wake
semantics and snapshot generations. The exit test compares values, full
lifecycle receipts and source bytes against the original reads, preserves the
exact generic callback/failure sequence, and exercises foreign/withdrawn,
permission/version/token/generation refusals while the former shared mutexes
are held. Native HV entry is not claimed by these host tests. Strict arm64e iOS
compile/link and dyld validation retain 155 exports, four loads and identical
native imports.

Runtime148 / App209 was actually installed in device192 attempt3 after backups,
then booted as Normal238. Initialization completed with real advancing frames
and explicit handoff; guest SSH authenticated the actual boot UUID. The native
login sequence's first sampled desktop already had wallpaper, menu bar and
Dock. This bounded check found no obvious startup regression. It does not prove
physical frame rate or a new cold Ready time.

Evidence under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

- `cpu-gic-local-generations-source-local-v89-attempt1/`
- `cpu-exit-detail-snapshot-source-local-v91-attempt1/`
- `independent27-signed-runtime-exit-detail-snapshot-v148-attempt1/`
- `independent27-signed-app-exit-detail-snapshot-v209-attempt1/`
- `independent27-exit-detail-snapshot-device-v192-attempt3/receipt.json`
- `independent27-app209-exit-detail-snapshot-normal-guest-lifecycle-v238-attempt1/`
- `independent27-vnc-input-v53-normal238-cpu91-ui-performance-v1/`

An initial App profile started after its drag ended and is only an idle
baseline. It must not be reported as a drag-time profile. Further performance
work must use matching operation/sample timestamps.
