# Owner-only GIC snapshots for unchanged state

Status: experimental and withdrawn from the running product. Normal199 and
Normal201 initialized with real frames, but no complete GUI/lifecycle acceptance
was obtained. Normal199 App/VMM exited without a matching new crash report.
Following the user's pointer/drag regression report, Dev176 restored the prior
CPU76 / GIC12 runtime. The report is not proof that GIC13 caused the regression.
Do not ship this optimization as an accepted performance fix.

Normal198 native boot samples still showed four vCPUs competing at physical
route entry, virtual timer routing and aggregate line reads. GIC13 / CPU77
retains the same locked arbitration, but reuses its complete IRQ/FIQ/INTID result
when an admitted owning CPU is inside Run and the state generation and relevant
timer level have not changed.

Every state-mutating entry invalidates before touching IRQ, affinity, group,
priority, route, sleep, active state or topology. ICC IAR reads invalidate too.
Quiesce and detach invalidate again after native callbacks before later state
changes. Read-only line polling and callback-pin bookkeeping do not invalidate.
The 64-bit generation saturates by permanently disabling reuse, avoiding wrap
and ABA. Native interfaces remain unchanged.

Snapshot storage belongs only to its retained attachment's pthread. A hit checks
the full original identity, controller, attached/not-closing state, native retain,
owner pthread and currently running state. Foreign, changed-identity, outside-Run,
dirty and changed-level operations use the original locked computation. Running
excludes reset while physical-batch callback pins are acquired outside arbitration.
Every batch still invokes the real native boundary and deadline scheduler, keeps
both callback pins through them, publishes owner completion, then releases the
CPU pin and controller pin last. No timer, wake or native result is fabricated.

The other 28 CPU objects, 155 export names/kinds, four load semantics and native
import semantics are unchanged. No GPU, input, clipboard, network or audio object
is replaced. The current guest's two native graphics compatibility preferences
remain required; this optimization is not a substitute for that GUI fix.

Host validation: actual IRQ/FIQ transitions, PMR/group/enable/priority, IAR/EOI,
SGI/SPI/MSI, affinity route, sleep, raw MMIO, reset/quiesce, owner/identity/output
bounds, saturation, failure/reentrant closing and four running owners were tested.
The ordinary run passed 66,782 checks; ThreadSanitizer passed 67,918 checks (totals
vary with the concurrent reset observer). Repeated unchanged observations retain
the generation while still invoking all boundary/deadline callbacks. A valid
owner's cached GetLines also completed while arbitration was held by that owner.

The host benchmark exercises four owners and 800,000 physical-batch + virtual
route + aggregate-line cycles, including timer transitions every 64 iterations.
Three baseline runs took 0.215–0.227 seconds; snapshot runs took 0.078–0.085
seconds. Every IRQ/INTID and deadline result was checked. These are host fixture
measurements, not a guest speed claim or proof of 30-second desktop readiness.

Runtime134 / App188 was signed and installed as Dev175 (seven own files, four
new trust hashes, preserved permissions). Actual cold Normal199 GUI, timing and
lifecycle validation were not completed. The product has since reverted to
Runtime133; end-to-end startup remains unresolved.

Evidence under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

- `gic13-mutation-invalidation-source-map-v1.json`.
- `gic13-host-owner-snapshots-v1/`.
- `cpu-gic-owner-snapshots-source-local-v77-attempt1/`.
- `independent27-gic-owner-snapshots-device-v175-attempt1/receipt.json`.
- `independent27-app188-gic-owner-snapshots-normal-guest-lifecycle-v199-attempt1/`.
