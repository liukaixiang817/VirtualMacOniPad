# App disconnection termination: native evidence and repair

On 2026-10-21 at 05:49:43.100 UTC, iPad launchd recorded that the actual
independent27 UIKit App (PID 96457) exited due to SIGPIPE, sent by that same
process. RunningBoard and SpringBoard independently recorded signal 13.
VMM PID 96494 exited afterward. The four CPU cancellation receipts are teardown
consequences; they do not establish a CPU/GIC failure. There is no evidence
that the user closed the App or that the initialization timer killed it.
This establishes this exit's cause, not the cause of every earlier exit.

Main50 installs `vm27_broken_pipe_policy_v2.h` before UIApplicationMain starts
worker threads. SIGPIPE is ignored for the process so closed-stream writes
return EPIPE to their existing error handlers. Other signals are unchanged.
Per-socket SO_NOSIGPIPE remains enabled, and existing relay/clipboard/native
connection error handling remains in place. Pipes and framework-owned file
descriptors also need this process policy. The exact descriptor that caused
the original signal has not yet been identified.

The selected source is `VirtualMacApp_independent_disconnect_recovery_v50.m`.
The product builder and preserving-info signer retain the installed resource
baseline, version metadata and entitlements. Runtime134, CPU77, GIC13,
Surface12 and all other runtime files are unchanged. Device179 installs only
the signed App main file, with a backup and one new trust hash. The hash is
`cbd3cc90d99e4fe0497e088ec38e21aa82ea8c51`.

Validation:

- The host regression uses real closed pipes and socket pairs. Unprotected
  subprocess controls terminate with SIGPIPE; protected subprocesses receive
  EPIPE, exit normally, and retain the SIGTERM disposition.
- Normal208's actual startup query reports `query=0 ignored=1`.
- SSH 22222 authenticated before login. Three real SSH handshakes were then
  abruptly closed at TCP level. The same App PID 97375 and VMM PID 97400,
  with unchanged start identities, survived, and native relay completion
  counters advanced. A later Root command still succeeded through the
  authenticated guest connection. The same identities remained alive at
  06:19:15 UTC, then the guest was normally shut down for a separate startup
  performance comparison; the App was cleaned up only after native guest
  stop confirmation.

Evidence under DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm:
`normal207-actual-app-sigpipe-termination-evidence-v1.log`,
`independent27-normal207-system-termination-archive-v2`,
`independent27-disconnect-recovery-device-v179-attempt1`,
`independent27-normal208-actual-tcp-reset-regression-v1`, and
`independent27-normal208-after-three-real-ssh-resets-v1`.

This repair does not fix the guest icon service's separate CoreImage teardown
crashes. Normal208 again showed blank Settings icons and a PAC exception in
objc_msgSend / NSSet / PrecompiledKernels teardown. The failed async compile
preference trial has been restored to its original absence. Gray desktop and
approximately 30-second cold Ready remain unresolved. These source changes
must be included in the eventual standalone dual-backend beta3 deb; no such
deb or release has been completed or published yet.
