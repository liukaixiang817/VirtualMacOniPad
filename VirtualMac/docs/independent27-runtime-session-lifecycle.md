# Independent macOS27 runtime session lifecycle

App279/Runtime179 is installed on the M2 iPad14,6 running16.1.1. Published
Beta5 assets remain unchanged. The implementation is not yet accepted across
the supported device/OS matrix.

The captured failure kept the App alive after its VMM exited. The old parent
factory and stopped-VM binding remained retained. A later load checked that
expired factory, poisoned the process runtime, and the GUI hid the underlying
error behind a generic framework-load message. User reports include entering
settings, backgrounding and returning without deliberately starting a guest;
regression coverage must include that path, not only Hibernate.

The current implementation preserves the accepted portable loader and explicit
owned-bundle startup policy:

* The exact stopped VM is unbound on its actual main queue, after input,
  display and SSH cleanup. A running or mismatched owner is retained/refused.
* Only the parent VZ image's `xpc_connection_set_event_handler` import routes
  through the existing XF reexport. The observer calls the unchanged original
  handler, then records real final INVALID delivery and callback completion.
* Internal transport event setters bypass that observer. Some execute under
  the transport lock; routing them through the observer would deadlock startup.
* The old owned child must be genuinely waited/reaped and absent. Parent
  listener/control cancellation and queue draining must finish; the original
  client must have delivered final INVALID if a client was created.
* Retirement clears only that client epoch. Native validation, immutable server
  registration, file/code identity and live-child checks remain intact. There
  is no arbitrary flag reset or signal of an unidentified process.
* The loaded signed image graph remains retained. A new nonce and authenticated
  child bootstrap create the next session. Partial-load poisoning still fails
  closed, while a previously ready exited session can be reconstructed.
* The GUI retains the underlying loader NSError in reports.

The relinked startup library must contain `LC_RPATH @loader_path`: current
provider libraries use `@rpath` install names. A closed strong-symbol graph alone
is insufficient to prove that dyld can locate files. App277/Runtime177 lacked
this path, and App278/Runtime178 exposed the internal-setter deadlock. Neither
was accepted; App279/Runtime179 corrects both and passed actual guest execution.

The exact Runtime176-to179 saved-state transition is admitted only after an
actual audit of unchanged VMM sections, CPU99/GIC19/GPU24 and guest device
providers. No generic manifest mismatch bypass exists. The original2.89GB
snapshot restored through the native API, its original guest boot UUID was
read over authenticated SSH, and native USB screenshots showed the desktop.

Bounded device acceptance retained App PID82557 across VMM82559,82689 and82778:

1. Restore the previous snapshot; confirm original guest boot UUID and desktop.
2. Native save, stop and commit; return to settings, background/re-enter and
   restore again. The actual old child was reaped; the retirement receipt was
   `status=0 released=1`. No force-quit was used.
3. Clean guest shutdown, no Current.plist and no running guest; execute three
   settings/background/re-entry cycles. Actual runtime startup succeeded in
   the same App, followed by a full27 cold boot and authenticated guest SSH.

Evidence: `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:
`runtime179-app279-lifecycle-acceptance-v2.json`, the referenced native receipts,
`runtime179-restored-desktop-v1.png`, and the Runtime179 saved-state audit.
A fresh App83023 was then tested with no guest or saved session: two settings-only
background/re-entry cycles passed, followed by actual runtime load and child83053.
That fresh process subsequently cold-booted the full27 guest. After the USB
descriptor probes, authenticated LAN-proxied guest SSH confirmed boot UUID
FD20818E-865E-4F6F-AAAD-A302578D8F2B and running WindowServer, Dock and
WallpaperAgent. Evidence is `independent27-guest-root-runtime179-lan-post-usb-read-v1`.
The wider device/OS matrix remains a separate acceptance item. Temporary UI-control attempts were cleaned and are
not evidence of successful remote clicks or input calibration.
