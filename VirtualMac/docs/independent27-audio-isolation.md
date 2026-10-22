# Independent27 audio and Bluetooth isolation

The user authorized deferring unsupported Bluetooth audio on 2026-10-22.
Ordinary speaker playback must not depend on Bluetooth audio. iPadOS Bluetooth,
including Magic Keyboard, remains outside this compatibility module.

Actual Normal238 drag profiles found a continuously running
`BTAudioHALPlugin` queue: 0.943 CPU seconds in a three-second VMM sample.
Matching USB logs contained 37,422 interrupted connections in 7.869 seconds;
bluetoothd rejected the actual VMM as an unknown audio client. The complete old
macOS13 stack also had this loop, so it was not exclusive to the new CPU port.

Runtime149 tried the native `com.apple.bluetooth.internalAudioTool` entitlement.
Normal239 still produced the same errors. That experiment is not the solution
and its extra entitlement is removed in Runtime150.

## Runtime150 / App211

`vm27_bluetooth_audio_unavailable_v1.c` interposes only the native Bluetooth
plugin's XPC creation call in the exact owned mobile VMM executable. Admission
requires service name `com.apple.BTAudioHALPlugin.xpc`, actual loaded plugin UUID
`C3698098-E6CA-374A-94EC-504AE04C934B` and return RVA `0x367a8`.
The captured iPadOS16 plugin checks the returned NULL at `0x367ac` and takes its
existing failure path before installing a handler, resuming or registering.
The adapter returns NULL/ENOTSUP; it creates no substitute service and claims no
audio-server identity. Other calls continue to the native API. A mismatched
system plugin version is not modified by this exact-version adapter.

The module loads through one appended VMM dependency in verified zero header
padding. Original sections, imports, binding ordinals, CPU91/GIC16, GPU and input
code stay whole. The VMM retains its original fourteen entitlements. No daemon,
system file, feature flag, kernel identity or global Bluetooth setting changes.
The normal native audio sink and playback session are retained.

Apple's [dyld interposition implementation](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldRuntimeState.h)
describes the image-specific exclusion that permits an interposer to call the
original implementation. Actual activation was also checked on this iPad.

## Focused native evidence

The scoped device194 receipt completed successfully, then Normal240 booted and
logged in with the exact installed App211/Runtime150. Its own log recorded the
Bluetooth-unavailable branch. A bounded 90-second native startup capture had
zero occurrences of the prior interrupted-connection error. Actual guest SSH
continued through iPad port22222.

The guest reported Apple Virtual Sound Device as its default stereo output,
48 kHz, source Speakers. Native `afplay -v 0.15 Glass.aiff` returned zero. This
proves device admission and playback completion, not an acoustic measurement
of sound from the physical iPad speakers. Microphone input is still deferred.

In a newly calibrated, actual Settings-window drag, the three-second VMM sample
used 2.723 CPU seconds versus the previous 4.176. The busy Bluetooth queue was
absent; App main-thread CPU remained small (0.060 seconds). Window workload and
guest background load can vary, so these samples establish removal of the busy
loop, not a controlled overall speedup or a measured frame rate.

Evidence is under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

- `independent27-bt-audio-unavailable-device-v194-attempt1/receipt.json`
- `independent27-app211-bt-audio-unavailable-normal-guest-lifecycle-v240-attempt1/`
- `normal240-bt-unavailable-startup-syslog-v1/`
- `independent27-normal240-bt-endpoint-first-read-v1/`
- `independent27-guest-normal240-bt-independent-native-audio-v1/`
- `independent27-vnc-input-v53-normal240-bt-audio-unavailable-gui-v1/`
- `ipad-gated-native-profile-normal240-app-vmm-drag-bt-unavailable-v1/`

Publication remains deferred. The tested source/module must be carried into the
future standalone dual-backend package; this diagnostic install is not that
finished package.
