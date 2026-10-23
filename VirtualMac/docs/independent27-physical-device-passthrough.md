# Beta6 physical device passthrough

The requested devices are independent targets:

* USB means physical downstream devices plugged into the iPad USB-C data port,
  including storage, USB Wi-Fi adapters and USB Bluetooth adapters. The guest
  should own their actual USB transactions after explicit attachment.
* Wi-Fi means the iPad's built-in radio, including guest control of that radio.
* Bluetooth means the iPad's built-in radio. Audio must remain independent of
  Bluetooth availability.

NAT, a virtual Ethernet interface, shared host folders, and host Bluetooth
accessory forwarding do not meet these physical passthrough requirements.

## Current implementation boundary

The installed App279/Runtime179 and published Beta5 do not implement physical
USB or built-in radio passthrough. No new switch has been exposed as working.
The running guest, existing keyboard/trackpad and speaker path are unchanged.

macOS27 provides `VZUSBPassthroughDeviceConfiguration` and
`VZUSBPassthroughDevice`, with attachment through `VZUSBController` on the VM's
queue. Its public physical-device path relies on AccessoryAccess. Apple's
[WWDC26 explanation](https://developer.apple.com/videos/play/wwdc2026/224/)
describes exclusive accessory assignment and release. The exact current VZ27
image also exports `_VZIOUSBHostPassthroughDeviceConfiguration` and
`_VZIOUSBHostPassthroughDevice`; these offer a candidate IOService-based route
without claiming that macOS's AccessoryAccess daemon exists on iPadOS16.

Read-only discovery on the connected M2 iPad/16.1.1 confirmed:

* `/System/Library/PrivateFrameworks/IOUSBHost.framework/IOUSBHost` loads and
  provides device/interface/pipe classes and real control, bulk/interrupt and
  isochronous request methods. Method presence is not transfer acceptance.
* Native device objects are120 bytes and controller-interface objects312 bytes.
  Existing compatibility device objects are104 bytes and the AVP controller
  superclass is320 bytes. A direct superclass/library substitution is unsafe.
* `AAUSBAccessory` and `AAUSBAccessoryManager` are absent from this process.
* The iPad's Wi-Fi driver uses `AppleBCMWLANBusInterfacePCIe` on a `wlan`
  PCI device. Bluetooth has separate `bluetooth-pcie` and
  `AppleBluetoothModule` registry nodes. Neither is a downstream USB device.
* No downstream `IOUSBHostDevice` was present with the iPad connected to the
  Mac. `PCIPassthroughController`, `IOPCIPassthroughClient`,
  `IOPCIPassthroughDevice`, and `AppleUSBUserHCIResources` did not match a
  service in that snapshot. This is an observation, not proof that all other
  private hardware-access mechanisms are impossible.

## Native USB bridge prototype

`vz/host/vm27_physical_usb_native_v1.inc` and
`scripts/development/build-physical-usb-native-v1.py` build a separate candidate.
They have not replaced the installed provider.

The bridge has distinct Objective-C runtime class names and exports aliases for
the original framework imports. It keeps the existing320-byte AVP/offline
controller and descriptor parsing. Physical device/interface wrappers delegate
to native iPadOS objects rather than copying or subclassing their private
storage. Requests missing from the bridge can be forwarded only to selectors
actually implemented by the retained native target.

Opening requires a selected, current registry ID. Hubs, controllers, explicitly
built-in devices, absent IDs, and interfaces outside the selected device are
rejected. A selection cannot change while native objects or their opens remain
outstanding. Native failures remain failures. The bridge does not turn dummy
controller responses into successful physical transfers.

The Mac oracle passed real native device/interface matching-dictionary
comparisons, distinct native/bridge class identity, preserved controller size,
and rejection of missing devices. An initial iPad probe could not map its own
dynamic library from its staging directory because of sandbox restrictions;
the following probe statically links the same bridge rather than adding a
no-sandbox entitlement. The static iPad oracle passed: real native device and
interface matching, distinct class identities, preserved320-byte bridge
controller alongside the actual312-byte native class, and absent-device
rejection. These checks do not constitute guest USB acceptance.

Primary evidence is under
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/`:

* `beta6-device-inventory-v3/`: successful native framework and registry probe.
* `beta6-native-vz-usb-abi-v1/`: native Mac metadata and exact ported image scan.
* `beta6-native-usb-bridge-v1-attempt2/`: iOS/Mac candidates and build records.
* `beta6-native-usb-bridge-ios-probe-v1/mac.stdout`: passing Mac oracle.
* `beta6-native-usb-bridge-ios-probe-v2/`: explicit dynamic-loader failure.
* `beta6-native-usb-bridge-ios-probe-v3/`: static iPad oracle and its receipt.

The macOS SDK explicitly documents `IOUSBHostObjectInitOptionsDeviceCapture`
as macOS-only. Discovering iPadOS request methods does not prove this exclusive
capture mode exists there. Initial flash-drive probes must use non-capturing
control/descriptor requests; complete guest ownership requires a separately
verified capture/release mechanism. Do not substitute a successful descriptor
read for exclusive device assignment.

## Remaining work and acceptance

1. Complete the actual App selection UI and authenticated App/VMM selection
   handoff. The prototype selection export alone is not a user-facing feature.
2. Configure a genuine XHCI USB controller when needed. The current App does
   not explicitly configure `usbControllers`. Preserve existing guest input.
3. Attach through the actual VZ VM queue, propagate real native errors and
   device-disconnect events, and release ownership back to iPadOS.
4. Start with the user's USB flash drive: observe its VID/PID and descriptors
   in the guest, read a known file without formatting or altering its contents,
   then eject/detach and verify host recovery. Disk-image emulation is not a
   substitute. Test hub children and replug with a fresh registry ID afterwards.
5. Check pause, stop, relaunch and native Hibernate compatibility explicitly;
   do not silently claim that external hardware state can be snapshotted.
6. Test USB network/Bluetooth adapters with actual compatible guest drivers.
   Successful USB enumeration alone does not establish wireless functionality.
7. Investigate built-in Wi-Fi and Bluetooth ownership, driver compatibility,
   DMA/interrupt isolation, and reversible release separately. There is no
   implemented safe built-in radio assignment path yet. Do not unbind a host
   radio or map its DMA/PCI BARs based only on guessed private selectors.

The acceptance criteria include iPadOS stability, working host recovery and the
existing audio/input paths. Beta6 is a development target, not an accepted
release on the strength of the inventory or oracle alone.

## Actual flash-drive access (2026-10-23)

The reconnected aigo U397 is VID0x3535/PID0x6500, with current registry
ID4295073597 in boot3AB622D6-C539-4458-A8B6-061236F9084C. The previous
ID4295071593 is stale. LAN SSH is working while the drive occupies USB-C.

The earlier non-capturing opens failed at `IOServiceOpen` with0xe00002e2.
Reading only already mapped native code identified the iPadOS framework's
type0 open. The exact device kernel maps that type to
`AppleUSBHostFrameworkDeviceClient`, rather than
`AppleUSBHostDeviceUserClient`. The previous allowlist named the latter.
The successful probe's actual registry children also identify the framework
client by its real class name; this is not inferred from an entitlement alone.

Changing the allowlists to `AppleUSBHostFrameworkDeviceClient` and
`AppleUSBHostFrameworkInterfaceClient` made the same probe succeed. Both root
and the App's mobile501 identity opened the real native device and completed
an18-byte GET_DESCRIPTOR. The mobile configuration probe then completed
two further GET_DESCRIPTOR requests and read the complete121-byte configuration.
It contains interface0, alternate0 with two bulk endpoints and protocol0x50,
and alternate1 with four endpoints and protocol0x62. All selections were
released and temporary probes cleaned. No disk blocks were read or written.

`resources/PhysicalUSBEntitlements.plist` records the actual native client
classes. `scripts/development/prepare-native-usb-entitlements-v1.py` augments
existing App/VMM signing inputs while preserving their other entitlements and
all existing IOKit classes, including IOSurface. Prepared role inputs are under
`beta6-native-usb-signing-inputs-v1`; they have not been signed or installed.
The fragment does not establish compatibility with every supported iOS build.

The next distinct barrier is exclusive interface ownership. A non-seizing
mobile open of interface4295073602 returned0xe00002c9 (exclusive access).
No interface transfer was attempted. The current iPadOS16.1.1 framework
device-client code rejects its capture flag, and the SDK documents
DeviceCapture as macOS-only. The legacy capture/release API must be considered
separately: its documented capture behavior excludes mass-storage interfaces.
Do not remove a mounted storage driver or reinterpret an unsupported capture
result as successful ownership. No capture, reset, reconfiguration, driver
termination or successful host volume unmount has been performed.

`beta6-native-usb-access-acceptance-v1.json` pins the successful native outputs,
configuration parsing, exact signing fragment and prepared inputs. The native
read is accepted on this M2; exclusive guest assignment remains unimplemented.
After these probes, authenticated guest SSH still found WindowServer, Dock
and WallpaperAgent running in the full27 guest, boot UUID
FD20818E-865E-4F6F-AAAD-A302578D8F2B.

## Host storage release investigation (2026-10-23)

The current interface is owned by the native UAS storage driver. Its child
media are disk4 and disk4s4; the external exFAT volume is mounted by UserFS.
The native legacy IOUSBLib device and interface plugins both work with their
actual client classes. Plugin creation and descriptor access do not grant
exclusive access to the mounted storage interface.

Two ordinary release paths have been tried once each on this selected drive:

* `DADiskUnmount` with default options returned 0xc010 (EBUSY). The native DA
  session requires `com.apple.private.diskarbitrationd.access`; adding this
  entitlement to the diagnostic probe resolved session creation, not ownership.
* `LiveFSMountClient unmountVolumeByID:how:` with the exact current mount ID
  and `how=0` returned NSPOSIXErrorDomain 16 (EBUSY). The volume remained
  mounted. The tested probe had the native LiveFS connection entitlement.

Neither attempt proceeded to USB interface seizure. No forced unmount, disk
content access or system service termination was used. The ordinary vnode file
descriptors and working directories of the relevant Files/UserFS processes did
not identify an open reference to this volume; this does not rule out Mach file
ports or kernel references.

The current iPadOS DiskArbitration image does not export
`DARegisterDiskMountApprovalCallback`, its checked block variants, or
`_DARegisterCallback`. The temporary pre-mount watcher therefore stopped at
preflight without registering a callback or changing mount behavior. Although
`DARegisterDiskPeekCallback` and `DADiskClaim` are present, their presence is not
evidence that they can suppress automatic mounting. Do not request repeated
physical reconnects until the intended native control path is actually ready.

The next investigation is the native volume-manager eject path used above
ordinary unmounting, followed by cooperative interface ownership and verified
host recovery. The App/VMM remain App279/Runtime179; none of these diagnostic
permissions or experimental ownership paths have been installed into them.

Evidence: `beta6-usb-legacy-interface-v1`, `beta6-usb-legacy-volume-v3`,
`beta6-usb-legacy-volume-v4`, `beta6-usb-volume-fd-read-v1`, and
`beta6-usb-pre-mount-capability-v3` under the diagnostics directory above.
