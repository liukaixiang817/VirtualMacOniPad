# Private IOUSBHost compatibility provider

This is an explicit **USB unavailable** policy for a private macOS27 runtime. It is not a USB passthrough implementation. It does not load in the production 13.2.1 path or replace iPadOS frameworks.

`modern_usbh_host_unavailable_compat.{h,m}` implements the seven C descriptor helpers imported by the original VZ27/VMM27 binaries. Pure parsing is independent of hardware. It defines the original five imported Objective-C classes, their metaclasses, and the `IOUSBHostObject` superclass. All actual hardware initializers return nil with `NSMachErrorDomain` / `kIOReturnUnsupported`; they release the failed receiver and do not retain or call callbacks. A matching dictionary uses a private class name that cannot enumerate physical IOUSBHost devices, rather than an empty dictionary that could match every service. Unknown methods remain unavailable.

The native macOS27 class and public method ABI was read through the Objective-C runtime without opening any IOKit service. `IOUSBHostControllerInterface` has a real `NSObject` superclass and a 320-byte instance footprint. The provider preserves that footprint for VMM's subclass field boundary; its reserved bytes are not an implementation of the original private fields. No imported original `IOUSBHost` ivar offset symbol was found. The other class hierarchy and footprints are likewise preserved. Subclass hardware creation still fails honestly.

Validation is under `DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/virtualization27-native-closure-v2`:

- `usbh-contract-v1/native-abi.json`: native superclass, footprint, method encodings and private ivar observations.
- `usbh-contract-v2/descriptor-results.json`: 70,170 valid descriptor/endpoint cases produced exactly the same output as real Mac IOUSBHost.
- `usbh-contract-v2/class-results.json`: 102 checks, including 55 original method ABI comparisons, real failed initializer ownership, subclass footprint, and closed matching behavior; zero failures.
- `usbh-probe-build-v1`: the same bounded class test built for iPadOS, signed with four probe-only rights. Actual device receipt is `../usb-unavailable-native-v1/result.json`: direct child PID31345, observed wait0, 55 method ABI comparisons and 102 checks with zero failures, hardwareCalls0. The exact probe, provider and ABI oracle hashes matched before and after; the child was absent after execution. It created no guest VM, GPU work or IOKit connection. The 70,170 descriptor comparisons above were performed on the Mac, separately from this iPad class test.

Malformed descriptors whose body exceeds `wTotalLength` are rejected conservatively. The native Mac implementation was observed to return the descriptor header in some malformed cases; that stricter fail-closed behavior is deliberate, and is not described as valid-input equivalence.

`prepare-modern-vz-usb-unavailable.py` changes only the original strong IOUSBHost load-command path to `@loader_path/VM27USBUnavailable.dylib`. It preserves the command kind, slot and ordinal, original VZ UUID, code and file-backed sections. This is a new app-private compatibility dependency. It does not restore the reconstruction's lost original symbol binding closure. The 844 original-required-name gate and `--load-only` must remain until all other providers are implemented. The VMM's corresponding dependency needs its own separately reviewed route; this script only changes VZ.
