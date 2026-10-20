# Genuine DiskImageKit27 compatibility

The private candidate comes from the original macOS27 DiskImageKit image, UUID
`652b07a998be31d298d7ffcaf14aca5e`. Its CPU-only probe checks 168 original and
reconstructed strong imports before calling any metadata accessor. This module
does not substitute older DiskImageKit or Virtualization classes.

`modern_swift_diskimagekit_cvw_compat.cpp` implements the seven missing compact
value-witness imports for the nine named original tables: six configurations or
logging structs and three error structs. It accepts bounded ownership opcodes
and exact original descriptor schemas, authenticates actual metadata pointers,
and uses the host's real Swift/Objective-C retain and release operations. Its
struct initializer delegates field layout to the native Swift runtime and builds
only the scoped compact ownership program. Other layouts fail closed. There is
no global Swift handler registration.

`swift_relative_metadata.py` audits source and rebuilt images with pinned SHA256
values. It maps declared source sections to the corresponding new sections and
parses official singleton, conformance, field-record, and mangled-reference
schemas. Unproved external pointers prevent repair. The DIKit candidate supplies
32 independently identified original GOT symbols through strong native-provider
routes. Reserved symbolic kinds are preserved only when their original bytes
and local relative distance remain exact; their semantics are not invented.

The source has no framework initializer. The iOS candidate flattens framework
paths, stamps the platform, routes the seven CVW imports, repairs proven Swift
relative references, and removes an unused import row after the original empty
ivar strings were localized. Existing instruction sections and bind-site PAC
fields remain unchanged from the reconstruction. The extraction itself already
reconstructed cache instructions; byte identity with the raw cache code is not
claimed.

The frozen candidate is in
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/diskimagekit-scoped-cvw-image-v9`.
The provider is `diskimagekit-cvw-build-v3`, and the independent probe is
`diskimagekit-metadata-probe-build-v2`. Its default mode only loads the image and
checks imports. Explicit `--metadata` calls the nine original `swiftcall`
accessors, then verifies the complete response, exact named descriptor, witness
layout and UUID from the same selected image base. It makes no disk, VM or GPU
calls. Only the independent iOS probe has the four required launch/mapping
entitlements.

That v9 image remains a historical metadata candidate. A later genuine
`CaseIterable` fixture exposed 20 incorrectly plain protocol-requirement GOT
pointers. The new `diskimagekit-static-bootstrap-build-v12` restores their
original DA/address-diverse `0x7d4c` contract and supplies an explicit three-ISA
initialization transaction. Its native Mac metadata, array, witness, ownership
and rollback evidence and remaining iPad boundaries are described in
`modern-swift-array-compat.md`. v9 must not be treated as a verified functional
DIKit loading path.

Native Mac evidence is recorded in `diskimagekit-cvw-receipt-v1/receipt.json`:
all nine private-image metadata initializations passed; real compiler-generated
public configurations passed copying, taking, destruction, reflection and
existential buffer ownership tests against native witnesses and the scoped
provider. Eight malformed-input controls failed as expected. Native direct
self-copy CVW triggered a PAC fault in the original runtime, so the original
comparison excludes that operation; the scoped provider's exact-self
preservation has its own check. Move assignment and initialization continue to
reject overlapping storage.

These checks do not establish complete disk functionality. The three error
values and two private configuration/logging values were not manufactured.
Their metadata was verified; their actual value lifecycles and the old host's
DiskImages2 method ABI and disk operations require separate native checks.
Full macOS27 Virtualization/VMM integration remains incomplete.
