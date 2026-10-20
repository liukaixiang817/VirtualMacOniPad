# Genuine hidden RTTI complete/base destructor forwarding

This scoped provider closes the genuine macOS27 EFI framework's hidden
`__cxxabiv1::__si_class_type_infoD1Ev` import on the pinned iPad libc++abi. It
exports exact D1/D2 names, verifies the native UUID, vtable RVA/slots and entire
complete/deleting/public base destructor code, then calls the genuine complete
entry. The complete entry is one direct branch to public `std::type_infoD2`.
The Itanium complete/base distinction is preserved: documented __si classes
have only nonvirtual bases and empty own destructors, so both chains are equal.
The actual hidden native D2 entry was not independently located.

It creates no RTTI classes/vtables, provides no deleting destructor and replaces
no native allocation or ownership. An unsupported native image fails before
calling the destructor. The probe destroys only SDK-constructed `type_info`
base subobjects in its own placement storage, ends their base lifetime, then
releases raw storage exactly once. No system/compiler/static RTTI is destroyed.
Complete native __si construction is not verified.

The frozen candidate is under
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/efi-native-rtti-v1/build-v2`.
The tracked build and independent validator are respectively
`scripts/development/build-modern-native-rtti.py` and
`scripts/tests/validate-modern-native-rtti.py`.

Actual iPad evidence (2026-10-08):
`native-rtti-contract-v1/result.json`, PID 31764, observed wait 0, reaped/absent,
673 checks / 0 failures, 64 D1 and 64 D2 calls, 128 real constructed own base
subobjects and 128 raw owners released, four joined workers. Candidate provider
SHA/UUID/RVA and files match before/after. There were zero VM/GPU calls and no
VM/HV/VMM/PVG images. Independently parsed evidence is retained separately in
`efi-native-rtti-v1/native-owned-base-verification.json`; frozen build files were
not modified after device execution.

The corresponding Mac fixture actually executed PID 26040, wait 0, 672 checks /
0 failures with its own genuine current Mac system code pins. Both probe D1/D2
imports are strong positive two-level imports from the exact candidate provider;
sixteen static weak/flat/wrong-provider/missing-binding negative controls reject.

The original27 EFI candidate now loads on iPad with this provider (Root's
`efi27-loadonly-native-v2`, PID 31857, wait 0). That load-only result did not call
EFI APIs and does not establish NVRAM behavior or a complete macOS27 backend.

Official layout/chain source is retained with license: LLVM 14.0.6
`libcxxabi/src/private_typeinfo.{h,cpp}`. Destructor variants follow the
[Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html).
