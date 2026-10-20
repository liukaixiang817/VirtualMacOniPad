# DiskImages2 RTTI reconstruction

The genuine macOS27 DiskImages2 reconstruction incorrectly names five imported
RTTI **data address points** as complete destructors. None of these five names
exists in its original undefined nlist. An independent read of all 1,189
original cache slide-v5 chains and the exact libc++abi export trie proves the
actual target is the native `__ZTV…` export **plus 16 bytes**:

| Type | Original slots |
| --- | ---: |
| `__class_type_info` | 192 |
| `__si_class_type_info` | 632 |
| `__vmi_class_type_info` | 363 |
| `__pointer_type_info` | 1 |
| `__function_type_info` | 1 |

The cached owner is `/usr/lib/libc++abi.dylib`, original Mac UUID
`a21743ee6e1c3e7497ea7af793de4bdf`. The original vptr authentication is DA,
diversity zero, no address diversity. The reconstructed pointer words already
retain that authentication correctly; an early manual interpretation of those
bits was wrong. The fix changes the **symbol, positive owner and addend**, and
does not change any of those 1,189 pointer words.

`scripts/development/prepare-modern-diskimages2-rtti-data.py` requires the exact
original oracle and input hashes. It adds a strong libc++abi dependency and uses
the official `DYLD_CHAINED_IMPORT_ADDEND` format2 to retain each `+16` address
point. It preserves every other import name, ordinal and weak flag. No
destructor code, synthetic vtable, allocation or object-deletion layout is
implemented. The original Mac owner UUID is an extraction oracle; iPad must
use its real native libc++abi vtable exports, not the Mac library.

The frozen final candidate is
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-rtti-data-build-v2`.
It retains genuine DiskImages2 UUID `a456d4a4d6ab3549965d0400f3552de3`.
Both Mac and explicitly platform-only iOS variants pass codesign strict and
dyld validation. `scripts/tests/validate-modern-diskimages2-rtti-data.py`
independently verifies all 33,386 chained pointers, all old payload bytes
unchanged, the five strong vtable imports with addend16, and four negative
controls rejecting IA keys and missing addends. Review evidence is retained in
`di2-rtti-data-independent-review-v2/verification.json`.

These candidates have **not been loaded or executed**. Original reconstruction
flat-import semantics outside these five rows, other modern imports, and
metadata remain unresolved. This is an extraction repair, not a complete DI2
closure or runnable macOS27 backend. The frozen v1 binary bytes are identical
to v2, but its manifest wrongly calls all 1,189 PAC slots “corrected”; v2
correctly records 1,189 validated slots and zero changed PAC slots.

Do not route the old five converter names to a D1 function provider. Downstream
readers must support format2 import entries (word plus signed32 addend); a
format1-only parser cannot safely inspect this image.
