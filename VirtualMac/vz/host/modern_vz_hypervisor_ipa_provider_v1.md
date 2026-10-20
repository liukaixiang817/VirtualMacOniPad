# Application-owned original27 maximum IPA provider v1

`VM27IPALimit.dylib` implements the exact original27 public ABI
`int32_t hv_vm_config_get_max_ipa_size(uint32_t *out)`. It performs one real
native capability operation0 on a private original352-byte zero-input buffer,
then caches that operation's actual status/result with `pthread_once`. There is
no fallback36, old13 runtime function pointer, VM/CPU creation, guest mapping,
guest memory access, CPU run, IRQ operation or iPadOS change.

The wire profile is deliberately limited to the verified M2 iPad14,3/4/5/6
iPadOS16.1.1 build20B101, Darwin22.1.0 with16KiB pages. The original old13
native buffer occupies352 bytes; the original public getter reads packed
little-endian64-bit fields at0x149 and0x151. Both high halves must be zero,
then the lower minimum is written as exactly four bytes. These offsets are
wire offsets; the genuine27 user-space capability object has different
internal offsets and is not treated as this native wire structure.

Before querying, the provider validates its private acquisition/trap are in
the same owned `VM27IPALimit.dylib` image, with its post-link actual Mach-O
UUID embedded as data, exact LC_ID and original12-byte `mov x16,-5; svc80;
ret` trap. It checks OS identity and records the calling thread's actual ID.
The query owns three pages; only the middle page is writable. Exactly352
zero bytes are32-aligned, all other middle-page bytes remain0xa5 canaries,
and the two outside pages are inaccessible. Returned packed fields are read
only after a returned native success with every exterior canary intact.
The mapping must be released before success is published.

A null public output returns `0xfae94003` without initiating a query. A real
native failure is returned/cached unchanged and leaves output unchanged.
Profile, own-frame, mapping, canary or packed-high-half failure returns
`0xfae94001`, also leaving output unchanged. A successful first query writes
exactly one uint32; all later calls use its actual cached minimum/status.

`VZFrameworkCopyMaxIPANativeReceiptV1` copies72 bytes of process-local receipt
without querying, allocating a mapping or invoking a native operation. The
receipt before initialization is all zero (`schemaVersion=0`, `queryCalls=0`),
which is explicitly unready. A usable success requires schema1, queryCalls1,
nonzero actual queryOwnerThread, actualNativeReturn/status0, every provenance
flag1, resultKnown1 and the actual packed-low minimum matching minIPA. Error
receipts may record some observations; only `resultKnown=1` authorizes using
minIPA. A copied receipt is diagnostic data, not proof of CPU execution.

The candidate exports only the original getter and the read-only receipt copy.
Its only runtime dependency is stock libSystem. The private engine's fixture
callbacks are not exported. It uses its own immutable production boundary.

The isolated operation0 actual receipt is
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/native-op0-tail-actual-v1/result.json`.
One returned native operation read0x24/0x24 with intact exterior and released
mapping; this established real IPA36 acquisition. It did not establish
independent CPU execution or successful original27 VZ/VMM initialization.
The new provider itself remains unexecuted on device until a separate actual
receipt is captured. Local fixture tests are not native query evidence.

The intended inert staging route is original27 VZ import559, original HV
ordinal26, `_hv_vm_config_get_max_ipa_size` to `@rpath/VM27IPALimit.dylib`.
The already separate maxVCPU import560 route is not changed. This source
does not edit any import route or deployed production file.
