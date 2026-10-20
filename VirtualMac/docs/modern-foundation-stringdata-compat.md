# Private Foundation String.data compatibility

The original macOS 27 DiskImages2 image calls the concrete Swift
`String.data(using:allowLossyConversion:)` overload. Apple's current SDK marks
that overload as iOS 18 / macOS 15; iPadOS 16.1.1 does not export its symbol.
The older `StringProtocol` overload and the Objective-C `NSString` encoding
method remain available.

`modern_foundation_stringdata_compat.swift` defines a private method on Apple's
real Swift `String`. It delegates conversion to system
`NSString.data(using:allowLossyConversion:)`, returning the system's real
`Data?`. The linker exports exactly one alias for the missing concrete method.
Its `swiftcc` return `{ i64, i64 }` and arguments
`ptr noalias, i1, i64, ptr` match an original SDK generated direct caller.
There are no fabricated Foundation types or global hooks.

The original SDK fixture imports Foundation and Darwin only. Its function
selects the concrete overload under an iOS 18 / macOS 15 availability context.
Only that symbol's LLVM declaration changes from weak to strong; generated
instructions and pointer authentication remain unchanged. The fixture compares
17 encodings across 12 strings and both lossy settings against real NSString
and the legacy generic overload, verifies UTF-8 bytes and nil conversion,
and checks Data copy-on-write ownership.

Local build `foundation-stringdata-sdk-build-v1` completed actual macOS execution
with PID 93028 and wait 0: 3368 original SDK calls, 6824 checks, 440 nil results,
and 192 copy-on-write checks. The scoped iOS build then completed actual iPad
execution with PID 42156 and wait 0, the same 3368 SDK calls, 6824 checks,
440 nil results and 192 copy-on-write checks. The externally checked PID was
absent, and the two staged file hashes/CDHashes were checked again afterward.
`foundation-stringdata-native-independent-review-v1` reparses the saved
receipt with JSON type checks and confirms all 26 source pins are unchanged.

The new DI2 candidate is `diskimages2-foundation-loadonly-build-v2`. It changes
only import row 78 from system Foundation ordinal 14 to the private umbrella
ordinal 32 relative to the frozen HPKE candidate. All 818 import names,
770 strong imports / 48 original weak imports, original code and section data,
five RTTI address points, and authenticated pointer words remain unchanged.
The 60 private import routes and 31 original dependencies are retained.
Fourteen file signatures and eight mutated-image controls passed static review.

The candidate READY record binds the successful scoped original SDK fixture
receipt on the iPad as a prerequisite for loading this candidate.
The genuine macOS 27 DI2 image then loaded on the iPad with PID 42417 and
wait 0. The 88 saved transcript rows verify 60 provider identities, five
original Objective-C classes and eight original method ABIs/RVAs. All 35
candidate pins and 18 Foundation actual-result pins remain unchanged.
`diskimages2-foundation-native-independent-review-v1` also rejected five
mutated actual-receipt controls. No DI2 method was called in this load test.

`diskimages2-foundation-owned-raw-build-v1` is the next scoped fixture. It
preserves the 13 libraries from that successful load byte-for-byte and uses
the previously reviewed genuine DI2 Objective-C caller. It creates only one
new 0600, 128 KiB regular file in its own root-private diagnostic directory.
The borrowed original framework fd must match the file's device/inode and
strict read/write flags. The fixture makes at most one 4096-byte write and
three 4096-byte reads, uses publicly declared iOS `fsync` for persistence,
checks genuine handle destruction and reopen/readback, and verifies a real
NSError for an owned nonexistent filename. It checks ten desktop Security
counters before and after; no attach or guest image is involved. The parent
must observe the actual exit status, PID absence and owned-file cleanup.
Fourteen signatures passed independent static review, and 21 malformed
receipt models were rejected. The first RAW run, PID 43962, exited 81 after
five original DI2 calls. It obtained the correct owned-file read/write fd,
completed two reads, one write, fsync and readback, then failed the destruction
and fd-close check. It removed its own file; the parent verified the exact
PID and all own files were absent. The whole run remains failed.

The original `openWithError:` method returns the allocated/initialized handle
directly with +1 ownership, without autoreleasing that return. The first
fixture incorrectly retained it again. `di2-open-owned-return-static-audit-v1`
compares the original and executed candidate's 640-byte open method, 208-byte
initializer and 68-byte C++ destruction method and records their exact hashes.
The new `diskimages2-foundation-owned-raw-build-v2` consumes that +1 return
without an extra retain, releases an unexpected owned error return, and emits
an explicit JSON Boolean summary. All 13 framework/provider library files
remain unchanged. A complete source comparison limits changes to five diff
hunks; 22 malformed receipt models are rejected, including the original
actual exit 81. The actual second run, PID 46014 with wait 0, completed
41 checks and 12 original DI2 object/descriptor calls. Both genuine handles
closed their borrowed fds on destruction, and reopen verified persistent
readback. The data I/O comprises three direct POSIX reads, one direct POSIX
write and fsync on an fd returned by the original framework; this does not
exercise original DI2 data read/write methods. The own 128 KiB file was
removed, and the parent checked the exact PID, all own filenames and all
14 staged file hashes/CDHashes/root owners afterward.

The original wrapper's failed result remains unchanged: its parser expected
a JSON Boolean for `hasNSError`, while the frozen Objective-C C11 expression
`@(error != nil)` boxes an integer. Original-target SDK AST analysis confirms
`BinaryOperator 'int' '!='` and `selector=numberWithInt:`. The saved program
reported integer 1, real NSPOSIXErrorDomain/code 2, and an explicit Boolean
success summary. The new saved-only adjudication preserves all original
bytes, requires that exact integer type without coercion, and rejects 12
malformed controls. It records actual functional RAW success separately from
the old failed wrapper.

`diskimagekit-genuine-di2-loadonly-build-v2` first failed on the device at
PID 46580 with wait 78: genuine DI2 and DIKit loaded, but discovery stopped
at original Swift `_swiftImmortalRefCount`. The original Swift nlist marks
this symbol N_ABS with value `0x80000004ffffffff`, rather than an address of
allocated data. A private assembly provider exports that exact absolute
value, without dereferencing it. Original macOS runtime discovery and a
local standalone provider both return the same value.

The resulting `diskimagekit-genuine-di2-loadonly-build-v3` passed on the
iPad at PID 47088 with wait 0. The saved 117-row receipt confirms 168 imports,
245 bootstrap checks, 20 original requirement pointer authentications,
three authenticated static ISA bindings before and after, restored current
and maximum protection for one owned page, and exact absolute discovery
with zero data dereferences. The parent confirmed exact child absence and
all 20 staged hashes/CDHashes/root owners afterward. This run executes no
original DIKit metadata or disk API.

The DIKit candidate retains the 13 genuine DI2 libraries and three scoped Swift providers
byte-for-byte. Only DIKit's original dependency ordinal 4 path changes to
its private genuine DI2 sibling; all 164 strong import rows, chain/PAC words
and nonempty section bytes are unchanged. Its original bootstrap source is
recompiled solely to pin the new DIKit file hash. Nineteen file signatures
and dyld validations passed. The isolated caller requires 168 original and
current imports, three authenticated ISA bindings before/after, 20 original
requirement pointer authentications, one owned page with restored current
and maximum protection, and exact identities for five added libraries.

The subsequent nine-type metadata run, PID 47608 with wait 83, failed the
strict scoped ownership metadata check after successful bootstrap and
absolute discovery. Its original receipt, source, and whole failed result
remain preserved. The saved text does not record the query's return status
or actual layout fields. A new private observer therefore records exact
metadata call/type/state, query status with sentinel-filled output,
primitive function identities, and bounded read-only value-witness/layout
fields. The context observer, PID 48132 with wait 83, confirms that the real
query succeeds but the old Mac dimension comparison fails. The subsequent
field observer, PID 48646 with wait 83, records the actual Foundation URL
nominal type: size/stride 8/8, and genuine ASIF offsets 0/8/16, size 17,
stride 24. The original Mac has URL size 16 and ASIF size 25/stride 32.
All three original failed golden-comparison receipts remain failed and
unchanged. A failed cached-library realpath or heap-metadata dladdr
observation is not evidence that the primitive or type is absent.

The original SDK declares URL and the public DIKit configuration structs
without `@frozen`. Exact original ASIF/Open factory and getter instruction
slices read the runtime metadata offset vector and authenticate the actual
URL value witnesses; they do not require a fixed 16-byte URL layout.
This establishes the dynamic layout access, while real typed value and
ownership tests are still needed to establish semantics on the old runtime.

The first 128-iteration original SDK semantic run, PID 49507, hit its
3-second CPU limit with wait 152 after reporting five real SDK dimensions.
It did not complete a semantic or ownership summary; the saved output cannot
distinguish slow repeated work from a first-call stall. Its whole failed
receipt and frozen candidate remain unchanged.

A new one-iteration diagnostic passed on the iPad at PID 50339 with wait 0.
It authenticates seven original configuration factories/getters before
calling them through the real original SDK types. All 286 before/after
checkpoints close, including Mirror iteration, dynamic casts, public
getters, value copies, Array copy-on-write, and weak NSURL destruction.
The run completes 12 configuration checks and three real ownership checks
with eight known original factories. Implicit SDK metadata/getter calls are
not included in that factory count. The child was absent afterward and all
21 staged file pins were preserved. No padding or original Mac golden
comparison was changed; the single round does not establish the previous
128-round CPU budget or all nine metadata interfaces.

Two new local 16-round A/B candidates use byte-identical original SDK
fixtures, the same CPU 5/6-second limits, and a 10-second wall limit. The
second candidate changes only the private compact-witness provider's fixed
nine strong Swift primitive identity validation to `pthread_once` and
retains its own already-loaded runtime image handles until child exit.
The original dynamic metadata, layout, nested witness and ownership
validation code remains unchanged. Both candidates report per-iteration
CPU/monotonic timestamps, 192 semantic checks, 48 weak ownership checks,
and then nine explicit original metadata calls/33 scoped queries. Both
completed actual iPad execution: original PID 50884 and cached PID 51380,
each with wait 0. The repeated SDK workload uses 1,373,129,000 CPU nanoseconds
with the original provider and 344,029,000 with the cached provider, about
3.99 times faster in this single same-workload comparison. Both complete
192 semantic checks, 48 ownership checks and all nine metadata/33 query
checks, with unchanged values. Initialization and dimensions occur before
this timing window, so this is not an application cold-start or guest-speed
measurement. The counter means one cache initializer run; that initializer
keeps the original nine identity checks and revalidates each of its nine
owned runtime-image references. Dynamic metadata/layout remains uncached.

A new strict 128-round regression candidate preserves the exact original
SDK fixture binary, signature, source and bodies from failed PID 49507. It
uses the successful cached provider and the old CPU 3/4-second and wall
10-second limits. Only its separate caller adds four call-boundary/timing
records and two cache-status observations. No internal per-iteration
progress can be added without changing the preserved fixture. This strict
regression then completed on the iPad at PID 51882 with wait 0 and 147
strict transcript rows. It completes 1536 configuration checks, 384 weak
ownership checks, 1024 known original factories and nine metadata/33 queries
within the old limits: 2,692,308,000 CPU nanoseconds and 2,692,472,000 wall
nanoseconds for the SDK workload. The cache initializer remains one before
and after. The parent confirms exact child absence and all 21 file
hashes/signatures/root owners afterward. The independent saved-result
review retains all 161 candidate pins and the old PID 49507 failed receipt.
The old Mac golden failures also remain unchanged; this is a new verified
host-runtime semantic contract, with no layout padding change.

Loading alone does not prove DiskImages2 methods or RAW disk I/O work. This
compatibility step does not establish a complete macOS 27 CPU/VMM/VZ backend.

References: [Apple String documentation](https://developer.apple.com/documentation/swift/string/data(using:allowlossyconversion:)),
[Apple NSString documentation](https://developer.apple.com/documentation/foundation/nsstring/data(using:allowlossyconversion:)).
