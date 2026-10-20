# Native CPU initialization slices

This application-private module uses the same opaque CPU handle, op6-created
context, driver instance, worker TLS and generation as the kernel lifecycle
module. It neither links nor loads an old Hypervisor provider. The writer is a
trusted bounded self-task callback; modern consumers never receive a raw
context, guessed Apple object, fake version or USER/VIEW pointer.

The initial native admission remains the exact iPadOS16.1.1 profile, native
HV ISA1, unchanged real context version0e and one fresh CPU. NativeISA2/3 are
not silently admitted by this local implementation. Every request must match
the actual slot word, owner and generation returned through CPU creation.
Each typed read/write rechecks current owner/TLS/live context and real version.

The default creation-policy slice follows the original13 `5544..55b8` stores:
default config vmkeys0 to6e8/6e0, OR678 bit56, OR670 bit18, read4030 bit4 and
conditionally clear670 bit20, OR670 bit19, OR748 bit2. It does not write4030,
copy the production value13, force a dirty word to a historical value, copy
modern dirty masks, or implement the old userspace CPU feature table. The
original postcreate feature-cache stage precedes this slice; implementing this
slice alone is expressly not the complete original create contract.

Original scalar IDs0..34 and SIMD IDs0..31 write only their genuine native
fields and widths. Those original setters do not change dirty748. Control
IDs0..16 follow the verified selector table and the original field-first
write, then OR678 bit56 /670 bit18 /748 bit2. ID0 andID6 alias synchronization
fields; their order matters. No architectural values are invented by the
module: the caller supplies typed values for its own CPU. Default keys remain
strictly scoped zero; nondefault modern config objects are not accepted.

A write callback can fail after partial mutation. The receipt distinguishes
attempted and completed writes; failure after any attempt poisons further
initialization and preserves the real owning-thread CPU destroy handle. It
does not claim rollback, exact restoration, or memory unchanged on failure.
Reentrant destroy during a write is rejected before the kernel. Normal cleanup
still uses exactly the native lifecycle destroy calls.

Full architectural reset and run requests explicitly return UNSUPPORTED.
The separate SYS adapter admits only its pinned typed selectors after this
default-policy slice. Every initialization receipt keeps
`architecturalResetComplete=false` and `runAllowed=false`. Missing work
includes the optional op8 contract, genuine modern feature/config/cache ownership,
original27 USER/VIEW/PAC/TLS callbacks, mapping/space lifetimes, and native exit
and cancellation translation. No run primitive is present in this module.

The complete pinned old reset inventory is in diagnostics
`native-cpu-initialization-v1/audit/contract.json`:109 static call sites,
41 unique authenticated callees, indexed SYS tables and17 exact control
selector branches. A static omission or same cached field value is not a
causal explanation of the earlier reason11/watchdog failure.

Local host models cover owner/slot/generation/profile/version rejection,
all35 scalar and32 SIMD fields, all17 control fields including aliases,
conditional policy RMW, partial failure and reentrant cleanup. They never
execute SVC or load Apple virtualization code. The optional isolated native
candidate creates only one VM/CPU, applies default-policy plus five own typed
writes, checks78 snapshot fields and destroys/reaps; no map, op8 or run is
possible through its operation filter. Native results must be reported
separately from these local model results.

Actual native1 evidence is now separate and complete for these bounded slices.
`kernel-initialization-native-v1` parent33999/child34000 returned0 for native
ops1/6/7/2; six default-policy plus five caller-supplied typed stores read back,
78 known fields checked and same-owner CPU/VM destruction completed. That
probe observed bit4=false but did not log the full4030 byte.
`kernel-system-native-v1` parent34488/child34489 additionally read the actual
4030 low byte3 and completed six default-policy plus seven same-value SYS
stores, all13 stores8 bytes wide with exact readback and owner cleanup.
Both tests performed0maps/op8/run/guest instructions.

`kernel-isa2-readonly-native-v1` parent35507/child35508 separately established
real native2 create/read/destroy, with unchanged version0e, actual4030
word0x0e1f00001f0def13 and byte19/bit4=true. Its two78-field snapshots matched;
it performed0writes/maps/op8/run. The tracked implementation still admits
native1 only. `native-isa2-system-probe-v1` is a separately frozen candidate
whose five scoped admission comparisons use native2; it requires the actual
bit4=true and tests seven default-policy plus seven same-value SYS stores.
`kernel-system-isa2-native-v1` parent35775/child35776 executed this exact
candidate: ops1/6/7/2 each0, seven default-policy plus seven same-value SYS
stores all8 bytes with exact readback,4030 byte19/bit4=true and78 fields
checked at all three snapshots. It kept0maps/op8/run, did not request software
feature-cache values, and completed owner CPU/VM destruction and reaping.
An independent receipt review rejected12 corrupted receipts. The tracked
API's native1 admission guard remains unchanged pending explicit integration.
Neither successful creation nor bounded writes prove guest execution or the
modern27 public CPU/USER/VIEW contract.
