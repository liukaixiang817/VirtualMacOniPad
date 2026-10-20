The application-private SYS adapter implements an explicitly bounded part of
the original iPadOS16.1.1 native context contract. It is not an Apple27
USER/VIEW object, does not claim the modern public SYS wrapper has run, and
never changes the genuine context version or policy4030.

`native-system-register-contract-v1/audit.py` pins the exact old Hypervisor
SHA c40d039280f8048b9e921d2ea7181e50e7e6dd693614cc494baa4d7f43d8efe4.
Stock LLVM disassembly and a bounded integer-only CFG evaluator enumerate all
65536 encoded selectors and crosscheck152 SDK cases against prior receipts.
The engine exposes154 physical u64 descriptors, nine requested-feature u64
cache entries, and two genuine control routes. Unknown32-bit selectors leave
the descriptor/read output unchanged and cannot cause native field access.

Original getter5d30 reads dirty748 first, even when the descriptor mask is0.
For a nonzero mask it next reads ready4100; the field can be consumed if
`((dirty748 | ready4100) & mask) != 0`. Original setter6c0c needs only actual
ready4100 for this decision, regardless of existing dirty748. It writes the
field before reading and ORing the decoded mask into748. Mask0 setters write
only the8-byte field. The new engine preserves these read/store orders and
uses masks decoded from the real old kernel descriptor, not copied modern
dirty words. If readiness would require original op8(NULL), it returns
UNSUPPORTED with `nativeOp8Required=true`, before any store. There is no op8
or guest run primitive in this module.

The two outer SYS selectorsc000/c005 read raw698/690 respectively and their
setters use original control5/3 semantics: field,678ORbit56,670ORbit18,
748ORbit2. The nine feature selectors arec020/c021/c028/c029/c030/c031/
c038/c039/c03a; they affect only this CPU's explicitly requested-value cache.
Each cache entry is invalid on a fresh CPU until an explicit setter supplies
it, and CPU destruction discards it. Their getter does not return invented
host capabilities or seed zero-valued defaults.

The old0x118-byte per-CPU table contains considerably more than those nine
values. Original510c seed writes **0xe0 continuous bytes**, from table+8
through+e7. It includes12 feature/cache u64s at+8..67 and128 bytes of CCSIDR
at+68..e7. The config-feature getter exposes selectors0..11;10/11 read the
last two u64s in reversed order. The CCSIDR getter copies64 bytes per group:
selector0 from table+a8, selector1 from+68. The seed depends on genuine host
capabilities and SDK-conditional masks; it is not implemented by this nine
entry requested-value cache. Table+0 is a native context pointer. The later
`native-op8-run-contract-v1` audit identifies table+e8 pending IRQ/FIQ shadow
bits7/6 and the entry/return synchronization through control0; its other
bits remain unclassified. Table+f0 is the u32 public exit reason, +f8/+100/
+108 are u64 syndrome/virtual/physical addresses, and+110 saves the original
native6d8 bit0 as one byte. Remaining padding and all exit cases are not closed.
Full-table classification, capability acquisition, and original27 object
bindings remain separate work.

The public typed entry uses the same opaque CPU/VM and driver instance as
create/destroy. It checks real owner TLS/thread, generation, returned slot,
nativeISA1, pinned OS profile, unchanged real version0e, and completed default
creation-policy slice. Every callback repeats the ownership/version gate.
READ commits its output only after all checks succeed. Failed or possibly
partial writes poison further initialization, while preserving same-owner
CPU destruction. Reentrant destroy is rejected before kernel invocation.
No policy/version/ready field is writable through this adapter.

NativeISA1 admission records only what the independent lifecycle and typed
initialization probes have established. It is not a semantic claim about
AArch64 or the production guest. Original VMM serialized0 maps to native2,
serialized1 to3, serialized2 to1; unknown serialized values are rejected by
the new closed conversion helper. The production guest uses native2 and
policybit4=true. The initial native1 initialization observed only bit4=false;
the subsequent native1 SYS test directly read4030 low byte3. The earlier native2 v29
reason11 loop and native1 controls both lack a successful instruction/trap
oracle. Neither flag differences nor this SYS model prove their root cause.
A separately gated native2 create/read/destroy milestone has now passed:
`kernel-isa2-readonly-native-v1`, parent35507/child35508, ops1/6/7/2 each0 with
same-owner CPU/VM destruction and both processes reaped. It read the real
4030 word0x0e1f00001f0def13, low byte19 and bit4=true; version0e remained
unchanged and two78-field snapshots matched. It performed0writes/maps/op8/run.
This is native2 read-only admission evidence, not permission to manufacture
policy4030 or replace a real version.

Current native proof: `kernel-initialization-native-v1` actual parent33999 /
child34000, native ops1/6/7/2 each0, six default-policy plus five typed writes
all read back,78 known fields exactly checked and complete owner cleanup.
`kernel-system-native-v1` actual parent34488/child34489 then returned0 for
ops1/6/7/2 and complete same-owner destruction. It directly observed4030
low byte3/bit4=false, completed six default-policy plus seven same-value SYS
stores (13 exact8-byte writes/readbacks), checked78 fields and kept0map/op8/run.
Its nine software feature-cache tests used explicit caller-requested values;
they did not acquire real capabilities or install the complete0x118 table.

The tracked production API still admits native1. A distinct frozen
`native-isa2-system-probe-v1` changes five scoped admission comparisons to2,
requires the actual bit4=true, and tests seven default-policy plus seven
same-value SYS stores, with no requested feature-cache setters. Its155228
portable checks and candidate file/signature gates passed. Its separate actual
`kernel-system-isa2-native-v1` parent35775/child35776 returned0 for
ops1/6/7/2 with owner cleanup and process reaping: seven default-policy plus
seven same-value SYS stores, all14 exact8-byte writes/readbacks, byte19 and
bit4=true, three78-field snapshots, no feature-cache request and0map/op8/run.
Its independent receipt review rejected12 malformed receipts. This scoped
result does not change the tracked native1 admission guard. In all
receipts `completeModernSYSContract=false` and `runAllowed=false`.
