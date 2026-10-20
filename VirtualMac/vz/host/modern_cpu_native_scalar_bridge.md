# Genuine native scalar values through the bounded original27 leaf

`modern_cpu_native_scalar_bridge.{c,h}` joins two already separated interfaces:
the fixed, same-owner native CPU reader and the original27 scalar accessor
bridge. It supports only X0..X30, PC, FPCR and FPSR. It snapshots the actual
kernel-owned CPU without old Hypervisor, copies only those explicit values
into an application-private input cache, invokes the exact audited genuine27
`0x3810..0x3934` helper through its existing signed-entry guard, and commits a
value only when the returned value equals the genuine native snapshot.

The private cache contains neither a modern/native version header nor a kernel
pointer. The preexisting scalar bridge uses a 24-byte bounded input holder;
only its +0x10 pointer is consumed by these exact 34 pure-leaf branches. This
holder is not an Apple USER, has no VIEW/vtable/callback, and must never be
passed to any public wrapper, constructor, other helper or VMM context consumer.
`hv_vcpu_get_reg` at `0x853a0` still requires genuine USER resolution and cannot
be bound to this utility. No replacement `hv_vcpu_get_context` is offered.

The 34 permitted branches have no native operation, observer, exception,
extended-vector selection or dirty write. CPSR ID34 enters a real VIEW and is
rejected before the native read. Original27 SIMD `0x8ae4` has a different
contract: `raw+0x4140` bit0 chooses an ordinary 128-bit lane or a real extended
vector buffer/stride at +0x4150/+0x4148. This bridge does not claim that feature
or use a fabricated flag to choose the ordinary path.

Local mock checks exercise real adapter ownership/snapshot/guard logic with
nonzero per-field values and a clearly synthetic leaf fixture; they prove no
Apple image execution. Earlier genuine-helper fixtures used private patterned
cache inputs, and the independent v4 device run proved 78 genuine native reads.
Root has now executed this joined route on iPad. The exact receipt is
`kernel-modern-scalar-native-v1`: main/outer process31541, CPU diagnostic
child31542, 34 native snapshot→genuine27 helper parity records, all true,
103 exact helper byte/identity verifications, CPSR34 rejected before read/helper
with output unchanged, and zero old13 images. Native op1/6/7/2 each returned0,
all handles were freed on their real owners, pthread joined, child wait0 and
both processes were subsequently absent. The main compiled zero driver copies;
one SHA/UUID-gated private dylib owned every CPU/VM handle and TLS entry.

The genuine native context version remained `0x206879700000000e`, with zero
guest instructions and native writes. This is execution proof for the joined
restricted value route on a newly created empty CPU. It does not show nonzero
guest architectural state or the public modern wrapper on a running guest.
Full original27 CPU creation/reset/run/exit, USER/VIEW and all 257 VMM context
consumers remain separate integration work. Original delivered binaries,
manifests and exact source snapshots are unchanged.
