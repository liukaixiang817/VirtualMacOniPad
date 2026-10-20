# Application-private kernel CPU lifecycle

`modern_cpu_kernel_lifecycle.{c,h,S}` implements a restricted direct bridge to
the iPadOS 16.1.1 native hypervisor Mach trap. It does not link or load the 13
Hypervisor framework. The initial scope is one VM and one CPU, native
create/read-version/destroy only. It does not execute guest instructions,
initialize architectural state, construct Apple's modern USER/VIEW, implement
the public exit record, or expose a replacement `hv_vcpu_get_context`.

The assembly entry is the exact 12-byte trap used by the original host provider:
`movn x16,#4; svc #0x80; ret`, with operation in x0 and argument pointer in x1.
The C layer admits operations 1, 2, 6, 7 only through its lifecycle API. The
launcher verifies the trap's bytes and own-image provenance before calling it.
No system code or kernel state layout is patched.

## Verified original input contract

The source bytes are pinned under
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/context-consumer-adapter-v2/audit/`.
Original host Hypervisor SHA-256:
`c40d039280f8048b9e921d2ea7181e50e7e6dd693614cc494baa4d7f43d8efe4`.

| Operation | Input | Source evidence |
| --- | --- | --- |
| 1, VM create | reserved u64@0, IPA limit u64@8, granule u32@16, nativeHVISA u32@24 | `4af4..4b50`, call `4b40` |
| 2, VM destroy | NULL | `4b50..4b5c` |
| 6, CPU create | requested slot u64@0, output context pointer u64@8 | `53f0..55e8`, call `5464` |
| 7, CPU destroy | NULL; the current owning thread identifies the CPU | `55e8..5658`, call `5608` |

The public configuration descriptor is a private C value, not an Apple OS
object. The translator currently admits only 36 IPA bits, granule 0, native
HV ISA1, EL2 false and VHE false. These are the exact original host constructor
default inputs. Unknown/modern-only options return UNSUPPORTED before native
calls. This does not claim a hardware capability maximum. The old field name
`serializedISA` was inaccurate: this32-byte native input holds the value of
the genuine Hypervisor config getter, not the VMM serialized `isa` property.
Old executed source snapshots preserve the historical name and are unchanged.

The original VMM at `d9ff8..da034` maps serialized2 to nativeHVISA1,
serialized1 to nativeHVISA3, and all other32-bit values to nativeHVISA2.
`VZKernelConvertSerializedGuestISA` now distinguishes these namespaces and
admits only scoped serialized0/1/2, mapping them to2/3/1 respectively. Unknown
values are rejected with the output unchanged; it does not infer architectural
names for the numeric selectors. The initial lifecycle translator still admits
only nativeHVISA1, preserving its actual verified default32-byte input and
restricting native execution to the previous create/destroy milestone.
Converted nativeHVISA2/3 do not silently broaden that execution profile.
The earlier nativeHVISA1 CPU-run control returned HV_UNSUPPORTED; creating and
destroying a nativeHVISA1 CPU is not guest execution proof.

The old provider passes at least the first 28 meaningful bytes of the VM input
within its stack frame; this implementation zeroes a complete aligned 32-byte
struct, including both reserved words. It does not copy an opaque modern config
object. Modern frontend integration must capture genuine modern getters and
translate their meanings into these explicit inputs.

The kernel's successful CPU-create result yields its genuine context pointer.
The module reads eight bytes at `+0x4000`, using a bounded self-task read, and
requires the unchanged real host version `0x206879700000000e`. A wrong or
unreadable context does not become a fake modern context. The native-created
CPU remains represented by a live recovery handle, and must still be destroyed
on its actual owner thread. The raw context pointer is never returned to a
modern VMM context consumer.

## Ownership and failure behavior

The VM records its creator's actual pthread ID. CPU create is performed by the
caller's actual pthread; module TLS reserves its live handle before the native
call. This TLS belongs to the compatibility module and does not overwrite the
original VMM's TLV state. One process registry and a mutex block overlapping VM
creation. A per-VM reservation blocks competing CPU creation and VM destruction
while a CPU create is in progress.

Every native return code is preserved separately from adapter validation status.
Neither a populated ID nor a non-null context is substituted for native success.
Wrong-owner calls and double destroy are rejected before reaching the kernel.
Failed native destroy preserves ownership for an explicit same-thread retry.
Live handles cannot be freed; outstanding CPU handles keep the VM allocation
alive. Caller-owned pointers must remain valid until their successful free;
this is not a general stale-pointer registry.

Create/read/destroy alone writes no version, GPR, feature, native control or
dirty byte. The optional separately linked
`modern_cpu_kernel_initialization.c` now provides owner-bound default creation
policy, scalar/SIMD/control slices; see its contract for scope and failure
behavior. Complete feature/reset, modern USER/VIEW and run remain separate
work. The old public exit buffer was an old
userspace table entry; native op6 does not return a public 32-byte exit object.
This module therefore does not pass a fabricated exit pointer to the original
27 CPU constructor. A future original constructor binding must implement the
real userspace exit lifetime/translation and architectural initialization first.

## Independent diagnostic and acceptance boundary

The build output is
`context-consumer-adapter-v2/candidate/vm27-kernel-lifecycle-probe`. It has four
scoped entitlements: platform-application, no-container, private.hypervisor and
security.hypervisor. It imports only stock libSystem facilities, never dlopens
anything, and refuses any process already loading Hypervisor or Virtualization.
The profile gate admits Darwin 22.1.0 / 20B101 and M2 iPad14,3 through iPad14,6.
The platform profile is a pinned safety gate, not a claim that a local mock can
verify the actual device's driver.

Run only while the production VMM/installer/GPU workers are stopped:

```sh
./vm27-kernel-lifecycle-probe --kernel-create-destroy
```

The parent starts its same signed executable as a child. It bounds that child to
eight wall seconds with an extra one-second reap window. The child has a two CPU
second limit and uses a default-attribute pthread for op6/op7. Normal completion
requires successful native op1, op6, two unchanged real version reads, same-owner
op7, native op2, and successful freeing of both private handles. A context-read
failure still takes the same-owner destruction route. A join or native destroy
failure returns strict failure, preserving the failure in JSON lines.

The watchdog kills only its child. A timeout is strict failure and explicitly
does not claim same-owner cleanup or that a blocked kernel syscall was recovered.
The controlling host must verify the child is gone and the iPad/SSH remain
responsive before further tests. Host process/device checks and deployment are
the Root agent's responsibility; this module/build performed neither.

The local mock fixture covers eight scenarios and 257 checks, including native
errors, mismatched/unreadable/null context, wrong-thread access, competing
creation, double destruction, failed destruction recovery and byte-for-byte
unchanged native pages. It links no SVC trampoline and executes zero kernel
hypervisor operations. Signature, actual entitlement, dyld validation and import
checks also pass for the iOS candidate. Device execution is not inferred.

Root's actual native lifecycle receipt is now saved under
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/kernel-lifecycle-native-v2`.
PID30414 completed native op1/6/7/2 with all returns0, real native context
version `0x206879700000000e`, same worker ownership, creator VM cleanup,
successful handle frees, native wait0 and child absence. Zero old13/HV/VZ
images were loaded. The actual main was dyld index1, which explains the first
diagnostic gate failure; the corrected gate resolves `dladdr(main)` and checks
its actual UUID, bounded load commands and all twelve SVC bytes.

The subsequent `kernel-context-native-v1` receipt records PID30847 reading all
78 fixed native fields twice, unchanged, and completing the same native
create/destroy/cleanup with no old13 image. Native control/synchronization
words +670/+678/+748/+4100 were `0x0000030000100000`,0,0,all-ones. The physical
values are private typed observations, not a fabricated modern context page.
Exact deployed source snapshots and manifests are retained in v3/v4 diagnostic
directories; later modules are separately versioned.

These PASS results prove restricted independent kernel lifecycle and fixed
read-only fields. They do not prove full original27 Hypervisor, VMM, VZ,
architectural initialization, run, exit, interrupts or guest boot. The original
27 hard native-version check and 257 context consumers remain to be adapted.
Modern USER/VIEW/dirty and extended-vector state must retain real semantics.
