V5 is an alternative application-private lifecycle unit. Link V5 alone instead
of V4/V3/V2. Existing source, snapshots and frozen products remain unchanged.
The native create/control abstraction retains its four native call expressions,
fixed op6 16-byte `{0,0}` packet, op7 NULL argument, exact full64 context magic,
actual CPU owner pthread/private TLS, stable VM epoch and process-monotonic CPU
generation. Multiple own worker handles are modelled; actual native allocation
of multiple CPUs using fixed request0 is still unproved. No Run is supplied.

Five new own APIs address the real dangling-pointer gap in an external VMM
adapter. Publish only accepts the actual owner CPU whose initial CPUCreate
completed successfully and validated version `206879700000000e`. A private
cleanup handle from a failed read/version never becomes publishable, even if a
later separate read could succeed. The independent nonzero own identity is
process-monotonic, never reused across VM epochs, and unrelated to the native
returned slot, CPU generation, thread number or an Apple USER/VIEW object.

BorrowIdentity obtains the process registry lock before dereferencing the
current VM, then the VM mutex. It retains the actual entry in a real linked
borrow allocation containing exact VM epoch, CPU generation and actual
borrowing pthread. CPUCreate uses the same registry-before-VM lock order. No
callback is invoked while either lookup lock is held; acquisition and release
invoke no native/read/write/currentThread callback at all.

BorrowHandle acquires the borrow guard and then CPU guard before any
currentThread callback. It requires the actual borrowing pthread, actual CPU
owner pthread/private TLS, retained list membership, same VM epoch/generation,
live VM/CPU, completed creation and no drain. Only a valid retained allocation
allows safely obtaining the CPU pointer before this validation. Synchronous
release/free/destroy/get/set/unpublish/publish reentry refuses BUSY, preserving
output and resources. ReleaseBorrow is sealed to its actual acquiring pthread
and removes only that exact retained entry reference. Already freed CPU/borrow
pointers remain invalid C; this does not promise safe arbitrary pointer input.

Unpublish permanently denies lookup of that issued identity and starts drain.
Existing borrows remain allocated for release; BorrowHandle refuses further
use during drain. CPUDestroy stops new lookups before checking the real borrow
count/list. It refuses BUSY without a native call while any reference remains;
after release the actual CPU owner may retry teardown. A native destroy failure
keeps the live private cleanup handle, pending state and unpublished/draining
entry. CPUFree rejects a live, published or borrowed entry and requires its
actual original owner pthread. Every retained handle, including dead handles,
still blocks VMDestroy until free. A stranded exited owner remains tracked;
there is no fake owner override or automatic freeing on a foreign thread.

All five API refusals preserve supplied outputs. Outputs must be disjoint from
the VM and every CPU/entry/borrow allocation, including partial overlap and
address-wrap cases. The unchanged pending read now applies the same extended
private-allocation boundary. Pending values are own calloc-backed booleans,
not claims about native defaults. Pending APIs add no native reads/writes.

VMCreate rejects an existing registered VM or exhausted generation before
calling currentThread. This corrects the independently reproduced V4 admission
ordering issue where a rejected replacement's injected callback could destroy
and free the old drained VM, allowing the replacement to proceed. V4 evidence
is retained. The new regression verifies existing-VM BUSY with zero callback,
zero new mock operation and unchanged old resource.

Local validation uses actual pthreads with injected ordinary C mocks, not
kernel traps. It tests owner/borrower seals, incomplete creation, callback
reentry, generation/VM-epoch/list corruption, overflow, private aliases,
unpublish/stale IDs across VM lifetimes, pending access during borrow pressure,
and four concurrent lookup threads alongside 64 create/destroy/free cycles on
another actual owner worker. Ordinary and ASan/UBSan models include all V4
multi-CPU/owner-exit, V3 pending/callback and ISA1/2 V2 lifecycle/init/system
regressions. Ten actual changed C source models are compiled and fail the
required refusal invariants. Separate C++ linking checks the five new C APIs;
normal/ASan alias models verify that pending cannot overwrite borrow storage.

The strict arm64e iOS candidate exports exactly the old 21 symbols plus these
five own identity/reference APIs, with unchanged undefined system imports,
empty entitlements and no candidate loading or deployment. The frozen pure
pending setter is still hidden; entry/return planners remain dead-stripped.

This identity is **not an Apple public CPU ID publication**, and a retained
entry is **not a native Run/post-return lease**. No public `hv_*` symbols are
exported. The actual original27 VMM still requires a separate 296B C++ CPU
object, ID at +0xd8, persistent provider exit pointer at +0xe0, exact public
Mach statuses/config/register/SME/private/GIC APIs and a real guarded Run
operation. V5 does not create the missing public 32B exit allocation, map
success into public `hv_vcpu_create`, apply entry plans, enlarge native request
slots or install wrappers. No USER/VIEW casts, old13 forwarders, observed-value
defaults, initialization write authorization, raw11 cause, absence inference,
device operations, native Run/retries or full27 acceptance are introduced.
