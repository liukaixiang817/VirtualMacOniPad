The V3 lifecycle is an alternative implementation unit of the existing private
CPU bridge. It preserves the V2 API and adds only
`VZKernelCPUSetPendingInterruptV3` and `VZKernelCPUReadPendingInterruptsV3`.
Compile `modern_cpu_kernel_lifecycle_v3.c` instead of
`modern_cpu_kernel_lifecycle_v2.c`; linking both defines the same legacy APIs
twice. Existing builds continue selecting V2. No existing header, source,
frozen product or build script is changed by this addition.

The original pending contract audited in
`native-pending-control-return-contract-v1` uses IRQ/FIQ types 0/1 and separate
pending bits. V3 stores equivalent typed application booleans in its own opaque
CPU allocation. Both start false because the new private field is calloc
allocated; schema=1 is set during private CPU construction. These values do
not claim to be native context or kernel creation defaults. The complete
frozen pure-value source/header are copied byte exactly; V3 calls only its
setter, including a same-value invocation to validate a read. The iOS build
compiles that module with hidden visibility and dead strips both unused
entry/return plan functions.

Both APIs acquire the CPU's atomic operation exclusion before invoking
`currentThread`. They then require the actual owning thread, the private
`OwnedCPU` TLS, a live VM and CPU, the VM's actual active CPU and the same
internal current generation. An arbitrary supplied owner value, native slot,
run token or lease cannot substitute for this binding. No native context read,
write callback or trap is performed. A callback reentry returns BUSY while the
outer CPU still owns exclusion; it cannot destroy or free the resource.

Set accepts only typed IRQ/FIQ and an exact 0/1 pending value. The frozen pure
setter validates schema, both booleans and reserved state in a separate staged
value. Read uses the same validation and stages all output until success. Its
output must be valid caller-owned application storage disjoint from the entire
private CPU and VM allocations; whole/partial aliases and uintptr range wrap
are refused. All refusals preserve actual pending state and read output.

Genuine successful owner-thread CPU destroy clears the added private state
under existing exclusion; a native destroy failure preserves pending values
and the live cleanup handle. Free follows the original V2 guards and clears
the private field before releasing storage. A retained destroyed handle rejects
new pending operations. A newly created CPU starts its own separate values
and cannot borrow the previous handle's generation or TLS identity. A freed
pointer is no longer a valid handle and must not be passed to any API.

The existing native initialization/system paths and lifecycle behavior are
checked by normalizing only the new field initialization/cleanup and added API
block back to the exact V2 source bytes. Existing lifecycle, initialization,
system, callback and boundary models run against the alternative V3 unit in
ordinary and ASan/UBSan configurations. New actual-pthread and private-boundary
models cover pending independence, invalid values/schema, wrong thread/TLS,
callback and concurrent reentry, output aliases, failed destroy, successful
cleanup and generation replacement. C++ callers link against separate C
objects. The iOS arm64e candidate is signed and metadata checked locally and
is never loaded or deployed by the builder.

The built candidate exposes the existing 19 symbols plus exactly the two new
APIs. The only additional undefined symbol is the standard libSystem fortified
memory-copy helper `___memcpy_chk`. There is no new native or framework import;
external dependency remains libSystem. LeakSanitizer is unavailable on this
macOS platform; the models use ASan+UBSan with detect_leaks=0 and make no leak
sanitizer claim.

Pending state is preparation for a future complete run implementation. V3 does
not apply an entry plan, clean native pending/control fields after a run,
execute native Run or retry, create a post-return lease, construct USER/VIEW,
or change `runAllowed` / complete reset gates. The saved first SYS42 values do
not supply defaults or authorize writes. Full independent macOS27 guest boot
and the cause of the earlier native raw11 remain unproved.
