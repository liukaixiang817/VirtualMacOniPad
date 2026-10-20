# Own multi-CPU lifecycle V4

Link `modern_cpu_kernel_lifecycle_v4.c` as an alternative unit, with the existing native-field, initialization-V2, SYS-V2 and hidden pending-value units. Do not link V2/V3 lifecycle implementations together. Production builds and frozen V2/V3 source remain unchanged.

Each VM has a stable allocation epoch and a private registry of all retained CPU handles. Each actual worker has at most one live CPU via private TLS. Every CPU generation is separately process-monotonic and bound to that epoch; existing requests cannot reuse a generation after VM recreation. Native callbacks run outside the VM mutex, and atomic operation guards are acquired before caller callbacks. Successful native creation with unreadable/version-mismatched context still publishes a live cleanup handle. Failed owner destroy keeps it tracked; successful destroy clears own pending/TLS but the registry entry remains until actual creating pthread CPUFree. Any retained entry blocks VMDestroy.

The V3 pending API signatures remain intact and require owner/TLS/registry identity. Their output rejects aliases with every retained private CPU, registry entry and VM. No native read, native write or trap is used by pending APIs. No original public CPU ID, USER/VIEW or lifetime lease is fabricated.

The local build/model evidence is in `kernel-owned-multicpu-state-v4-local-v1/local-build-v4`: normal and ASan/UBSan real-pthread multi-handle, owner-exit, pending, legacy ISA1/2 lifecycle/initialization/SYS and callback tests pass. The strict arm64e iOS product has the same 21 exports as V3; only pthread_self/pthread_equal imports were added. It has not been loaded or deployed.

Native op6 input remains exactly {0,0}; op7 argument remains NULL for the current owner. Genuine13 sends a selected userspace slot, which can differ for a second CPU. Internal multi-CPU support does not prove actual multiple kernel allocations under the fixed request, guest execution or complete macOS27 backend acceptance. No Run or runAllowed gate changed.
