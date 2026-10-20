# Original27 framework maximum-vCPU query

This isolated provider implements only the original framework query
`hv_vm_get_max_vcpu_count(uint32_t *)`. The genuine macOS13.2.1 function at RVA
`0x4ae4` and genuine macOS27 function at RVA `0x2d00` contain exactly the same
sixteen bytes:

```
08088052 080000b9 00008052 c0035fd6
mov w8, 64; str w8, [x0]; mov w0, 0; ret
```

Therefore 64 is an original framework contract, not a measured iPad kernel
limit. A valid caller gets the same four-byte output and signed32 success.
The helper adds one documented app defense: null returns `HV_BAD_ARGUMENT`
(`0xfae94003`) without a write. Apple's header has a nonnull contract, and the
original leaf itself does not guard null.

There are no macOS13 Hypervisor imports, CPU/VM operations, capabilities,
initializers or state objects here. CPU admission must remain separately
bounded to the actually verified limit, currently at most two diagnostic CPUs.
No sixty-four-CPU lifecycle or guest execution is claimed. This provider does
not implement `hv_vm_config_get_max_ipa_size`; that function requires the
genuine capability cache and cannot be filled with the header's example 36.

Candidates and local ABI checks belong to
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/hv-framework-max-vcpu-contract-v1`.
Compilation and a local helper call do not validate original VZ startup. The
helper is not automatically deployed, trusted, or connected to a production VM.
