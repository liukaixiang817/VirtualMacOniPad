# Original27 VMM data capacity adapter

Three independent providers now support a fixed8MiB original VMM file: modern_xpc_large_bundle_registry (separate64KiB plists), modern_xpc_large_private_consumer (full CodeDirectory/SHA/CD/UUID authentication), and modern_xpc_large_original_parent (complete signed-page read and owner/FD pin). Their exported symbols have Large-specific names, so the original2MiB providers and frozen transport scopes retain their limits.

All readers require owned regular non-writable single-link files, O_NOFOLLOW and stable FD metadata during reads. Registry component traversal remains rooted at an owned directory FD. ApprovedCode, LWCRPolicy, PrivateEndpoint and original2MiB registry dylibs are reused as their exact frozen bytes. Original plugin entitlement queries and flags2 remain mandatory in this diagnostic fixture; no original registration API is exported.

Frozen candidate: DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/xpc-original-capacity8-v1/build-v4 (185files). Actual Mac PID75695/wait0:76checks0,3plans paired,1unstarted consumer paired, zero connections/messages/spawns/SecTask, owned temporary tree removed. Validator:62critical strong bindings,248 corrupted binding denials,42 actual receipt denials;38 original Mach-O file-backed sections+PAC chained payload preserve their exact original bytes.

The genuine27 VMM file is only signed local data, deployed600 and explicitly excluded from trustcache/launch. Its UUID remains4a6a588d1afd30f5a64d6304eb79be0b; runtime closure and original wire execution are pending. The signed data grows from5195312 to5206160bytes while code/import/PAC payload stays unchanged.

The iOS arm64e ABI0 candidate is compiled/signed, not yet executed in this receipt. Root exclusively performs device staging and validates truewait/PID absence/temp absence/all9file pins plus every14before/after provider path/UUID/SHA/RVA. The CLI uses only four previously established diagnostic rights and has no private virtualization/plugin entitlements.

This removes a size prerequisite for later genuine service integration. It does not increase production limits, alter iPadOS/bootstrap/launchd, complete the VMM loader, or execute any guest CPU/GPU.
