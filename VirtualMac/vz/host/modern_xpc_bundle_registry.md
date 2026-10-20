# Private bundle registry and typed service plan

This scoped module closes real filesystem registration and plan consumption,
not the complete `xpc_add_bundle_with_lwcr` launchd contract. It never exports
that original API, launches a process, or registers a system Mach service.

The caller creates an owned mode0700 root. Registration accepts an immediate
`.bundle` child, original27 flags2, and the exact immutable plugin LWCR. It reads
the parent's real `Contents/Info.plist`, each owned `.xpc` service Info.plist,
and its actual thin arm64 executable. Each path component uses `openat` with
`O_NOFOLLOW`; files must be owned, regular, non-world/group-writable and have one
hard link. The current bounded diagnostic scope permits up to16 services and
2MiB executable files. This is insufficient for the original5MiB VMM and is
not a production registration substitute.

Registration stages all records before a mutex-protected commit. A service
plan owns a duplicated root FD, copied identifiers and filesystem hashes, and
a retained immutable typed policy. Plans remain valid after the registry is
released. Consumers recheck the actual named root inode and all three file
hashes, inode/size/mode pins before each received-message gate. Embedded Mach-O
signature **bounds** and UUID are checked; this module has not authenticated
CodeDirectory pages or added an authorized-code fallback.

The actual native gate remains `VM27LWCRPolicyCheckReceivedMessage`. It requires
the particular received XPC message's native audit token, a validated SecTask,
and a native Boolean true plugin entitlement. A message body claiming true
does not authorize it. Four iPad signature controls previously verified that
the Boolean true was genuinely present but its SecTask was not validated, so
the current strict gate refused all messages. This limitation is preserved.

`xpc-bundle-registry-v1/build-v4` locally executed the actual Mac CLI:1119 checks
and0 failures, one real owned bundle/service registration,257 typed plans
created and destroyed,4 workers joined,64 real anonymous XPC messages checked
and64 SecTasks released. No application handler ran. The fixture corrupts and
restores only its owned service plist/code clone, rejects symlinks/path escape,
checks policy snapshot ownership, and removes every owned temporary file.
The service's executable is an exact copy of the probe, not a launched child.
Independent validation requires exact signed binaries and30 positive strong
bindings, with120 weak/flat/missing/wrong-provider negative controls.

The iOS3-file candidate is arm64e ABI0, minimum/SDK16.1. Both libraries have
empty entitlements. Only the CLI has platform-application, no-container,
no-sandbox and can-execute-cdhash, matching the previously validated private
library mapping scope. No get-task-allow, plugin grant, HV/GPU or Root-specific
code is added. Parent iPad execution subsequently passed:actual PID34327,
observed wait0/reaped/absent,1119checks,257 paired plans,64 real XPC messages,
64 paired SecTasks,4 joined workers and every owned temporary file removed.
Independent receipt validation is recorded in
`xpc-bundle-registry-v1/native-registry-verification.json`; the6 provider
identities agree before/after with the frozen registry/policy binaries.
Application calls and child launches remain0, authorized-positive coverage
remainsfalse, and production files were not changed.

Remaining work includes an independently authenticated, explicitly approved
code identity path if needed, an actual scoped child launcher and endpoint
handoff, every-message authorization of that child, complete unregister/join
lifecycle, and the precise originalVMM consumer route. A successful local
registry test is not complete XPC service registration or originalVMM success.
