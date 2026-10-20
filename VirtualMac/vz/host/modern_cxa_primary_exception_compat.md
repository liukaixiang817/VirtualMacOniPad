# Native primary exception initialization

The independent provider implements `__cxa_init_primary_exception` for the actual
iPad16.1.1 libc++abi UUID `fa871417be083e90b33ca6aa89813f3b`. It uses the genuine
native allocator, refcount, unwinder, complete object destructors and exception
cleanup. It provides no generic symbol fallback or artificial success result.

Read-only native code collectors confirmed the 128-byte LP64 exception header:
referenceCount at object-120; type at-112; destructor at-104; saved unexpected at-96;
saved terminate at-88; unwind header at-32. The native destructor call is `blraaz`
and the original throw stores incoming function pointers directly: the old header
uses IA/zero-discriminator pointers. The compiling SDK's current address-diverse
cxxabi destructor and handler qualifiers must remain disabled for the iOS build.

Initialization adapts LLVM21.1.3 `libcxxabi/src/cxa_exception.cpp`: reset the initial
reference count, save current handlers/type/destructor, write the genuine primary
exception class and native cleanup, then return the real header. Other fields and
the object's construction state remain untouched. The native cleanup at RVA0x13bd8
is 48 bytes with SHA25421a8dd67600536f79e0124db33b439405770018eabc7ccbf658752d83fbb6.
It invokes the saved terminate handler on invalid cleanup reasons and decrements
the genuine primary reference for `_URC_FOREIGN_EXCEPTION_CAUGHT`. Nine system
entry RVA/full-code hashes and the cleanup/UUID are checked before object mutation.
An unsupported image is rejected before touching the object.

The original official LLVM14 old inline throw/layout and LLVM21 new initialization
sources, source URLs/SHA and license are retained in the frozen candidate's source
directory. The exact system code evidence is in cxa-code-native-v1/v2. Current-Mac
tests use separately captured current-system pins and a fixture-only current PAC
schema; that schema is never enabled in the iOS provider.

The selected immutable candidate is
`DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cxa-primary-exception-v1/build-v4`.
Its candidate.json SHA is
6036833054992caec1ecb9565a33b07c9a8ecd00c72da5d78bd45eaa3dd56d50;
the provider SHA is378d38389334f506d5fbf17dc234bdcc0732bc62d780844994f4f8faef950e58.
Libraries have no entitlements. The independent iOS probe has exactly platform,
no-container, no-sandbox and can-execute-cdhash; no Hypervisor/get-task privilege.

Actual iPad verification:

* cxa-lifecycle-native-v1: childPID31126, observed wait0, reaped/absent.722 checks/0
  failures;70 calls reached the strong-import candidate;68 real objects all finished
  native destruction;66 real native/std rethrows;2 genuine native cleanup calls;
 4 pthread workers joined; one genuine placement-construction failure and native
  free without an invalid destructor. Exact private file hashes remained equal
  before/after; no VM/HV/VMM/PVG images or VM/GPU work.
* cxa-saved-terminate-native-v1: childPID31242, observed wait79, reaped/absent.
 18 checks and the actual saved-terminate event. The current process handler would
  exit80, so79 verifies the handler saved in the candidate-initialized header.
* Separate actual Mac fixture PID23644 wait0:717 checks/0; the corresponding
  saved-handler control PID23645 actually exited79.

The independent validator checks exact binary/signature contents and actual
positive chained strong imports for init/rethrow/factory. Eight weak/flat/wrong
provider/missing import negative controls are rejected. Its transcript function
rechecked both actual iPad stdout files with their observed PID/wait results; see
cxa-primary-exception-v1/native-lifecycle-verification.json. The SDK27 omission of
the native rethrow export is supplied only by a link-time TBD declaration targeting
the genuine `/usr/lib/libc++abi.dylib`; no runtime replacement is introduced.

This verifies the real old-system ABI bridge and lifecycle. The new API is not yet
bound into a running original27 VMM, and these results do not establish full27
CPU/VMM/Virtualization execution.

The subsequent immutable `vmm-runtime-aggregate-v1/build-v4` reexports this exact
provider from its new private C++ wrapper. Actual iPad strong-wrapper consumers
passed: PID32892 observed wait0,724 checks/0,70 initializations/68 native
destructors/66 rethrows/2 native cleanups; saved-handler control PID33051 actually
exited79 after19 checks. Both children were absent after reaping. This verifies
the newly assembled strong reexport path with the same native ABI implementation;
it does not execute the two-byte21-route original VMM artifact. Independent results
are in `vmm-runtime-aggregate-v1/native-aggregate-verification.json`.
