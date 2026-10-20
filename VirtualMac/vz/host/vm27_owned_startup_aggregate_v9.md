# Static original VMM route and shared provider graph

The empty C source provides no instructions. Its linker-generated strong
reexports expose the real V9 original-XPC ABI, V2 preparation API and unchanged
private CheckIn provider. The independent build tool compiles only these new
ordinary iOS libraries and the real bundle reader. Nine earlier libraries retain
all bytes and signatures. One actual ClientRegistration file serves V9 and the
unchanged original ClientServices reexport; one HeadlessCheckIn file serves V2
and the original VMM's import90 through the new aggregate. No singleton is copied
into a second provider image.

The static route builder takes the latest ClientServices inert VMM candidate.
It reuses existing strong dependency54 and its 64-byte command for the aggregate.
Only the create, set-one-shot and main import ordinals and their matching nlist
ordinal bytes change from15 to54. Import indexes, binding/PAC words, original
instructions, data, entrypoint, other routes and dependency versions stay exact.
The output is nonexecuting 0600 data with a stale original signature. Whole-byte
inverse and damaged controls validate this limited delta; compilation and static
reexport inspection do not prove runtime loading.

The aggregate does not call Prepare. A trusted pre-Main caller still must pass
the real V9 typed parent/PID/owner and nonce into V2, deliver the actual control
messages and preserve final-INVALID/drain lifetimes. No constructor, new launcher,
original handler execution, global LaunchServices, native CPU operation, signing,
trustcache or deployment belongs to these builders. Strict Large mode's missing
outer kernel-CDHash result remains fail-closed; native Boolean rejection remains
real. Other strong dependencies and original handler role checks are unresolved.
Neither provider compilation nor the inert import route is a complete backend.
