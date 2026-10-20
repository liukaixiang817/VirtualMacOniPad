#include <stdbool.h>
#include <stdint.h>
/* Keep the original native caller admission in its own function. Otherwise
 * release optimization inlines its 16 KiB buffer into hv_vm_config_create;
 * that entry then snapshots LR only after the compiler's stack-probe call.
 * The full original UUID/instruction/path/return-address checks stay intact. */
static __attribute__((noinline)) bool ChildConfigEntryV14(uintptr_t caller);
#include "vm27_hv_public_vm_bootstrap_v28.m"
