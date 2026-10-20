// Retain the reviewed VM/RAM/GIC implementation. The combined build supplies
// Factory16 and Life20, which preserve the existing private ownership ABI and
// add genuine virtual timer masking and nonzero-offset physical timer access.
#include "vm27_hv_public_vm_bootstrap_v10.h"
#include "vm27_hv_public_vm_bootstrap_v9.m"
