// Exact old-host hypervisor Mach trap entry. No old framework is imported.
// Original reference: Hypervisor 13 RVA492c, x16=-5; svc80; ret.
.text
.p2align 2
.private_extern _VZCPU27KernelTrapRaw
.globl _VZCPU27KernelTrapRaw
_VZCPU27KernelTrapRaw:
    movn x16, #4
    svc #0x80
    ret
