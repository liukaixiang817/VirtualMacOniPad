.text
.p2align 2
.private_extern _VZIPA27KernelTrapRaw
.globl _VZIPA27KernelTrapRaw
_VZIPA27KernelTrapRaw:
    mov x16, #-5
    svc #0x80
    ret
