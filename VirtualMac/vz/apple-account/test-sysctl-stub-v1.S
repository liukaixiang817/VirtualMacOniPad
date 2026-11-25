.text
.p2align 2
.globl _VMAppleAccountTestStubV1
_VMAppleAccountTestStubV1:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x19, x0
    mov x20, x2
    mov x9, #9
    mov x10, #10
    mov x11, #11
    mov x12, #12
    mov x13, #13
    mov x14, #14
    mov x15, #15
    mov x16, #16
    msr nzcv, x1
    bl _VMAppleAccountSysctlStubV1
    mrs x1, nzcv
    stp x8, x1, [x20]
    stp x9, x10, [x20, #16]
    stp x11, x12, [x20, #32]
    stp x13, x14, [x20, #48]
    stp x15, x16, [x20, #64]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
