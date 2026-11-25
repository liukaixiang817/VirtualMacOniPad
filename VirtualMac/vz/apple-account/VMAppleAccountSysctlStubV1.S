// Native ARM64 counterpart of Henge's scoped CSET compatibility hook.
// Enter at the audited CSET w8,ne site with the real sysctl_req in x19.
// Preserve every other register, NZCV, SP and all non-stack guest memory.
#ifndef VM_APPLE_ACCOUNT_PROC_COMM
#error Supply an independently audited proc command offset
#endif
.text
.p2align 2
.globl _VMAppleAccountSysctlStubV1
.private_extern _VMAppleAccountSysctlStubV1
_VMAppleAccountSysctlStubV1:
    cset w8, ne
    sub sp, sp, #80
    stp x9, x10, [sp]
    stp x11, x12, [sp, #16]
    stp x13, x14, [sp, #32]
    stp x15, x16, [sp, #48]
    mrs x14, nzcv
    str x14, [sp, #64]
    ldr x9, [x19]
    cbz x9, Ldone
    add x9, x9, #VM_APPLE_ACCOUNT_PROC_COMM
    add x10, x9, #17
    adr x11, Lnames
Lname:
    mov x13, #0
Lfull:
    ldrb w14, [x11, x13]
    ldrb w15, [x10, x13]
    cmp w14, w15
    b.ne Lskip
    cbz w14, LshortStart
    add x13, x13, #1
    b Lfull
LshortStart:
    mov x12, #0
Lshort:
    cmp x12, #16
    b.eq LshortEnd
    ldrb w14, [x11, x12]
    ldrb w15, [x9, x12]
    cmp w14, w15
    b.ne Ldone
    cbz w14, Laccepted
    add x12, x12, #1
    b Lshort
LshortEnd:
    ldrb w15, [x9, #16]
    cbnz w15, Ldone
Laccepted:
    mov w8, #0
    b Ldone
Lskip:
    ldrb w14, [x11], #1
    cbnz w14, Lskip
    ldrb w14, [x11]
    cbnz w14, Lname
Ldone:
    ldr x14, [sp, #64]
    msr nzcv, x14
    ldp x9, x10, [sp]
    ldp x11, x12, [sp, #16]
    ldp x13, x14, [sp, #32]
    ldp x15, x16, [sp, #48]
    add sp, sp, #80
.globl _VMAppleAccountSysctlStubReturnV1
.private_extern _VMAppleAccountSysctlStubReturnV1
_VMAppleAccountSysctlStubReturnV1:
#ifdef VM_APPLE_ACCOUNT_STUB_NATIVE_TEST
    ret
#else
    // The installer replaces only this word with B to handler + 60.
    .long 0x14000000
#endif
Lnames:
#define VM_APPLE_ACCOUNT_PROCESS(name) .asciz name
#include "VMAppleAccountProcessesV1.def"
#undef VM_APPLE_ACCOUNT_PROCESS
    .byte 0
.globl _VMAppleAccountSysctlStubEndV1
.private_extern _VMAppleAccountSysctlStubEndV1
_VMAppleAccountSysctlStubEndV1:
