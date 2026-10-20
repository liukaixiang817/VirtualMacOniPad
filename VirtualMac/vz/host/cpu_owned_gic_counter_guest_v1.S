// Copied as bytes into one guest instruction page; never called by the host.
.text
.p2align 2
.private_extern _VM27OwnedGICGuestStartV1
.private_extern _VM27OwnedGICGuestBRKV1
.private_extern _VM27OwnedGICGuestEndV1
.globl _VM27OwnedGICGuestStartV1
.globl _VM27OwnedGICGuestBRKV1
.globl _VM27OwnedGICGuestEndV1
_VM27OwnedGICGuestStartV1:
    mrs x0, CNTPCT_EL0
    mrs x1, CNTFRQ_EL0
    mov x3, #0xff
    msr ICC_PMR_EL1, x3
    mrs x4, ICC_PMR_EL1
    mov x5, #0x10000000
    ldr w6, [x5, #4]
    mrs x7, ICC_IAR1_EL1
    mrs x8, CNTP_CTL_EL0
_VM27OwnedGICGuestBRKV1:
    brk #0
_VM27OwnedGICGuestEndV1:
