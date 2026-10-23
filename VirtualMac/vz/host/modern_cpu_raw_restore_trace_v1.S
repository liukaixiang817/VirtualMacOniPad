.text
.p2align 2
.globl _VM27OwnedRawHVPassV1
.private_extern _VM27OwnedRawHVPassV1
_VM27OwnedRawHVPassV1:
    mov x16, #-5
    svc #0x80
    ret
