.text
.p2align 2
.private_extern _VM27OwnedCreationNativeTrapV1
.globl _VM27OwnedCreationNativeTrapV1
_VM27OwnedCreationNativeTrapV1:
    mov x16, #-5
    svc #0x80
    ret
