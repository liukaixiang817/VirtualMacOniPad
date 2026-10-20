.text
.p2align 2
.private_extern _VM27OwnedBRKNativeTrapV1
.globl _VM27OwnedBRKNativeTrapV1
_VM27OwnedBRKNativeTrapV1:
    mov x16, #-5
    svc #0x80
    ret
