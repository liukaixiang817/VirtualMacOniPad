.text
.p2align 2
.private_extern _VM27CPUConfigCapabilityKernelQueryV1
.globl _VM27CPUConfigCapabilityKernelQueryV1
_VM27CPUConfigCapabilityKernelQueryV1:
    mov x16, #-5
    svc #0x80
    ret
