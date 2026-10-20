// The actual current kernel HV trap ABI. x0 is operation; x1 is the packet
// pointer or actual native10 slot mask. No old framework entry is involved.
.text
.p2align 2
.globl _VM27ProductionNativeTrapV1
.private_extern _VM27ProductionNativeTrapV1
_VM27ProductionNativeTrapV1:
 mov x16, #-5
 svc #0x80
 ret
