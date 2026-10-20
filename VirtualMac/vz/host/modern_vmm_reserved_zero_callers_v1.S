.text
.p2align 2
.globl _VM27ReservedZeroSaveV1
_VM27ReservedZeroSaveV1:
sub sp, sp, #0x320
stp x0, x1, [sp, #0]
stp x2, x3, [sp, #16]
stp x4, x5, [sp, #32]
stp x6, x7, [sp, #48]
stp x8, x9, [sp, #64]
stp x10, x11, [sp, #80]
stp x12, x13, [sp, #96]
stp x14, x15, [sp, #112]
stp x16, x17, [sp, #128]
stp x18, x19, [sp, #144]
stp x20, x21, [sp, #160]
stp x22, x23, [sp, #176]
stp x24, x25, [sp, #192]
stp x26, x27, [sp, #208]
stp x28, x29, [sp, #224]
str x30, [sp, #240]
stp q0, q1, [sp, #256]
stp q2, q3, [sp, #288]
stp q4, q5, [sp, #320]
stp q6, q7, [sp, #352]
stp q8, q9, [sp, #384]
stp q10, q11, [sp, #416]
stp q12, q13, [sp, #448]
stp q14, q15, [sp, #480]
stp q16, q17, [sp, #512]
stp q18, q19, [sp, #544]
stp q20, q21, [sp, #576]
stp q22, q23, [sp, #608]
stp q24, q25, [sp, #640]
stp q26, q27, [sp, #672]
stp q28, q29, [sp, #704]
stp q30, q31, [sp, #736]
mrs x9, nzcv
str x9, [sp, #0x310]
mov x0, #-2
.long 0x90000001 | ((((0x28b000-((0x4a2b00+(. - _VM27ReservedZeroSaveV1))&~0xfff))>>12)&3)<<29) | (((((0x28b000-((0x4a2b00+(. - _VM27ReservedZeroSaveV1))&~0xfff))>>12)>>2)&0x7ffff)<<5)
add x1, x1, #3744
.long 0x94000000 | (((0x4129f4-(0x4a2b00+(. - _VM27ReservedZeroSaveV1))) >> 2)&0x03ffffff)
cbz x0, LSaveFail
mov x8, x0
ldr x0, [x24]
mov w1, #0x390
add x2, x19, #0x950
blraaz x8
cbnz w0, LSaveFail
ldr x9, [sp, #0x310]
msr nzcv, x9
ldp q0, q1, [sp, #256]
ldp q2, q3, [sp, #288]
ldp q4, q5, [sp, #320]
ldp q6, q7, [sp, #352]
ldp q8, q9, [sp, #384]
ldp q10, q11, [sp, #416]
ldp q12, q13, [sp, #448]
ldp q14, q15, [sp, #480]
ldp q16, q17, [sp, #512]
ldp q18, q19, [sp, #544]
ldp q20, q21, [sp, #576]
ldp q22, q23, [sp, #608]
ldp q24, q25, [sp, #640]
ldp q26, q27, [sp, #672]
ldp q28, q29, [sp, #704]
ldp q30, q31, [sp, #736]
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #0x320
.long 0x14000000 | (((0x289bf4-(0x4a2b00+(. - _VM27ReservedZeroSaveV1))) >> 2)&0x03ffffff)
LSaveFail:
ldr x9, [sp, #0x310]
msr nzcv, x9
ldp q0, q1, [sp, #256]
ldp q2, q3, [sp, #288]
ldp q4, q5, [sp, #320]
ldp q6, q7, [sp, #352]
ldp q8, q9, [sp, #384]
ldp q10, q11, [sp, #416]
ldp q12, q13, [sp, #448]
ldp q14, q15, [sp, #480]
ldp q16, q17, [sp, #512]
ldp q18, q19, [sp, #544]
ldp q20, q21, [sp, #576]
ldp q22, q23, [sp, #608]
ldp q24, q25, [sp, #640]
ldp q26, q27, [sp, #672]
ldp q28, q29, [sp, #704]
ldp q30, q31, [sp, #736]
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #0x320
.long 0x14000000 | (((0x289e58-(0x4a2b00+(. - _VM27ReservedZeroSaveV1))) >> 2)&0x03ffffff)
.globl _VM27ReservedZeroSaveV1End
_VM27ReservedZeroSaveV1End:
.globl _VM27ReservedZeroRestoreV1
_VM27ReservedZeroRestoreV1:
sub sp, sp, #0x320
stp x0, x1, [sp, #0]
stp x2, x3, [sp, #16]
stp x4, x5, [sp, #32]
stp x6, x7, [sp, #48]
stp x8, x9, [sp, #64]
stp x10, x11, [sp, #80]
stp x12, x13, [sp, #96]
stp x14, x15, [sp, #112]
stp x16, x17, [sp, #128]
stp x18, x19, [sp, #144]
stp x20, x21, [sp, #160]
stp x22, x23, [sp, #176]
stp x24, x25, [sp, #192]
stp x26, x27, [sp, #208]
stp x28, x29, [sp, #224]
str x30, [sp, #240]
stp q0, q1, [sp, #256]
stp q2, q3, [sp, #288]
stp q4, q5, [sp, #320]
stp q6, q7, [sp, #352]
stp q8, q9, [sp, #384]
stp q10, q11, [sp, #416]
stp q12, q13, [sp, #448]
stp q14, q15, [sp, #480]
stp q16, q17, [sp, #512]
stp q18, q19, [sp, #544]
stp q20, q21, [sp, #576]
stp q22, q23, [sp, #608]
stp q24, q25, [sp, #640]
stp q26, q27, [sp, #672]
stp q28, q29, [sp, #704]
stp q30, q31, [sp, #736]
mrs x9, nzcv
str x9, [sp, #0x310]
mov x0, #-2
.long 0x90000001 | ((((0x28b000-((0x4a2e00+(. - _VM27ReservedZeroRestoreV1))&~0xfff))>>12)&3)<<29) | (((((0x28b000-((0x4a2e00+(. - _VM27ReservedZeroRestoreV1))&~0xfff))>>12)>>2)&0x7ffff)<<5)
add x1, x1, #3808
.long 0x94000000 | (((0x4129f4-(0x4a2e00+(. - _VM27ReservedZeroRestoreV1))) >> 2)&0x03ffffff)
cbz x0, LRestoreFail
mov x8, x0
ldr x0, [x26]
mov w1, #0x390
ldr x2, [x19, #0x950]
blraaz x8
cbnz w0, LRestoreFail
ldr x9, [sp, #0x310]
msr nzcv, x9
ldp q0, q1, [sp, #256]
ldp q2, q3, [sp, #288]
ldp q4, q5, [sp, #320]
ldp q6, q7, [sp, #352]
ldp q8, q9, [sp, #384]
ldp q10, q11, [sp, #416]
ldp q12, q13, [sp, #448]
ldp q14, q15, [sp, #480]
ldp q16, q17, [sp, #512]
ldp q18, q19, [sp, #544]
ldp q20, q21, [sp, #576]
ldp q22, q23, [sp, #608]
ldp q24, q25, [sp, #640]
ldp q26, q27, [sp, #672]
ldp q28, q29, [sp, #704]
ldp q30, q31, [sp, #736]
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #0x320
ldr x21, [x19, #0x950]
.long 0x90000008 | (((((0x4ce000-((0x4a2e00+(. - _VM27ReservedZeroRestoreV1))&~0xfff))>>12))&3)<<29) | (((((0x4ce000-((0x4a2e00+(. - _VM27ReservedZeroRestoreV1))&~0xfff))>>12)>>2)&0x7ffff)<<5)
add x8, x8, #0x460
.long 0x14000000 | (((0x28c924-(0x4a2e00+(. - _VM27ReservedZeroRestoreV1))) >> 2)&0x03ffffff)
LRestoreFail:
ldr x9, [sp, #0x310]
msr nzcv, x9
ldp q0, q1, [sp, #256]
ldp q2, q3, [sp, #288]
ldp q4, q5, [sp, #320]
ldp q6, q7, [sp, #352]
ldp q8, q9, [sp, #384]
ldp q10, q11, [sp, #416]
ldp q12, q13, [sp, #448]
ldp q14, q15, [sp, #480]
ldp q16, q17, [sp, #512]
ldp q18, q19, [sp, #544]
ldp q20, q21, [sp, #576]
ldp q22, q23, [sp, #608]
ldp q24, q25, [sp, #640]
ldp q26, q27, [sp, #672]
ldp q28, q29, [sp, #704]
ldp q30, q31, [sp, #736]
ldp x0, x1, [sp, #0]
ldp x2, x3, [sp, #16]
ldp x4, x5, [sp, #32]
ldp x6, x7, [sp, #48]
ldp x8, x9, [sp, #64]
ldp x10, x11, [sp, #80]
ldp x12, x13, [sp, #96]
ldp x14, x15, [sp, #112]
ldp x16, x17, [sp, #128]
ldp x18, x19, [sp, #144]
ldp x20, x21, [sp, #160]
ldp x22, x23, [sp, #176]
ldp x24, x25, [sp, #192]
ldp x26, x27, [sp, #208]
ldp x28, x29, [sp, #224]
ldr x30, [sp, #240]
add sp, sp, #0x320
.long 0x14000000 | (((0x28cb8c-(0x4a2e00+(. - _VM27ReservedZeroRestoreV1))) >> 2)&0x03ffffff)
.globl _VM27ReservedZeroRestoreV1End
_VM27ReservedZeroRestoreV1End:
.globl _VM27ReservedZeroGetPropertyV1
_VM27ReservedZeroGetPropertyV1:
pacibsp
sub sp, sp, #0x40
stp x29, x30, [sp, #16]
stp x19, x20, [sp]
add x29, sp, #16
stp x0, x1, [sp, #32]
mov x0, #-2
.long 0x90000001 | ((((0x28b000-((0x4a3100+(. - _VM27ReservedZeroGetPropertyV1))&~0xfff))>>12)&3)<<29) | (((((0x28b000-((0x4a3100+(. - _VM27ReservedZeroGetPropertyV1))&~0xfff))>>12)>>2)&0x7ffff)<<5)
add x1, x1, #3744
.long 0x94000000 | (((0x4129f4-(0x4a3100+(. - _VM27ReservedZeroGetPropertyV1))) >> 2)&0x03ffffff)
cbz x0, LGetPropertyFail
mov x8, x0
ldr x0, [sp, #32]
ldr x0, [x0, #0xd8]
mov w1, #0x390
add x2, sp, #48
blraaz x8
cbnz w0, LGetPropertyFail
ldr x0, [sp, #48]
ldp x19, x20, [sp]
ldp x29, x30, [sp, #16]
add sp, sp, #0x40
retab
LGetPropertyFail:
.long 0x94000000 | (((0x40fe48-(0x4a3100+(. - _VM27ReservedZeroGetPropertyV1))) >> 2)&0x03ffffff)
brk #1
.globl _VM27ReservedZeroGetPropertyV1End
_VM27ReservedZeroGetPropertyV1End:
.globl _VM27ReservedZeroSetPropertyV1
_VM27ReservedZeroSetPropertyV1:
pacibsp
sub sp, sp, #0x40
stp x29, x30, [sp, #16]
stp x19, x20, [sp]
add x29, sp, #16
stp x0, x1, [sp, #32]
mov x0, #-2
.long 0x90000001 | ((((0x28b000-((0x4a3200+(. - _VM27ReservedZeroSetPropertyV1))&~0xfff))>>12)&3)<<29) | (((((0x28b000-((0x4a3200+(. - _VM27ReservedZeroSetPropertyV1))&~0xfff))>>12)>>2)&0x7ffff)<<5)
add x1, x1, #3808
.long 0x94000000 | (((0x4129f4-(0x4a3200+(. - _VM27ReservedZeroSetPropertyV1))) >> 2)&0x03ffffff)
cbz x0, LSetPropertyFail
mov x8, x0
ldr x0, [sp, #32]
ldr x0, [x0, #0xd8]
mov w1, #0x390
ldr x2, [sp, #40]
blraaz x8
cbnz w0, LSetPropertyFail
ldp x19, x20, [sp]
ldp x29, x30, [sp, #16]
add sp, sp, #0x40
retab
LSetPropertyFail:
.long 0x94000000 | (((0x40fe48-(0x4a3200+(. - _VM27ReservedZeroSetPropertyV1))) >> 2)&0x03ffffff)
brk #1
.globl _VM27ReservedZeroSetPropertyV1End
_VM27ReservedZeroSetPropertyV1End:
