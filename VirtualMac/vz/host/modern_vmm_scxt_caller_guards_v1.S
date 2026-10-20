.text
.p2align 2
.globl _VM27SCXTSaveGuardV1
_VM27SCXTSaveGuardV1:
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
ldr x0, [x24]
mov w1, #49184
add x2, sp, #768
#ifdef VM27_HOST_SCXT_FIXTURE
bl _VM27SCXTFixtureGetSYS
#else
.long 0x94000000 | (((0x412dd4-(0x4a2100+(. - _VM27SCXTSaveGuardV1))) >> 2)&0x03ffffff)
#endif
cbnz w0, LSaveFail
ldr x0, [x24]
mov w1, #49185
add x2, sp, #776
#ifdef VM27_HOST_SCXT_FIXTURE
bl _VM27SCXTFixtureGetSYS
#else
.long 0x94000000 | (((0x412dd4-(0x4a2100+(. - _VM27SCXTSaveGuardV1))) >> 2)&0x03ffffff)
#endif
cbnz w0, LSaveFail
ldr x9, [sp, #0x300]
ubfx x9, x9, #56, #4
ldr x10, [sp, #0x308]
ubfx x10, x10, #32, #4
cmp x9, #3
b.hi LSaveFail
cmp x10, #2
b.hi LSaveFail
cmp x9, #1
b.eq LSaveFractionValid
cbnz x10, LSaveFail
LSaveFractionValid:
cmp x9, #2
b.hs LSavePresent
b LSaveAbsent
LSavePresent:
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixturePresent
#else
ldr x0, [x24]
.long 0x14000000 | (((0x288934-(0x4a2100+(. - _VM27SCXTSaveGuardV1))) >> 2)&0x03ffffff)
#endif
LSaveAbsent:
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixtureAbsent
#else
.long 0x14000000 | (((0x288970-(0x4a2100+(. - _VM27SCXTSaveGuardV1))) >> 2)&0x03ffffff)
#endif
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixtureFail
#else
.long 0x14000000 | (((0x289e58-(0x4a2100+(. - _VM27SCXTSaveGuardV1))) >> 2)&0x03ffffff)
#endif
.globl _VM27SCXTSaveGuardV1End
_VM27SCXTSaveGuardV1End:
.globl _VM27SCXTRestoreGuardV1
_VM27SCXTRestoreGuardV1:
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
ldr x0, [x26]
mov w1, #49184
add x2, sp, #768
#ifdef VM27_HOST_SCXT_FIXTURE
bl _VM27SCXTFixtureGetSYS
#else
.long 0x94000000 | (((0x412dd4-(0x4a2600+(. - _VM27SCXTRestoreGuardV1))) >> 2)&0x03ffffff)
#endif
cbnz w0, LRestoreFail
ldr x0, [x26]
mov w1, #49185
add x2, sp, #776
#ifdef VM27_HOST_SCXT_FIXTURE
bl _VM27SCXTFixtureGetSYS
#else
.long 0x94000000 | (((0x412dd4-(0x4a2600+(. - _VM27SCXTRestoreGuardV1))) >> 2)&0x03ffffff)
#endif
cbnz w0, LRestoreFail
ldr x9, [sp, #0x300]
ubfx x9, x9, #56, #4
ldr x10, [sp, #0x308]
ubfx x10, x10, #32, #4
cmp x9, #3
b.hi LRestoreFail
cmp x10, #2
b.hi LRestoreFail
cmp x9, #1
b.eq LRestoreFractionValid
cbnz x10, LRestoreFail
LRestoreFractionValid:
cmp x9, #2
b.hs LRestorePresent
b LRestoreAbsent
LRestorePresent:
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixturePresent
#else
ldr x2, [x19, #0x760]
.long 0x14000000 | (((0x28b584-(0x4a2600+(. - _VM27SCXTRestoreGuardV1))) >> 2)&0x03ffffff)
#endif
LRestoreAbsent:
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixtureAbsent
#else
.long 0x14000000 | (((0x28b5a8-(0x4a2600+(. - _VM27SCXTRestoreGuardV1))) >> 2)&0x03ffffff)
#endif
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
#ifdef VM27_HOST_SCXT_FIXTURE
b _VM27SCXTFixtureFail
#else
.long 0x14000000 | (((0x28cb8c-(0x4a2600+(. - _VM27SCXTRestoreGuardV1))) >> 2)&0x03ffffff)
#endif
.globl _VM27SCXTRestoreGuardV1End
_VM27SCXTRestoreGuardV1End:
#ifdef VM27_HOST_SCXT_FIXTURE
.globl _VM27SCXTHostInvoke
_VM27SCXTHostInvoke:
stp x29, x30, [sp, #-48]!
stp x24, x26, [sp, #16]
str x19, [sp, #32]
mov x24, x0
mov x26, x0
mov x19, x1
cbnz w2, LFixtureRestore
bl _VM27SCXTSaveGuardV1
b LFixtureDone
LFixtureRestore:
bl _VM27SCXTRestoreGuardV1
LFixtureDone:
ldr x19, [sp, #32]
ldp x24, x26, [sp, #16]
ldp x29, x30, [sp], #48
ret
_VM27SCXTFixturePresent:
mov w0, #0
ret
_VM27SCXTFixtureAbsent:
mov w0, #1
ret
_VM27SCXTFixtureFail:
mov w0, #2
ret
#endif
