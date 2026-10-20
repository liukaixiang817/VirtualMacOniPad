// Preserve the original AMX host-capability gates; query the owned guest CPU.
// Only explicit absence with inactive zero controls omits the complete block.
.text
.p2align 2
.globl _VM27AMXAvailabilitySaveGuardV1
_VM27AMXAvailabilitySaveGuardV1:
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
adr x1, LSaveQueryName
#ifdef VM27_HOST_AMX_FIXTURE
bl _VM27AMXFixtureDlsym
#else
.long 0x94000000 | (((0x4129f4-(0x4a3a00+(. - _VM27AMXAvailabilitySaveGuardV1)))>>2)&0x03ffffff)
#endif
cbz x0, LSaveFail
mov x16, x0
ldr x0, [x24]
add x1, sp, #0x300
mov w9, #2
str w9, [sp, #0x300]
blraaz x16
cbnz w0, LSaveFail
ldr w9, [sp, #0x300]
cmp w9, #1
b.eq LSavePresent
cbnz w9, LSaveFail
ldr x9, [x19, #0x958]
ldr x10, [x19, #0x960]
orr x9, x9, x10
cbnz x9, LSaveFail
mov w10, #0x1d68
ldrb w9, [x19, x10]
cbnz w9, LSaveFail
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixturePresent
#else
ldr x0, [x24]
.long 0x14000000 | (((0x289c54-(0x4a3a00+(. - _VM27AMXAvailabilitySaveGuardV1)))>>2)&0x03ffffff)
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixtureAbsent
#else
.long 0x14000000 | (((0x289ce4-(0x4a3a00+(. - _VM27AMXAvailabilitySaveGuardV1)))>>2)&0x03ffffff)
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixtureFail
#else
.long 0x14000000 | (((0x289e58-(0x4a3a00+(. - _VM27AMXAvailabilitySaveGuardV1)))>>2)&0x03ffffff)
#endif
LSaveQueryName:
.asciz "VM27VMMGetAMXAvailabilityV1"
.p2align 2
.globl _VM27AMXAvailabilitySaveGuardV1End
_VM27AMXAvailabilitySaveGuardV1End:
.globl _VM27AMXAvailabilityRestoreGuardV1
_VM27AMXAvailabilityRestoreGuardV1:
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
adr x1, LRestoreQueryName
#ifdef VM27_HOST_AMX_FIXTURE
bl _VM27AMXFixtureDlsym
#else
.long 0x94000000 | (((0x4129f4-(0x4a3d00+(. - _VM27AMXAvailabilityRestoreGuardV1)))>>2)&0x03ffffff)
#endif
cbz x0, LRestoreFail
mov x16, x0
ldr x0, [x26]
add x1, sp, #0x300
mov w9, #2
str w9, [sp, #0x300]
blraaz x16
cbnz w0, LRestoreFail
ldr w9, [sp, #0x300]
cmp w9, #1
b.eq LRestorePresent
cbnz w9, LRestoreFail
ldr x9, [x19, #0x958]
ldr x10, [x19, #0x960]
orr x9, x9, x10
cbnz x9, LRestoreFail
mov w10, #0x1d68
ldrb w9, [x19, x10]
cbnz w9, LRestoreFail
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixturePresent
#else
ldr x23, [x19, #0x958]
.long 0x14000000 | (((0x28c97c-(0x4a3d00+(. - _VM27AMXAvailabilityRestoreGuardV1)))>>2)&0x03ffffff)
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixtureAbsent
#else
.long 0x14000000 | (((0x28c9f8-(0x4a3d00+(. - _VM27AMXAvailabilityRestoreGuardV1)))>>2)&0x03ffffff)
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
#ifdef VM27_HOST_AMX_FIXTURE
b _VM27AMXFixtureFail
#else
.long 0x14000000 | (((0x28cb8c-(0x4a3d00+(. - _VM27AMXAvailabilityRestoreGuardV1)))>>2)&0x03ffffff)
#endif
LRestoreQueryName:
.asciz "VM27VMMGetAMXAvailabilityV1"
.p2align 2
.globl _VM27AMXAvailabilityRestoreGuardV1End
_VM27AMXAvailabilityRestoreGuardV1End:
#ifdef VM27_HOST_AMX_FIXTURE
.globl _VM27AMXHostInvoke
_VM27AMXHostInvoke:
stp x29, x30, [sp, #-64]!
stp x24, x26, [sp, #16]
stp x19, x23, [sp, #32]
mov x24, x0
mov x26, x0
mov x19, x1
movi v0.16b, #0x17
movi v31.16b, #0x29
mov x8, #0x1234
mov x9, #0xa0000000
msr nzcv, x9
cbnz w2, LAMXFixtureRestore
bl _VM27AMXAvailabilitySaveGuardV1
b LAMXFixtureDone
LAMXFixtureRestore:
bl _VM27AMXAvailabilityRestoreGuardV1
LAMXFixtureDone:
ldp x19, x23, [sp, #32]
ldp x24, x26, [sp, #16]
ldp x29, x30, [sp], #64
ret
_VM27AMXFixturePresent:
mov w0, #0
b LAMXCaptureExit
_VM27AMXFixtureAbsent:
mov w0, #1
b LAMXCaptureExit
_VM27AMXFixtureFail:
mov w0, #2
b LAMXCaptureExit
LAMXCaptureExit:
mrs x9, nzcv
adrp x10, _VM27AMXFixtureExitNZCV@PAGE
str x9, [x10, _VM27AMXFixtureExitNZCV@PAGEOFF]
adrp x10, _VM27AMXFixtureExitX8@PAGE
str x8, [x10, _VM27AMXFixtureExitX8@PAGEOFF]
adrp x10, _VM27AMXFixtureExitVectors@PAGE
add x10, x10, _VM27AMXFixtureExitVectors@PAGEOFF
str q0, [x10]
str q31, [x10, #16]
ret
#endif
