#include "modern_vmm_scxt_state_guard_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, getCalls, setCalls, failAt;
static const int32_t unsupported = (int32_t)UINT32_C(0xfae9400f);
static uint64_t values[2] = {UINT64_C(0x1122334455667788), UINT64_MAX};
static void Check(bool ok) { ++checks; if (!ok) abort(); }
static int32_t Get(uint64_t cpu, uint16_t id, uint64_t *out) {
    Check(cpu == 0);
    Check(id == (getCalls % 2 ? VM27_VMM_SCXT_EL1_V1 : VM27_VMM_SCXT_EL0_V1));
    ++getCalls;
    if (failAt == getCalls) return unsupported;
    *out = values[(getCalls - 1) % 2];
    return 0;
}
static int32_t Set(uint64_t cpu, uint16_t id, uint64_t value) {
    Check(cpu == 0);
    Check(id == (setCalls % 2 ? VM27_VMM_SCXT_EL1_V1 : VM27_VMM_SCXT_EL0_V1));
    Check(value == values[setCalls % 2]);
    ++setCalls;
    return failAt == setCalls ? unsupported : 0;
}
int main(void) {
    VM27VMMCPUStateBindingV1 binding = {.cpuID = 0, .generation = 17, .ownerThread = 23};
    VM27VMMSCXTReceiptV1 receipt;
    VM27VMMSCXTFrameV1 frame, sentinel;
    memset(&sentinel, 0xa5, sizeof(sentinel));
    for (unsigned csv2 = 0; csv2 < 16; ++csv2) {
        for (unsigned frac = 0; frac < 16; ++frac) {
            VM27VMMGuestPFRV1 guest = {UINT64_C(0x0000123456789abc) | (uint64_t)csv2 << 56,
                UINT64_C(0x0000000056789abc) | (uint64_t)frac << 32};
            VM27VMMSCXTPresenceV1 presence = (VM27VMMSCXTPresenceV1)99;
            VM27VMMSCXTSectionStatusV1 status = VM27VMMDecodeSCXTProfileV1(guest, &presence);
            bool known = csv2 <= 3 && frac <= 2 && (csv2 == 1 || frac == 0);
            if (!known) {
                Check(status == VM27_VMM_SCXT_UNSUPPORTED_PROFILE_V1 && (int)presence == 99);
                frame = sentinel;
                Check(VM27VMMSaveSCXTSectionV1(guest, binding, Get, &frame, &receipt) == status);
                Check(memcmp(&frame, &sentinel, sizeof(frame)) == 0 && receipt.attemptedMask == 0);
                continue;
            }
            getCalls = setCalls = failAt = 0;
            Check(status == (csv2 >= 2 ? VM27_VMM_SCXT_CAPTURED_V1 : VM27_VMM_SCXT_OMITTED_V1));
            Check(presence == (csv2 >= 2 ? VM27_VMM_SCXT_PRESENT_V1 : VM27_VMM_SCXT_ABSENT_V1));
            Check(VM27VMMSaveSCXTSectionV1(guest, binding, Get, &frame, &receipt) == status);
            Check(frame.validMask == (csv2 >= 2 ? 3u : 0u) && getCalls == (csv2 >= 2 ? 2u : 0u));
            if (csv2 < 2) {
                // Omitted storage is invalid, so arbitrary old bytes cannot
                // become readable architectural state or a restore write.
                frame.el0 = UINT64_MAX; frame.el1 = UINT64_C(0xdecafbad);
            }
            VM27VMMSCXTFrameV1 saved = frame;
            Check(VM27VMMRestoreSCXTSectionV1(guest, binding, Set, &frame, &receipt) == status);
            Check(memcmp(&frame, &saved, sizeof(frame)) == 0 && setCalls == (csv2 >= 2 ? 2u : 0u));
            VM27VMMGuestPFRV1 changed = guest; changed.pfr0 ^= 1;
            Check(VM27VMMRestoreSCXTSectionV1(changed, binding, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
            VM27VMMCPUStateBindingV1 stale = binding; ++stale.generation;
            Check(VM27VMMRestoreSCXTSectionV1(guest, stale, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
            stale = binding; ++stale.ownerThread;
            Check(VM27VMMRestoreSCXTSectionV1(guest, stale, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
            stale = binding; ++stale.cpuID;
            Check(VM27VMMRestoreSCXTSectionV1(guest, stale, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
            frame.validMask ^= 1;
            Check(VM27VMMRestoreSCXTSectionV1(guest, binding, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
        }
    }
    VM27VMMGuestPFRV1 present = {UINT64_C(2) << 56, 0};
    for (unsigned failing = 1; failing <= 2; ++failing) {
        getCalls = 0; failAt = failing; frame = sentinel;
        Check(VM27VMMSaveSCXTSectionV1(present, binding, Get, &frame, &receipt) == VM27_VMM_SCXT_TYPED_FAILURE_V1);
        Check(memcmp(&frame, &sentinel, sizeof(frame)) == 0 && getCalls == failing);
        Check(receipt.typedReturn == unsupported && receipt.completedMask == (failing == 1 ? 0u : 1u));
        getCalls = failAt = 0;
        Check(VM27VMMSaveSCXTSectionV1(present, binding, Get, &frame, &receipt) == VM27_VMM_SCXT_CAPTURED_V1);
        VM27VMMSCXTFrameV1 saved = frame;
        setCalls = 0; failAt = failing;
        Check(VM27VMMRestoreSCXTSectionV1(present, binding, Set, &frame, &receipt) == VM27_VMM_SCXT_TYPED_FAILURE_V1);
        Check(memcmp(&frame, &saved, sizeof(frame)) == 0 && setCalls == failing);
        Check(receipt.typedReturn == unsupported && receipt.completedMask == (failing == 1 ? 0u : 1u));
        Check(receipt.attemptedMask == (failing == 1 ? 1u : 3u));
        Check(receipt.failedIdentifier == (failing == 1 ? VM27_VMM_SCXT_EL0_V1 : VM27_VMM_SCXT_EL1_V1));
    }
    VM27VMMGuestPFRV1 absent = {UINT64_C(1) << 56, UINT64_C(2) << 32};
    getCalls = setCalls = failAt = 0;
    Check(VM27VMMSaveSCXTSectionV1(absent, binding, NULL, &frame, &receipt) == VM27_VMM_SCXT_OMITTED_V1);
    Check(VM27VMMRestoreSCXTSectionV1(absent, binding, NULL, &frame, &receipt) == VM27_VMM_SCXT_OMITTED_V1);
    Check(getCalls == 0 && setCalls == 0);
    Check(VM27VMMRestoreSCXTSectionV1(present, binding, Set, &frame, &receipt) == VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
    Check(VM27VMMSaveSCXTSectionV1(present, binding, NULL, &frame, &receipt) == VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    Check(VM27VMMSaveSCXTSectionV1(absent, binding, NULL, &frame, (VM27VMMSCXTReceiptV1 *)&frame) == VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    Check(VM27VMMRestoreSCXTSectionV1(absent, binding, NULL, &frame, (VM27VMMSCXTReceiptV1 *)&frame) == VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    printf("{\"checks\":%u,\"allCSV2FractionEncodings\":256,\"mockTypedSYSOnly\":true,\"nativeCalls\":0,\"deviceOperations\":0}\n", checks);
    return 0;
}
