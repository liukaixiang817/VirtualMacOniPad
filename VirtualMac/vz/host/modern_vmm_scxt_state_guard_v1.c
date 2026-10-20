#include "modern_vmm_scxt_state_guard_v1.h"
#include <stddef.h>
#include <string.h>

static bool Overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (an > UINTPTR_MAX - x || bn > UINTPTR_MAX - y) return true;
    return x < y + bn && y < x + an;
}

VM27VMMSCXTSectionStatusV1 VM27VMMDecodeSCXTProfileV1(
    VM27VMMGuestPFRV1 guest, VM27VMMSCXTPresenceV1 *out) {
    if (!out) return VM27_VMM_SCXT_BAD_ARGUMENT_V1;
    unsigned csv2 = (unsigned)((guest.pfr0 >> 56) & 15);
    unsigned frac = (unsigned)((guest.pfr1 >> 32) & 15);
    if (csv2 > 3 || frac > 2 || (csv2 != 1 && frac != 0))
        return VM27_VMM_SCXT_UNSUPPORTED_PROFILE_V1;
    *out = csv2 >= 2 ? VM27_VMM_SCXT_PRESENT_V1 : VM27_VMM_SCXT_ABSENT_V1;
    return csv2 >= 2 ? VM27_VMM_SCXT_CAPTURED_V1 : VM27_VMM_SCXT_OMITTED_V1;
}

static bool BindingValid(VM27VMMCPUStateBindingV1 binding) {
    // CPU ID0 is legal. A live registry generation/thread cannot be0.
    return binding.generation != 0 && binding.ownerThread != 0;
}

static VM27VMMSCXTSectionStatusV1 Finish(VM27VMMSCXTReceiptV1 *receipt,
    VM27VMMSCXTSectionStatusV1 status) {
    receipt->status = status;
    return status;
}

VM27VMMSCXTSectionStatusV1 VM27VMMSaveSCXTSectionV1(
    VM27VMMGuestPFRV1 guest, VM27VMMCPUStateBindingV1 binding,
    VM27VMMGetSYSV1 get, VM27VMMSCXTFrameV1 *out,
    VM27VMMSCXTReceiptV1 *receipt) {
    if (!out || !receipt || Overlap(out, sizeof(*out), receipt, sizeof(*receipt)))
        return VM27_VMM_SCXT_BAD_ARGUMENT_V1;
    *receipt = (VM27VMMSCXTReceiptV1){0};
    if (!BindingValid(binding)) return Finish(receipt, VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    VM27VMMSCXTPresenceV1 presence;
    VM27VMMSCXTSectionStatusV1 status = VM27VMMDecodeSCXTProfileV1(guest, &presence);
    if (status == VM27_VMM_SCXT_UNSUPPORTED_PROFILE_V1) return Finish(receipt, status);
    receipt->presence = presence;
    VM27VMMSCXTFrameV1 frame = {
        .schemaVersion = VM27_VMM_SCXT_FRAME_SCHEMA_V1, .presence = presence,
        .guest = guest, .binding = binding
    };
    if (presence == VM27_VMM_SCXT_ABSENT_V1) {
        *out = frame;
        return Finish(receipt, VM27_VMM_SCXT_OMITTED_V1);
    }
    if (!get) return Finish(receipt, VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    receipt->attemptedMask = 1;
    receipt->typedReturn = get(binding.cpuID, VM27_VMM_SCXT_EL0_V1, &frame.el0);
    if (receipt->typedReturn) {
        receipt->failedIdentifier = VM27_VMM_SCXT_EL0_V1;
        return Finish(receipt, VM27_VMM_SCXT_TYPED_FAILURE_V1);
    }
    receipt->completedMask = 1;
    receipt->attemptedMask |= 2;
    receipt->typedReturn = get(binding.cpuID, VM27_VMM_SCXT_EL1_V1, &frame.el1);
    if (receipt->typedReturn) {
        receipt->failedIdentifier = VM27_VMM_SCXT_EL1_V1;
        return Finish(receipt, VM27_VMM_SCXT_TYPED_FAILURE_V1);
    }
    receipt->completedMask = frame.validMask = 3;
    *out = frame;
    return Finish(receipt, VM27_VMM_SCXT_CAPTURED_V1);
}

VM27VMMSCXTSectionStatusV1 VM27VMMRestoreSCXTSectionV1(
    VM27VMMGuestPFRV1 guest, VM27VMMCPUStateBindingV1 binding,
    VM27VMMSetSYSV1 set, const VM27VMMSCXTFrameV1 *input,
    VM27VMMSCXTReceiptV1 *receipt) {
    if (!input || !receipt || Overlap(input, sizeof(*input), receipt, sizeof(*receipt)))
        return VM27_VMM_SCXT_BAD_ARGUMENT_V1;
    VM27VMMSCXTFrameV1 frame = *input;
    *receipt = (VM27VMMSCXTReceiptV1){0};
    if (!BindingValid(binding)) return Finish(receipt, VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    VM27VMMSCXTPresenceV1 presence;
    VM27VMMSCXTSectionStatusV1 status = VM27VMMDecodeSCXTProfileV1(guest, &presence);
    if (status == VM27_VMM_SCXT_UNSUPPORTED_PROFILE_V1) return Finish(receipt, status);
    receipt->presence = presence;
    if (frame.schemaVersion != VM27_VMM_SCXT_FRAME_SCHEMA_V1 || frame.reserved ||
        frame.guest.pfr0 != guest.pfr0 || frame.guest.pfr1 != guest.pfr1 ||
        frame.binding.cpuID != binding.cpuID ||
        frame.binding.generation != binding.generation ||
        frame.binding.ownerThread != binding.ownerThread ||
        frame.presence != presence ||
        frame.validMask != (presence == VM27_VMM_SCXT_PRESENT_V1 ? 3u : 0u))
        return Finish(receipt, VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1);
    if (presence == VM27_VMM_SCXT_ABSENT_V1)
        return Finish(receipt, VM27_VMM_SCXT_OMITTED_V1);
    if (!set) return Finish(receipt, VM27_VMM_SCXT_BAD_ARGUMENT_V1);
    receipt->attemptedMask = 1;
    receipt->typedReturn = set(binding.cpuID, VM27_VMM_SCXT_EL0_V1, frame.el0);
    if (receipt->typedReturn) {
        receipt->failedIdentifier = VM27_VMM_SCXT_EL0_V1;
        return Finish(receipt, VM27_VMM_SCXT_TYPED_FAILURE_V1);
    }
    receipt->completedMask = 1;
    receipt->attemptedMask |= 2;
    receipt->typedReturn = set(binding.cpuID, VM27_VMM_SCXT_EL1_V1, frame.el1);
    if (receipt->typedReturn) {
        receipt->failedIdentifier = VM27_VMM_SCXT_EL1_V1;
        return Finish(receipt, VM27_VMM_SCXT_TYPED_FAILURE_V1);
    }
    receipt->completedMask = 3;
    return Finish(receipt, VM27_VMM_SCXT_CAPTURED_V1);
}
