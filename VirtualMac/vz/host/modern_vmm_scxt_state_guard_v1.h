// Application-owned VMM save/restore section. No hv_* symbol is implemented.
#ifndef VM27_VMM_SCXT_STATE_GUARD_V1_H
#define VM27_VMM_SCXT_STATE_GUARD_V1_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define VM27_VMM_SCXT_EL0_V1 UINT32_C(0xde87)
#define VM27_VMM_SCXT_EL1_V1 UINT32_C(0xc687)
#define VM27_VMM_SCXT_FRAME_EL0_OFFSET_V1 UINT32_C(0x760)
#define VM27_VMM_SCXT_FRAME_EL1_OFFSET_V1 UINT32_C(0x768)
#define VM27_VMM_SCXT_FRAME_SCHEMA_V1 UINT32_C(1)

typedef struct { uint64_t pfr0, pfr1; } VM27VMMGuestPFRV1;
typedef struct {
    uint64_t cpuID, generation, ownerThread;
} VM27VMMCPUStateBindingV1;
typedef enum {
    VM27_VMM_SCXT_ABSENT_V1 = 0,
    VM27_VMM_SCXT_PRESENT_V1 = 1
} VM27VMMSCXTPresenceV1;

// Distinct section outcomes: OMITTED is not HV_SUCCESS and has no SYS value.
typedef enum {
    VM27_VMM_SCXT_CAPTURED_V1 = 0,
    VM27_VMM_SCXT_OMITTED_V1 = 1,
    VM27_VMM_SCXT_BAD_ARGUMENT_V1 = 2,
    VM27_VMM_SCXT_UNSUPPORTED_PROFILE_V1 = 3,
    VM27_VMM_SCXT_INCOMPATIBLE_FRAME_V1 = 4,
    VM27_VMM_SCXT_TYPED_FAILURE_V1 = 5
} VM27VMMSCXTSectionStatusV1;

typedef struct {
    uint32_t schemaVersion;
    VM27VMMSCXTPresenceV1 presence;
    // bit0 EL0, bit1 EL1. Neither slot is architectural state when this is0.
    uint32_t validMask;
    uint32_t reserved;
    VM27VMMGuestPFRV1 guest;
    VM27VMMCPUStateBindingV1 binding;
    uint64_t el0, el1;
} VM27VMMSCXTFrameV1;

// Genuine public LP64 SYS ABI prefix (16-bit SYS identifier). On iOS, supply the same-CPU own public
// provider while its real registry borrow/CPU lock is held. These function
// pointers do not authorize native calls or establish ownership themselves.
typedef int32_t (*VM27VMMGetSYSV1)(uint64_t, uint16_t, uint64_t *);
typedef int32_t (*VM27VMMSetSYSV1)(uint64_t, uint16_t, uint64_t);
typedef struct {
    VM27VMMSCXTSectionStatusV1 status;
    VM27VMMSCXTPresenceV1 presence;
    uint32_t attemptedMask, completedMask;
    int32_t typedReturn;
    uint32_t failedIdentifier;
} VM27VMMSCXTReceiptV1;

// Inputs are the guest-visible values supplied for this CPU, never host/cached
// defaults. CSV2=2/3 implements FEAT_CSV2_2; CSV2_frac belongs only to CSV2=1.
// Reserved encodings refuse. Unknown does not become ABSENT.
VM27VMMSCXTSectionStatusV1 VM27VMMDecodeSCXTProfileV1(
    VM27VMMGuestPFRV1, VM27VMMSCXTPresenceV1 *);

// Caller holds the same real owner-thread lease/CPU lock throughout the call.
// Storage is valid owned C memory and does not overlap. Save publishes its
// complete section only after both true getters succeed; on failure outFrame
// stays unchanged. ABSENT publishes validMask0 and returns OMITTED. Its zero
// storage bytes are never a readable/writable architectural register value.
VM27VMMSCXTSectionStatusV1 VM27VMMSaveSCXTSectionV1(
    VM27VMMGuestPFRV1, VM27VMMCPUStateBindingV1, VM27VMMGetSYSV1,
    VM27VMMSCXTFrameV1 *outFrame, VM27VMMSCXTReceiptV1 *);

// Exact guest PFRs and owner CPU ID/generation/thread must match saved frame.
// Omitted fields never invoke a setter. Present setters are sequential: a
// failure preserves its true return and attempted/completed masks; the caller
// must retain the CPU/frame for recovery. No rollback or successful reset is
// claimed. The saved frame is never modified by Restore.
VM27VMMSCXTSectionStatusV1 VM27VMMRestoreSCXTSectionV1(
    VM27VMMGuestPFRV1, VM27VMMCPUStateBindingV1, VM27VMMSetSYSV1,
    const VM27VMMSCXTFrameV1 *, VM27VMMSCXTReceiptV1 *);

#ifdef __cplusplus
}
#endif
#endif
