#ifndef VM27_CPU_PENDING_INTERRUPT_VALUES_V1_H
#define VM27_CPU_PENDING_INTERRUPT_VALUES_V1_H
#include <stdint.h>

/* Independent application values only. There is no CPU, USER/VIEW, pointer,
 * ownership assertion, run token, read lease, writer or native-call interface.
 * Successful conversion never authorizes applying a plan to live state. */
#define VZ_CPU_PENDING_VALUES_SCHEMA_V1 UINT32_C(1)
#define VZ_CPU_PENDING_OLD_CONTEXT_VERSION_V1 UINT64_C(0x206879700000000e)
typedef struct {
    uint32_t schemaVersion, irqPending, fiqPending, reserved;
} VZCPUPendingInterruptValuesV1;
typedef enum { VZ_CPU_PENDING_IRQ_V1 = 0, VZ_CPU_PENDING_FIQ_V1 = 1 } VZCPUPendingInterruptTypeV1;
typedef struct {
    uint32_t schemaVersion, needsControl0Slice, controlIdentifier, reserved;
    uint64_t latchedPendingMask, requestedControl0Value;
} VZCPUControl0EntryValuePlanV1;
typedef struct {
    uint32_t schemaVersion, needsControl0Slice, controlIdentifier, originalRunStatusBits;
    uint64_t latchedPendingMask, requestedControl0Value;
    VZCPUPendingInterruptValuesV1 pendingAfter;
} VZCPUControl0ReturnValuePlanV1;
typedef enum {
    VZ_CPU_PENDING_VALUES_OK_V1 = 0,
    VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1,
    VZ_CPU_PENDING_VALUES_UNSUPPORTED_V1
} VZCPUPendingValueStatusV1;

/* All output buffers must be disjoint from input objects. Refusals preserve
 * output bytes. Inputs are actual typed values, never raw object/layout casts.
 * IRQ/FIQ type mapping agrees with the SDK and both genuine pending setters. */
#ifdef __cplusplus
extern "C" {
#endif
VZCPUPendingValueStatusV1 VZCPUSetPendingInterruptValueV1(
    const VZCPUPendingInterruptValuesV1 *, uint32_t type, uint32_t pending,
    VZCPUPendingInterruptValuesV1 *);
/* The currentControl0 value must come from genuine own live state. This API
 * does not establish its identity/version/lifetime or perform that read. */
VZCPUPendingValueStatusV1 VZCPUPlanControl0EntryValueV1(
    const VZCPUPendingInterruptValuesV1 *, uint64_t nativeContextVersion,
    uint64_t currentControl0, VZCPUControl0EntryValuePlanV1 *);
/* This is a value plan for the saved entry latch and separately read CURRENT
 * post-return control0. It is not a substitute for a Run/post-return lease.
 * Original old-run clears private pending BEFORE executing its control slice;
 * that ordering and mutation failure recovery belong to the eventual caller.
 * Existing V2 CONTROL0 adds its audited synchronization marks after writing
 * requestedControl0Value. The original run status is carried independently. */
VZCPUPendingValueStatusV1 VZCPUPlanControl0ReturnValueV1(
    const VZCPUControl0EntryValuePlanV1 *, const VZCPUPendingInterruptValuesV1 *,
    uint64_t nativeContextVersion, uint64_t currentPostReturnControl0,
    uint32_t originalRunStatusBits, VZCPUControl0ReturnValuePlanV1 *);
#ifdef __cplusplus
}
#endif
#endif
