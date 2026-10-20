#include "modern_cpu_pending_interrupt_values_v1.h"
#include <stddef.h>
#include <string.h>

static int Disjoint(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t av=(uintptr_t)a,bv=(uintptr_t)b;
    if(av>UINTPTR_MAX-an||bv>UINTPTR_MAX-bn)return 0;
    return av+an<=bv||bv+bn<=av;
}
static int Valid(const VZCPUPendingInterruptValuesV1 *v) {
    return v->schemaVersion==VZ_CPU_PENDING_VALUES_SCHEMA_V1 &&
        v->irqPending<=1 && v->fiqPending<=1 && !v->reserved;
}
static uint64_t Mask(const VZCPUPendingInterruptValuesV1 *v) {
    return (v->irqPending?UINT64_C(0x80):0)|(v->fiqPending?UINT64_C(0x40):0);
}
VZCPUPendingValueStatusV1 VZCPUSetPendingInterruptValueV1(
    const VZCPUPendingInterruptValuesV1 *input,uint32_t type,uint32_t pending,
    VZCPUPendingInterruptValuesV1 *out) {
    if(!input||!out||!Disjoint(input,sizeof(*input),out,sizeof(*out)))
        return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    VZCPUPendingInterruptValuesV1 value;memcpy(&value,input,sizeof(value));
    if(!Valid(&value)||pending>1)return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    if(type==VZ_CPU_PENDING_IRQ_V1)value.irqPending=pending;
    else if(type==VZ_CPU_PENDING_FIQ_V1)value.fiqPending=pending;
    else return VZ_CPU_PENDING_VALUES_UNSUPPORTED_V1;
    memcpy(out,&value,sizeof(value));return VZ_CPU_PENDING_VALUES_OK_V1;
}
VZCPUPendingValueStatusV1 VZCPUPlanControl0EntryValueV1(
    const VZCPUPendingInterruptValuesV1 *input,uint64_t version,
    uint64_t current,VZCPUControl0EntryValuePlanV1 *out) {
    if(!input||!out||!Disjoint(input,sizeof(*input),out,sizeof(*out)))
        return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    VZCPUPendingInterruptValuesV1 value;memcpy(&value,input,sizeof(value));
    if(!Valid(&value))return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    if(version!=VZ_CPU_PENDING_OLD_CONTEXT_VERSION_V1)return VZ_CPU_PENDING_VALUES_UNSUPPORTED_V1;
    VZCPUControl0EntryValuePlanV1 result={0};
    result.schemaVersion=VZ_CPU_PENDING_VALUES_SCHEMA_V1;
    result.latchedPendingMask=Mask(&value);
    result.needsControl0Slice=result.latchedPendingMask!=0;
    result.requestedControl0Value=current|result.latchedPendingMask;
    memcpy(out,&result,sizeof(result));return VZ_CPU_PENDING_VALUES_OK_V1;
}
VZCPUPendingValueStatusV1 VZCPUPlanControl0ReturnValueV1(
    const VZCPUControl0EntryValuePlanV1 *input,
    const VZCPUPendingInterruptValuesV1 *currentPending,uint64_t version,
    uint64_t currentControl0,uint32_t runStatus,VZCPUControl0ReturnValuePlanV1 *out) {
    if(!input||!currentPending||!out||
        !Disjoint(input,sizeof(*input),out,sizeof(*out))||
        !Disjoint(currentPending,sizeof(*currentPending),out,sizeof(*out)))
        return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    VZCPUControl0EntryValuePlanV1 entry;
    VZCPUPendingInterruptValuesV1 pending;
    memcpy(&entry,input,sizeof(entry));memcpy(&pending,currentPending,sizeof(pending));
    if(!Valid(&pending)||entry.schemaVersion!=VZ_CPU_PENDING_VALUES_SCHEMA_V1||
        entry.controlIdentifier||entry.reserved||entry.needsControl0Slice>1||
        entry.needsControl0Slice!=(entry.latchedPendingMask!=0))
        return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    /* USER140 bit8 and modern VIEW/policy branches are deliberately not a
     * boolean IRQ/FIQ contract. Refuse them rather than transplanting flags. */
    if(version!=VZ_CPU_PENDING_OLD_CONTEXT_VERSION_V1||
        (entry.latchedPendingMask&~UINT64_C(0xc0)))
        return VZ_CPU_PENDING_VALUES_UNSUPPORTED_V1;
    if((entry.requestedControl0Value&entry.latchedPendingMask)!=entry.latchedPendingMask)
        return VZ_CPU_PENDING_VALUES_BAD_ARGUMENT_V1;
    VZCPUControl0ReturnValuePlanV1 result={0};
    result.schemaVersion=VZ_CPU_PENDING_VALUES_SCHEMA_V1;
    result.needsControl0Slice=entry.needsControl0Slice;
    result.originalRunStatusBits=runStatus;
    result.latchedPendingMask=entry.latchedPendingMask;
    result.requestedControl0Value=currentControl0;
    result.pendingAfter=pending;
    if(entry.latchedPendingMask){
        result.pendingAfter.irqPending=0;result.pendingAfter.fiqPending=0;
        result.requestedControl0Value=currentControl0&~UINT64_C(0xc0);
    }
    memcpy(out,&result,sizeof(result));return VZ_CPU_PENDING_VALUES_OK_V1;
}
