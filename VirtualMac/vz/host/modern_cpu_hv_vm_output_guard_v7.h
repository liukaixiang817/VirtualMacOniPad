#ifndef VM27_CPU_HV_VM_OUTPUT_GUARD_V7_H
#define VM27_CPU_HV_VM_OUTPUT_GUARD_V7_H
#include <stdbool.h>
#include <stddef.h>
// The combined provider compiles Factory7 with this flag and the actual VM
// bootstrap guard. The bootstrap MUST refuse installation when it is false.
// No weak import or foreign callback supplies this guard.
#ifndef VM27_HV_VM_GUARD_LINKED
#define VM27_HV_VM_GUARD_LINKED 0
#endif
__attribute__((visibility("hidden")))
bool VM27CPUFactoryVMOutputGuardLinkedV7(void);
#if VM27_HV_VM_GUARD_LINKED
__attribute__((visibility("hidden")))
bool VM27HVVMOutputRangeDisjointV1(const void *,size_t);
#endif
// FactoryRegistry -> VMRegistry. The VM guard never calls Factory or OS.
// VM entrypoints query Factory BEFORE acquiring VMRegistry and release their
// mutex before every Factory lifecycle call. OS queries Factory before OSlock.
#endif
