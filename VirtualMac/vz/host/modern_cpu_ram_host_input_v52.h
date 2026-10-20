#ifndef VM27_RAM_HOST_INPUT_V52_H
#define VM27_RAM_HOST_INPUT_V52_H
#include <stdbool.h>
#include <stddef.h>
// Mapping inputs may alias retained caller-owned borrowed RAM data. They may
// never alias provider control allocations or provider-owned RAM allocations.
__attribute__((visibility("hidden"))) bool VZKernelRAMHostInputRangeDisjointV52(const void *,size_t);
__attribute__((visibility("hidden"))) bool VM27CPUFactoryRAMHostInputRangeDisjointV7(const void *,size_t);
__attribute__((visibility("hidden"))) bool VM27HVVMRAMHostInputRangeDisjointV26(const void *,size_t);
#endif
