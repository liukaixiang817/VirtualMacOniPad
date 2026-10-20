#ifndef VM27_RAM_RANGE_V54_H
#define VM27_RAM_RANGE_V54_H
#include "modern_cpu_ram_task_scope_v53.h"
#include "modern_vm_memory_packet.h"
__attribute__((visibility("hidden"))) VZKernelStatus VZKernelRAMRangeChangeV54(VZKernelVM *,uint64_t,VZKernelMemoryOperation,uint64_t,uint64_t,uint64_t,VZKernelRAMResultV9 *);
__attribute__((visibility("hidden"))) VM27CPUFactoryMachStatusV2 VM27CPUFactoryRAMRangeChangeV9(VM27CPUFactoryVMV2 *,VZKernelMemoryOperation,uint64_t,uint64_t,uint64_t,VZKernelRAMResultV9 *);
#endif
