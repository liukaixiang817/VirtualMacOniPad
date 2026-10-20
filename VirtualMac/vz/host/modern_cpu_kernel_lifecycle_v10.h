#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V10_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V10_H
#include "modern_cpu_kernel_lifecycle_v9.h"
// Logical value getter for exactly old genuine public scalar0..34/SIMD0..31.
// FPCR/FPSR/CPSR 32-bit backing is zero extended to public64. No native8/9,
// arbitrary offset or raw modern VIEW is provided. Same actual owner/TLS/gen.
typedef struct { uint64_t low,high; } VZKernelRegisterValueV10;
VZKernelStatus VZKernelCPUReadRegisterV10(VZKernelCPU *,VZKernelInitOperation,
 uint32_t identifier,VZKernelRegisterValueV10 *,VZKernelLifecycleResult *);
#endif
