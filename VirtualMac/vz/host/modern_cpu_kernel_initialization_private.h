// Internal offset-only engine. No raw context is passed to modern consumers.
#ifndef VZ_MODERN_CPU_KERNEL_INITIALIZATION_PRIVATE_H
#define VZ_MODERN_CPU_KERNEL_INITIALIZATION_PRIVATE_H
#include "modern_cpu_kernel_initialization.h"

typedef struct {
    void *context;
    bool (*readAt)(void *, uint32_t, size_t, void *);
    bool (*writeAt)(void *, uint32_t, size_t, const void *);
} VZKernelInitAccess;

VZKernelStatus VZKernelInitApplyVerifiedSlice(const VZKernelInitRequest *,
    const VZKernelInitAccess *, VZKernelInitReceipt *);
bool VZKernelInitOffsetWritable(uint32_t, size_t);
#endif
