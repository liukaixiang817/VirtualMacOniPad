#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V9_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V9_H
#include "modern_cpu_kernel_lifecycle_v8.h"
#include "modern_vm_memory_packet.h"
typedef struct VZKernelRAMV9 VZKernelRAMV9;
typedef struct {
 VZKernelStatus status;
 bool nativeInvoked;
 int32_t nativeReturn;
 uint64_t vmEpoch, ownerThread, bytes, guestAddress, flags;
 bool mapped, mappingUncertain, cleanupPending;
} VZKernelRAMResultV9;
// Own allocation, with guard pages. Caller must not munmap/reprotect the
// borrowed host address. No foreign host pointer is accepted. Native failures
// retain backing until an owner-verified successful unmap; all RAM handles
// block VM destroy/free. Map/protect/unmap/write/free require zero CPU handles.
// RAM may stay mapped while CPUs are created and live. Whole ranges only.
VZKernelStatus VZKernelRAMCreateV9(VZKernelVM *, uint64_t bytes,
 VZKernelRAMV9 **outRAM, void **outHostAddress, VZKernelRAMResultV9 *);
VZKernelStatus VZKernelRAMWriteV9(VZKernelRAMV9 *, uint64_t offset,
 const void *source, size_t bytes, VZKernelRAMResultV9 *);
VZKernelStatus VZKernelRAMMapV9(VZKernelRAMV9 *, uint64_t guestAddress,
 uint64_t flags, VZKernelRAMResultV9 *);
VZKernelStatus VZKernelRAMProtectV9(VZKernelRAMV9 *, uint64_t flags, VZKernelRAMResultV9 *);
VZKernelStatus VZKernelRAMUnmapV9(VZKernelRAMV9 *, VZKernelRAMResultV9 *);
VZKernelStatus VZKernelRAMFreeV9(VZKernelRAMV9 *);
#endif
