#ifndef VM27_OWNED_CHILD_DISK_IO_OBSERVER_V3_H
#define VM27_OWNED_CHILD_DISK_IO_OBSERVER_V3_H
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <dispatch/dispatch.h>
#define VM27_DISK_OBSERVER_EXPORT __attribute__((visibility("default")))
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPreadV1(int, void *, size_t, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPreadvV1(int, const struct iovec *, int, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPwriteV1(int, const void *, size_t, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPwritevV1(int, const struct iovec *, int, off_t);
VM27_DISK_OBSERVER_EXPORT int VM27OwnedChildDiskFsyncV1(int);
VM27_DISK_OBSERVER_EXPORT void VM27OwnedChildCompletionDispatchSyncV1(dispatch_queue_t, void *, dispatch_function_t);
VM27_DISK_OBSERVER_EXPORT int VM27OwnedChildCompletionKdebugTraceV1(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
#endif
