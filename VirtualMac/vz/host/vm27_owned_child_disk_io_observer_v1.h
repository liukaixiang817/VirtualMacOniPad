#ifndef VM27_OWNED_CHILD_DISK_IO_OBSERVER_V1_H
#define VM27_OWNED_CHILD_DISK_IO_OBSERVER_V1_H
#include <sys/types.h>
#include <sys/uio.h>
#define VM27_DISK_OBSERVER_EXPORT __attribute__((visibility("default")))
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPreadV1(int, void *, size_t, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPreadvV1(int, const struct iovec *, int, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPwriteV1(int, const void *, size_t, off_t);
VM27_DISK_OBSERVER_EXPORT ssize_t VM27OwnedChildDiskPwritevV1(int, const struct iovec *, int, off_t);
VM27_DISK_OBSERVER_EXPORT int VM27OwnedChildDiskFsyncV1(int);
#endif
