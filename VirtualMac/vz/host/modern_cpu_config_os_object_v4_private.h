#ifndef VM27_CPU_CONFIG_OS_OBJECT_V4_PRIVATE_H
#define VM27_CPU_CONFIG_OS_OBJECT_V4_PRIVATE_H
#include <stdbool.h>
#include <stddef.h>
// Link the OSv4 alternative and factoryV3 together. The OS output entry calls
// this before taking OS Registry; Factory Registry is released on return.
// The factory check never queries OS Registry or invokes external callbacks.
bool VM27CPUFactoryOutputRangeDisjointV3(const void *, size_t);
#endif
