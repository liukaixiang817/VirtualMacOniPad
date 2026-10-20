#ifndef VM27_CPU_CONFIG_OS_OBJECT_V3_PRIVATE_H
#define VM27_CPU_CONFIG_OS_OBJECT_V3_PRIVATE_H
#include <stdbool.h>
#include <stddef.h>
// Hidden cross-component output guard. No callback/native query is performed.
// Factory Registry may be held; this function acquires only OS Registry.
// OS Registry is never held while calling a factory or external acquisition.
bool VM27CPUConfigOutputRangeDisjointV3(const void *, size_t);
#endif
