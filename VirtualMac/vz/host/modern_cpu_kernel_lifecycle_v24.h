#ifndef VM27_CPU_KERNEL_LIFECYCLE_V24_H
#define VM27_CPU_KERNEL_LIFECYCLE_V24_H
#include "modern_cpu_kernel_lifecycle_v23.h"
// Same ABI and registry. Borrowed backing requires READ; requested guest WRITE
// additionally requires host WRITE at map/protect. RAM writes remain checked.
#endif
