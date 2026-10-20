#ifndef VZ_MODERN_CPU_KERNEL_LIFECYCLE_V8_H
#define VZ_MODERN_CPU_KERNEL_LIFECYCLE_V8_H
#include "modern_cpu_kernel_lifecycle_v7.h"
#include "modern_cpu_kernel_system.h"
// Alternative V8 source preserves V7 APIs and adds conditional, single
// native8(NULL) to the existing typed SYS entry. The full required 0x4108
// range is checked against actual self-task mappings before and after op8.
// The logical mask and original get/set order come from genuine0e bytes.
// No ready/version field is written and no op9 retry/reset default is added.
// Architecture reset, RAM binding and complete public Run remain unproved.
#endif
