/* V2 retains the V1 value layout and linked symbol. The prior caller-owned
 * native provenance is unchanged. Unlike the historical V1 policy, legal
 * unhandled 64-bit MRS/MSR (EC18, IL1, op0>=2) is a public exception for the
 * original VMM. Stateful HVC/private and non-register SYS remain refused. */
#ifndef VZ_MODERN_CPU_NATIVE_EXIT_REDUCER_V2_H
#define VZ_MODERN_CPU_NATIVE_EXIT_REDUCER_V2_H
#include "modern_cpu_native_exit_reducer_v1.h"
#endif
