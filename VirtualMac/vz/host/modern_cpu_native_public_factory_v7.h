#ifndef VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V7_H
#define VM27_MODERN_CPU_NATIVE_PUBLIC_FACTORY_V7_H
#include "modern_cpu_hv_public_abi_v2.h"
#include "modern_cpu_native_public_factory_v6.h"
// Alternative Factory7 + OS5 + acquisitionV2 share one private actual op0.
// This adds the genuine configuration feature getter for closed old selectors
// 0..11. Modern selectors12..17 remain unsupported with unchanged output.
// No feature seed is installed as an Apple USER table or CPU reset default.
#endif
