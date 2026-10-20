#ifndef VM27_MODERN_CPU_HV_PUBLIC_ABI_V3_H
#define VM27_MODERN_CPU_HV_PUBLIC_ABI_V3_H
#include "modern_cpu_hv_public_abi_v2.h"
#if !__has_include(<Hypervisor/hv_vcpu.h>)
// MacOSX27 hv_vcpu_types.h: true public 32-bit enum and IRQ0/FIQ1 values.
// iOS lacks that framework header; this adds only its audited caller ABI.
typedef enum {HV_INTERRUPT_TYPE_IRQ=0,HV_INTERRUPT_TYPE_FIQ=1} hv_interrupt_type_t;
#endif
#endif
