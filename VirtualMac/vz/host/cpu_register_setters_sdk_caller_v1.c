#include <Hypervisor/hv_vcpu.h>
#include "modern_cpu_public_register_setters_v1.h"

// Compiler-only genuine SDK caller. Neither call is linked or executed.
int32_t VM27SDKSIMDCallerABIOnlyV1(hv_vcpu_t cpu, hv_simd_fp_reg_t reg,
    hv_simd_fp_uchar16_t value, const VZKernelInitWriter *writer,
    VZKernelInitReceipt *receipt, VM27CPUFactoryDiagnosticV2 *diagnostic) {
    int32_t original = hv_vcpu_set_simd_fp_reg(cpu,reg,value);
    return original + VM27CPUSetSIMDRegisterV1(cpu,(uint32_t)reg,value,
        writer,receipt,diagnostic);
}
