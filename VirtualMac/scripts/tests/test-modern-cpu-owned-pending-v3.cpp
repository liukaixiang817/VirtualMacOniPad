#include "modern_cpu_kernel_lifecycle_v3.h"
#include <cstring>

int main() {
    VZCPUPendingInterruptValuesV1 output;
    std::memset(&output,0xa5,sizeof(output));
    const auto before=output;
    if(VZKernelCPUReadPendingInterruptsV3(nullptr,&output)!=VZ_KERNEL_BAD_ARGUMENT)
        return 1;
    if(std::memcmp(&output,&before,sizeof(output))) return 2;
    if(VZKernelCPUSetPendingInterruptV3(nullptr,VZ_CPU_PENDING_IRQ_V1,1)!=VZ_KERNEL_BAD_ARGUMENT)
        return 3;
    if(VZKernelNativeHVISAIsKnown(0)) return 4;
    return 0;
}
