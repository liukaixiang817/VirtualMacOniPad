/* Native6 admits each context metadata page until native7 withdraws it.
 * ProductionMutex prevents native7 from beginning while this read is live;
 * an already-started destroy has destroying set before dropping that lock.
 * Only the version word may cross CPU owners, and only an admitted current
 * CPU's private stack may receive it. No cross-owner register writes. */
#include "modern_cpu_production_cross_wake_v23.h"
bool VM27ProductionWakeVersionReadV23(const VZKernelLifecycleOps *ops,
    const void *address,uint64_t *out) {
    if(!VM27ProductionOwnerBoundaryEligibleV21(ops))return false;
    uint64_t thread=ProductionThreadV1(NULL);
    if(!thread)return false;
    LockProductionV1();
    ProductionCPUV1 *reader=CurrentCPUProductionV1(thread);
    ProductionCPUV1 *target=RangeCPUProductionV1(address,8,thread);
    bool admitted=ProductionV1.installed && ProductionV1.vmLive &&
        ProductionV1.taskPID==getpid() && FastCPUProductionV10(reader,thread) &&
        target && !target->writeFailed &&
        (uintptr_t)address-target->nativeContext==0x4000 &&
        ContextRangeProductionV10(target,address,8,false) &&
        ExternalRangeProductionV1(out,8) && StackRangeProductionV10(reader,out,8);
    if(admitted)NativeLoadProductionV10(address,8,out);
    UnlockProductionV1();
    return admitted;
}
