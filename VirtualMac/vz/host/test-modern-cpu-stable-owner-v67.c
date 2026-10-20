/* Exercise the real lifecycle source's private fast predicate and original
 * fallback metadata path. This is a host lifetime test, not a native HV run. */
#include "modern_cpu_kernel_lifecycle_v67.c"
#include <stdio.h>
static unsigned checks,failures;
static void check(bool value){++checks;if(!value)++failures;}
static void *foreign(void *p){VZKernelCPU *cpu=p;check(!StableOwnerMetadataV67(cpu));check(CPUOwnedV5(cpu)==VZ_KERNEL_NOT_LIVE);return NULL;}
int main(void){
 VZKernelVM vm={0};VZKernelCPU cpu={0};VZKernelCPURegistryEntryV5 entry={0};
 pthread_mutex_init(&vm.mutex,NULL);vm.live=true;vm.generation=11;vm.cpuHandles=1;vm.cpuRegistry=&entry;
 cpu.vm=&vm;cpu.live=true;cpu.generation=12;cpu.registryEntry=&entry;cpu.owner=31;cpu.requestedSlot=2;cpu.returnedSlot=2;
 atomic_init(&cpu.operationInProgress,true);entry.cpu=&cpu;entry.ownerPthread=pthread_self();entry.vmEpoch=11;entry.cpuGeneration=12;OwnedCPU=&cpu;
 check(StableOwnerMetadataV67(&cpu));check(CPUOwnedV5(&cpu)==VZ_KERNEL_OK);
 VZKernelLifecycleResult r={0};CPUResult(&cpu,&r);check(r.vmLive&&r.cpuLive&&r.cleanupPending&&r.generation==12&&r.requestedSlot==2&&r.returnedSlotWord==2&&r.ownerThread==31);
 pthread_t t;pthread_create(&t,NULL,foreign,&cpu);pthread_join(t,NULL);
 entry.vmEpoch=99;check(!StableOwnerMetadataV67(&cpu));check(CPUOwnedV5(&cpu)==VZ_KERNEL_NOT_LIVE);entry.vmEpoch=11;
 atomic_store(&cpu.operationInProgress,false);check(!StableOwnerMetadataV67(&cpu));atomic_store(&cpu.operationInProgress,true);
 cpu.live=false;OwnedCPU=NULL;check(!StableOwnerMetadataV67(&cpu));CPUResult(&cpu,&r);check(r.vmLive&&!r.cpuLive);
 vm.cpuRegistry=NULL;vm.cpuHandles=0;vm.live=false;CPUResult(&cpu,&r);check(!r.vmLive&&!r.cpuLive&&!r.cleanupPending);
 pthread_mutex_destroy(&vm.mutex);printf("Real lifecycle67 stable owner checks=%u failures=%u nativeHVExecuted=0\n",checks,failures);return failures?1:0;
}
