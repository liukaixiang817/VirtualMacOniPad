/* Production13 is retained verbatim. This private adapter groups only the
 * same owning CPU's C1 key writes; public writer and generic callback behavior
 * remain unchanged. A live native6 CPU pins both actual native pages until its
 * same pthread executes native7. There are no callbacks or guest entry while
 * the Production mutex is held by this finite transaction. */
#include "modern_cpu_production_native_ops_v17_owner_native_base.inc"
#include "modern_cpu_production_pac_batch_v14.h"

bool VM27ProductionPACBatchEligibleV14(const VZKernelLifecycleOps *ops,
 const VZKernelInitWriter *writer) {
 return ops && writer && ops->context==&ProductionV1 && writer->context==&ProductionV1 &&
  ops->currentThread==ProductionThreadV1 && ops->readMemory==ProductionReadV1 &&
  ops->nativeTrap==ProductionNativeV1 && writer->writeMemory==ProductionWriteV1;
}
static bool PACKeyOffsetV14(uint32_t offset) {
 switch(offset) {
  case 0x7b8:case 0x7c0:case 0x7c8:case 0x7d0:case 0x7d8:case 0x7e0:
  case 0x7e8:case 0x7f0:case 0x7f8:case 0x800:case 0x808:case 0x810:return true;
  default:return false;
 }
}
VM27PACBatchResultV14 VM27ProductionPACBatchWriteV14(uintptr_t context,
 uint64_t packedOffsets,const uint64_t *values,unsigned count) {
 VM27PACBatchResultV14 result={0};
 if(!context || !values || (count!=2 && count!=4))return result;
 uint64_t thread=ProductionThreadV1(NULL);if(!thread)return result;
 LockProductionV1();ProductionCPUV1 *cpu=CurrentCPUProductionV1(thread);
 bool ok=ProductionV1.installed && FastCPUProductionV10(cpu,thread) &&
  cpu->nativeContext==context &&
  ExternalRangeProductionV1(values,count*sizeof(*values));
 uint32_t stagedOffsets[4]={0};uint64_t staged[4]={0};
 for(unsigned i=0;i<count;++i)stagedOffsets[i]=(uint32_t)((packedOffsets>>(16*i))&0xffffu);
 for(unsigned i=0;i<count && ok;++i) {
  uint32_t off=stagedOffsets[i];
  ok=PACKeyOffsetV14(off) && WritableProductionV1(off,8) &&
   ContextRangeProductionV10(cpu,(void *)(context+off),8,true) &&
   StackRangeProductionV10(cpu,&values[i],8);
  if(ok)memcpy(&staged[i],&values[i],8);
 }
 uint64_t version=0;
 if(ok)ok=ContextRangeProductionV10(cpu,(void *)(context+0x4000),8,false);
 if(ok) {
  NativeLoadProductionV10((void *)(context+0x4000),8,&version);
  ok=version==VZ_KERNEL_NATIVE_CONTEXT_VERSION;
 }
 for(unsigned i=0;i<count && ok;++i) {
  ++result.attempted;uint64_t readback=0;
  NativeStoreProductionV10((void *)(context+stagedOffsets[i]),8,&staged[i]);
  NativeLoadProductionV10((void *)(context+stagedOffsets[i]),8,&readback);
  ok=readback==staged[i];
  if(ok)++result.completed;
  else cpu->writeFailed=true;
  CountProductionV10(&cpu->fastWrites);
 }
 if(ok) {
  NativeLoadProductionV10((void *)(context+0x4000),8,&version);
  ok=version==VZ_KERNEL_NATIVE_CONTEXT_VERSION;
 }
 if(ok)FastAdmissionProductionV10(cpu,true);
 result.ok=ok;UnlockProductionV1();
 static _Atomic unsigned observations;
 unsigned ordinal=atomic_load_explicit(&observations,memory_order_relaxed);
 while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&observations,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
 if(ordinal<8) {
  int saved=errno;
  dprintf(2,"[Independent27PACBatch14] sample=%u count=%u attempted=%u completed=%u success=%u exactNativeOwner=1 keyValuesUnchanged=1 perFieldReadback=1 nativeCalls=0\n",ordinal+1,count,result.attempted,result.completed,result.ok);
  errno=saved;
 }
 return result;
}
