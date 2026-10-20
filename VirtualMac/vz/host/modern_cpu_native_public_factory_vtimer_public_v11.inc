// BorrowSetVtimerOffsetV10 stays defined by the frozen Factory9 include.
// Only this copied public wrapper adds observation after PublicEndV6.
#include <ptrauth.h>
typedef struct {
 _Atomic unsigned published,count;
 _Atomic bool seen;
 _Atomic uint64_t lastOffset;
 uint64_t identity,epoch,generation;
} VM27VtimerTraceSlotV11;
static VM27VtimerTraceSlotV11 VM27VtimerTraceSlotsV11[64];
static void VM27VtimerOffsetLogV11(uint64_t identity,uint64_t epoch,uint64_t generation,
 uint64_t offset,hv_return_t status,uintptr_t caller) {
 const int saved=errno;VM27VtimerTraceSlotV11 *slot=NULL;
 for(unsigned i=0;i<64;++i) {
  VM27VtimerTraceSlotV11 *p=&VM27VtimerTraceSlotsV11[i];
  if(atomic_load_explicit(&p->published,memory_order_acquire)==2 &&
   p->identity==identity && p->epoch==epoch && p->generation==generation){slot=p;break;}
 }
 if(!slot)for(unsigned i=0;i<64;++i) {
  VM27VtimerTraceSlotV11 *p=&VM27VtimerTraceSlotsV11[i];unsigned expected=0;
  if(atomic_compare_exchange_strong_explicit(&p->published,&expected,1,
   memory_order_acq_rel,memory_order_acquire)) {
   p->identity=identity;p->epoch=epoch;p->generation=generation;
   atomic_store_explicit(&p->published,2,memory_order_release);slot=p;break;
  }
 }
 if(slot && atomic_load_explicit(&slot->count,memory_order_relaxed)<12) {
  bool seen=atomic_exchange_explicit(&slot->seen,true,memory_order_relaxed);
  uint64_t previous=atomic_exchange_explicit(&slot->lastOffset,offset,memory_order_relaxed);
  if(!seen || previous!=offset) {
   unsigned ordinal=atomic_load_explicit(&slot->count,memory_order_relaxed);
   while(ordinal<12 && !atomic_compare_exchange_weak_explicit(&slot->count,&ordinal,ordinal+1,
    memory_order_relaxed,memory_order_relaxed)){}
   if(ordinal<12)dprintf(2,"[Independent27HV] vtimer-offset-origin id=%llu epoch=%llu generation=%llu ordinal=%u first=%u previousRequested=0x%llx requested=0x%llx publicStatus=0x%08x callerReturnAddress=0x%llx callerPACStripped=1 noNativeRead=1 originalPublicOrderPreserved=1\n",
    (unsigned long long)identity,(unsigned long long)epoch,(unsigned long long)generation,ordinal+1,!seen,
    (unsigned long long)previous,(unsigned long long)offset,(unsigned)status,(unsigned long long)caller);
  }
 }
 errno=saved;
}
hv_return_t hv_vcpu_set_vtimer_offset(hv_vcpu_t identifier,uint64_t offset) {
 uintptr_t caller=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 uint64_t epoch=0,generation=0;
 VM27CPUFactoryBorrowV2 *borrow=NULL;hv_return_t status=VM27CPUFactoryBorrowAcquireV2(identifier,&borrow);
 if(!status) {
  epoch=borrow->epoch;generation=borrow->generation;
  VZKernelInitReceipt receipt={0};
  status=VM27CPUFactoryBorrowSetVtimerOffsetV10(borrow,offset,&receipt,NULL);
  // Failed release retains the real borrow in the existing caller TLS and
  // blocks further public admission until the owner drains that borrow.
  status=PublicReleaseV6(borrow,status);
 }
 PublicEndV6();
 if(epoch && generation)VM27VtimerOffsetLogV11(identifier,epoch,generation,offset,status,caller);
 return status;
}
