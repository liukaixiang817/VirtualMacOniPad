/* Each admitted CPU already belongs to the publishing pthread until native7.
 * Cache its immutable metadata in that pthread's private TLS; still compare
 * the actual shared epoch and PID before every access, and epoch again after
 * the fresh load. Foreign threads, fork, withdrawal and unadmitted buffers use
 * the unchanged original paths. The private slots are aligned to Apple ARM64
 * cache lines so another CPU's counters do not share this owner's metadata. */
#define VM27CPUOwnedMappingPublishV1 VM27CPUOwnedMappingPublishSlowV6
#define VM27CPUOwnedMappingWithdrawV1 VM27CPUOwnedMappingWithdrawSlowV6
#define VM27CPUSelfOwnedMappedRangeV1 VM27CPUSelfOwnedMappedRangeSlowV6
#define VM27CPUOwnedVersionReadV2 VM27CPUOwnedVersionReadSlowV6
#include "modern_cpu_owned_mapping_cache_v6_owner_tls_base.inc"
#undef VM27CPUOwnedMappingPublishV1
#undef VM27CPUOwnedMappingWithdrawV1
#undef VM27CPUSelfOwnedMappedRangeV1
#undef VM27CPUOwnedVersionReadV2
#define VM27CPUOwnedScalarReadV4 VM27CPUOwnedScalarReadSlowV6
#include "modern_cpu_owned_scalar_read_v6_slow.inc"
#undef VM27CPUOwnedScalarReadV4

typedef struct {
 OwnedMappingV1 *mapping;
 uint64_t epoch,token;
 pid_t pid;
 uintptr_t context,stack;
 size_t stackBytes;
 unsigned reads,writes;
} OwnerMappingTLSV6;
static _Thread_local OwnerMappingTLSV6 OwnerMappingV6;
_Static_assert(_Alignof(OwnedMappingV1)>=128 && sizeof(OwnedMappingV1)%128==0,
 "CPU admission metadata and counters cannot share another CPU slot cache line");
static bool CurrentMappingV6(void) {
 OwnerMappingTLSV6 *c=&OwnerMappingV6;
 return c->mapping && c->epoch && !(c->epoch&1) && c->pid==getpid() &&
  atomic_load_explicit(&c->mapping->epoch,memory_order_acquire)==c->epoch;
}
static bool SameMappingV6(void) {
 atomic_thread_fence(memory_order_acquire);
 return atomic_load_explicit(&OwnerMappingV6.mapping->epoch,memory_order_relaxed)==OwnerMappingV6.epoch;
}
static bool ContextRangeV6(uintptr_t at,size_t bytes,bool write) {
 OwnerMappingTLSV6 *c=&OwnerMappingV6;
 if(!InsideOwnedMappingV1(at,bytes,c->context,0x8000))return false;
 unsigned first=(unsigned)((at-c->context)>>14),last=(unsigned)((at-c->context+bytes-1)>>14);
 unsigned required=(1u<<first)|(1u<<last),pages=write?c->writes:c->reads;
 return (pages&required)==required;
}
bool VM27CPUOwnedMappingPublishV1(uint64_t slot,uintptr_t token,uint64_t thread,
 uintptr_t context,unsigned reads,unsigned writes,uintptr_t stack,size_t bytes,bool fullRW) {
 if(!VM27CPUOwnedMappingPublishSlowV6(slot,token,thread,context,reads,writes,stack,bytes,fullRW))return false;
 OwnedMappingV1 *m=&mappings[slot];uint64_t epoch=atomic_load_explicit(&m->epoch,memory_order_acquire);
 OwnerMappingTLSV6 c={.mapping=m,.epoch=epoch,.token=token,.pid=getpid(),.context=context,
  .stack=atomic_load_explicit(&m->stackStart,memory_order_relaxed),
  .stackBytes=atomic_load_explicit(&m->stackBytes,memory_order_relaxed),.reads=reads,.writes=writes};
 if(epoch && !(epoch&1) && atomic_load_explicit(&m->token,memory_order_relaxed)==token &&
    atomic_load_explicit(&m->epoch,memory_order_acquire)==epoch)OwnerMappingV6=c;
 return true;
}
void VM27CPUOwnedMappingWithdrawV1(uint64_t slot,uintptr_t token,VM27CPUOwnedMappingCountsV1 *counts) {
 VM27CPUOwnedMappingWithdrawSlowV6(slot,token,counts);
 if(slot<64 && OwnerMappingV6.mapping==&mappings[slot] && OwnerMappingV6.token==token)
  OwnerMappingV6=(OwnerMappingTLSV6){0};
}
bool VM27CPUSelfOwnedMappedRangeV1(const void *address,size_t bytes,bool write,
 VM27CPUSelfMappedReceiptV1 *receipt) {
 uintptr_t at=(uintptr_t)address;
 if(!receipt && at && bytes && bytes<=0x8000 && bytes<=UINTPTR_MAX-at && CurrentMappingV6()) {
  bool context=InsideOwnedMappingV1(at,bytes,OwnerMappingV6.context,0x8000);
  bool admitted=context?ContextRangeV6(at,bytes,write):
   InsideOwnedMappingV1(at,bytes,OwnerMappingV6.stack,OwnerMappingV6.stackBytes);
  if(admitted && SameMappingV6()) {
   CountOwnedMappingV1(context?&OwnerMappingV6.mapping->contextHits:&OwnerMappingV6.mapping->stackHits);
   return true;
  }
 }
 return VM27CPUSelfOwnedMappedRangeSlowV6(address,bytes,write,receipt);
}
__attribute__((visibility("hidden"))) bool VM27CPUOwnedVersionReadV2(const void *address,void *out) {
 if(address && out && CurrentMappingV6() && (uintptr_t)address==OwnerMappingV6.context+0x4000 &&
    (OwnerMappingV6.reads&2u) &&
    InsideOwnedMappingV1((uintptr_t)out,8,OwnerMappingV6.stack,OwnerMappingV6.stackBytes) && SameMappingV6()) {
  uint64_t value=*(const volatile uint64_t *)address;
  if(!SameMappingV6())return false;
  memcpy(out,&value,8);return true;
 }
 return VM27CPUOwnedVersionReadSlowV6(address,out);
}
__attribute__((visibility("hidden"))) bool VM27CPUOwnedScalarReadV4(const void *address,size_t bytes,void *out) {
 uintptr_t at=(uintptr_t)address;
 if(address && out && bytes && bytes<=16 && CurrentMappingV6() && ContextRangeV6(at,bytes,false) &&
    InsideOwnedMappingV1((uintptr_t)out,bytes,OwnerMappingV6.stack,OwnerMappingV6.stackBytes) && SameMappingV6()) {
  unsigned char staged[16];
  if(bytes==8 && !(at&7)){uint64_t v=*(const volatile uint64_t *)address;memcpy(staged,&v,8);}
  else if(bytes==4 && !(at&3)){uint32_t v=*(const volatile uint32_t *)address;memcpy(staged,&v,4);}
  else if(bytes==2 && !(at&1)){uint16_t v=*(const volatile uint16_t *)address;memcpy(staged,&v,2);}
  else {const volatile unsigned char *src=address;for(size_t i=0;i<bytes;++i)staged[i]=src[i];}
  if(!SameMappingV6())return false;
  memcpy(out,staged,bytes);CountOwnedMappingV1(&OwnerMappingV6.mapping->contextHits);return true;
 }
 return VM27CPUOwnedScalarReadSlowV6(address,bytes,out);
}
