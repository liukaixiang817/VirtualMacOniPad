#include <time.h>
#include "modern_gic_v3_engine_v5.h"
#include "modern_cpu_run_receipt_diagnostic_v29.inc"
#include <dispatch/dispatch.h>
// Resolved by the final link to this provider's existing public implementation.
extern int32_t hv_vcpus_exit(uint64_t *,uint32_t);
// Fixed process-lifetime diagnostic slots; never retain a native CPU/VM owner.
// At most one wake for each identity/epoch/generation, with no slot reuse.
typedef struct {
 _Atomic unsigned published,phase;
 _Atomic bool sampled;
 uint64_t identity,epoch,generation;
 int32_t result;
} VM27RunWakeSlotV63;
static VM27RunWakeSlotV63 VM27RunWakeSlotsV63[64];
static _Atomic bool VM27KernelInspectionClaimedV63;
static VM27RunWakeSlotV63 *VM27RunWakeSlotForV63(const VZKernelRunPendingRequestV14 *q,bool create) {
 for(unsigned i=0;i<64;++i) {
  VM27RunWakeSlotV63 *s=&VM27RunWakeSlotsV63[i];
  if(atomic_load_explicit(&s->published,memory_order_acquire)==2 &&
   s->identity==q->expectedPublicIdentity && s->epoch==q->expectedVMEpoch &&
   s->generation==q->expectedCPUGeneration)return s;
 }
 if(create)for(unsigned i=0;i<64;++i) {
  VM27RunWakeSlotV63 *s=&VM27RunWakeSlotsV63[i];unsigned expected=0;
  if(atomic_compare_exchange_strong_explicit(&s->published,&expected,1,memory_order_acq_rel,memory_order_acquire)) {
   s->identity=q->expectedPublicIdentity;s->epoch=q->expectedVMEpoch;s->generation=q->expectedCPUGeneration;
   atomic_store_explicit(&s->published,2,memory_order_release);return s;
  }
 }
 return NULL;
}
typedef struct {
 uint64_t identity,epoch,generation;
 VM27RunWakeSlotV63 *slot;
 dispatch_source_t source;
 dispatch_queue_t queue;
} VM27RunWakeJobV34;
static void VM27RunWakeCancelledV34(void *context) {
 VM27RunWakeJobV34 *job=context;
 dispatch_source_t source=job->source;dispatch_queue_t queue=job->queue;
 free(job);dispatch_release(source);dispatch_release(queue);
}
static void VM27RunWakeFiredV34(void *context) {
 VM27RunWakeJobV34 *job=context;unsigned expected=2;
 if(!atomic_compare_exchange_strong_explicit(&job->slot->phase,&expected,3,
  memory_order_acq_rel,memory_order_acquire))return;
 const int saved=errno;uint64_t identity=job->identity;
 dprintf(2,"[Independent27HV] diagnostic-wake-enter phase=3 id=%llu epoch=%llu generation=%llu actualRunReturnNotClaimed=1\n",
  (unsigned long long)identity,(unsigned long long)job->epoch,(unsigned long long)job->generation);
 // The public entry reacquires its actual registered attachment and retained
 // wake owner. No CPU, VM or lower-owner pointer survives in this timer job.
 int32_t result=hv_vcpus_exit(&identity,1);
 job->slot->result=result;
 atomic_store_explicit(&job->slot->phase,4,memory_order_release);
 dprintf(2,"[Independent27HV] diagnostic-wake-return phase=4 id=%llu epoch=%llu generation=%llu publicStatus=0x%08x actualRunReturnNotClaimed=1\n",
  (unsigned long long)identity,(unsigned long long)job->epoch,(unsigned long long)job->generation,(unsigned)result);
 dispatch_source_cancel(job->source);errno=saved;
}
static void VM27RunWakeArmV34(const VZKernelRunPendingRequestV14 *q) {
 VM27RunWakeSlotV63 *slot=VM27RunWakeSlotForV63(q,true);if(!slot)return;
 unsigned expected=0;
 if(!atomic_compare_exchange_strong_explicit(&slot->phase,&expected,1,
  memory_order_acq_rel,memory_order_acquire))return;
 const int saved=errno;
 VM27RunWakeJobV34 *job=calloc(1,sizeof(*job));
 if(job) {
  job->slot=slot;
  job->identity=q->expectedPublicIdentity;job->epoch=q->expectedVMEpoch;
  job->generation=q->expectedCPUGeneration;
  job->queue=dispatch_queue_create("VirtualMac.independent27.per-cpu-single-run-wake",DISPATCH_QUEUE_SERIAL);
  if(job->queue)job->source=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,job->queue);
 }
 if(!job || !job->queue || !job->source) {
  if(job){if(job->queue)dispatch_release(job->queue);free(job);}
  atomic_store_explicit(&slot->phase,5,memory_order_release);
  dprintf(2,"[Independent27HV] diagnostic-wake-unavailable phase=5 id=%llu epoch=%llu generation=%llu\n",
   (unsigned long long)q->expectedPublicIdentity,(unsigned long long)q->expectedVMEpoch,
   (unsigned long long)q->expectedCPUGeneration);
  errno=saved;return;
 }
 dispatch_set_context(job->source,job);
 dispatch_source_set_event_handler_f(job->source,VM27RunWakeFiredV34);
 dispatch_source_set_cancel_handler_f(job->source,VM27RunWakeCancelledV34);
 dispatch_source_set_timer(job->source,dispatch_time(DISPATCH_TIME_NOW,INT64_C(60000000000)),DISPATCH_TIME_FOREVER,0);
 atomic_store_explicit(&slot->phase,2,memory_order_release);
 dprintf(2,"[Independent27HV] diagnostic-wake-armed phase=2 delaySeconds=60 id=%llu epoch=%llu generation=%llu\n",
  (unsigned long long)job->identity,(unsigned long long)job->epoch,(unsigned long long)job->generation);
 dispatch_resume(job->source);errno=saved;
}
// Fixed process-lifetime diagnostic identities: no slot reset/reuse and no
// native/VM/CPU pointer retained. CPU operations already enforce real ownership.
// Per stage: first4 + powers8..2^24 (26) + first2 real nonzero line/entry (2).
// Two stages => at most56 new lines/CPU identity;64 slots =>3584/process.
typedef struct {
 _Atomic unsigned published;
 uint64_t identity,epoch,generation;
 _Atomic unsigned counts[4];
} VM27RunProgressSlotV55;
static VM27RunProgressSlotV55 VM27RunProgressSlotsV55[64];
static unsigned VM27RunProgressSampleV55(const VZKernelRunPendingRequestV14 *q,
 unsigned stage,bool nonzero,unsigned *ordinal) {
 VM27RunProgressSlotV55 *slot=NULL;
 for(unsigned i=0;i<64;++i) {
  VM27RunProgressSlotV55 *p=&VM27RunProgressSlotsV55[i];
  if(atomic_load_explicit(&p->published,memory_order_acquire)==2 &&
   p->identity==q->expectedPublicIdentity && p->epoch==q->expectedVMEpoch &&
   p->generation==q->expectedCPUGeneration){slot=p;break;}
 }
 if(!slot)for(unsigned i=0;i<64;++i) {
  VM27RunProgressSlotV55 *p=&VM27RunProgressSlotsV55[i];unsigned expected=0;
  if(atomic_compare_exchange_strong_explicit(&p->published,&expected,1,
   memory_order_acq_rel,memory_order_acquire)) {
   p->identity=q->expectedPublicIdentity;p->epoch=q->expectedVMEpoch;
   p->generation=q->expectedCPUGeneration;
   atomic_store_explicit(&p->published,2,memory_order_release);slot=p;break;
  }
 }
 if(!slot)return 0;
 unsigned n=VM27RunDiagnosticReserveV29(&slot->counts[stage*2],1u<<24);
 unsigned kind=n && (n<=4 || !(n&(n-1)))?1u:0u;
 if(nonzero && VM27RunDiagnosticReserveV29(&slot->counts[stage*2+1],2))kind|=2;
 *ordinal=n;return kind;
}
static _Atomic unsigned VM27RunStepLogCountV29;
static _Atomic unsigned VM27VirtualTimerStateLogsV35;
static _Atomic unsigned VM27VirtualTimerConsumedLogsV35;
// Observe existing local producer values only. Saturate after the final
// selected power of two; no extra context accesses or native calls occur.
static unsigned VM27RunSparseOrdinalV33(void) {
 unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27RunStepLogCountV29,1u<<24);
 return ordinal && (ordinal<=16 || !(ordinal&(ordinal-1)))?ordinal:0;
}
typedef struct {
 // PC1, Rt2, source4, selector8, handler flags16, read value32.
 unsigned known,rt;uint16_t selector;
 uint64_t pc,source,readValue;
 bool handled,write;
} VM27GICLocalDiagnosticV33;
static void VM27GICLogLocalV33(unsigned ordinal,
 const VZKernelRunStepReceiptV7 *step,const VM27GICLocalDiagnosticV33 *local) {
 if(!ordinal)return;
 int saved=errno;
 dprintf(2,"[Independent27HV] internal-local ordinal=%u token=%llu known=0x%x PC=0x%016llx rt=%u selector=0x%04x source=0x%016llx readValue=0x%016llx handled=%u write=%u\n",
  ordinal,(unsigned long long)step->runToken,local->known,
  (unsigned long long)local->pc,local->rt,local->selector,
  (unsigned long long)local->source,(unsigned long long)local->readValue,
  local->handled,local->write);
 errno=saved;
}
// New Life20 exact-source derivative; frozen Run18 remains unchanged.
// Only real RunPostAccessV7 capabilities may reach these native reads/writes.
static bool GICPostFieldV20(PendingRunAccessV14 *a,uint32_t off,bool write,uint64_t *v) {
 bool scalar=(off==0x108 || (off>=8 && off<=0xf8 && !(off&7)));
 bool timer=off==0x3f0 || off==0x438 || off==0x748 || off==0x4100 || off==0x4110 || off==0x6a0 || off==0x6d8 || off==0x430;
 if(!a->post || (!scalar && !timer) || (write && (off==0x4100 || off==0x4110 || off==0x6a0 || off==0x430)) ||
  !PendingBoundaryV14(a) || a->init.cpu->nativeContext>UINTPTR_MAX-off-8 ||
  !VM27CPUSelfMappedRangeV1((const void *)(a->init.cpu->nativeContext+off),8,write,NULL))return false;
 bool ok=write?a->init.writer->writeMemory(a->init.writer->context,
  (void *)(a->init.cpu->nativeContext+off),8,v):a->init.cpu->vm->ops.readMemory(
  a->init.cpu->vm->ops.context,(const void *)(a->init.cpu->nativeContext+off),8,v);
 return ok && PendingBoundaryV14(a);
}
static void GICPoisonV20(VZKernelCPU *cpu) {
 cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
 cpu->registryEntry->published=false;cpu->registryEntry->draining=true;Unlock(&cpu->vm->mutex);
}
static bool GICPostPSTATEV20(PendingRunAccessV14 *a,uint32_t *value) {
 if(!a->post || !PendingBoundaryV14(a) || a->init.cpu->nativeContext>UINTPTR_MAX-0x110-4 ||
  !VM27CPUSelfMappedRangeV1((const void *)(a->init.cpu->nativeContext+0x110),4,false,NULL))return false;
 bool ok=a->init.cpu->vm->ops.readMemory(a->init.cpu->vm->ops.context,
  (const void *)(a->init.cpu->nativeContext+0x110),4,value);
 return ok && PendingBoundaryV14(a);
}
typedef struct {
 PendingRunAccessV14 *access;
 bool syncRequired,syncAttempted,syncInvoked;
 VZKernelStatus syncStatus;
 int32_t syncNativeReturn;
} VM27RunDiagnosticSYSV36;
static bool VM27RunDiagnosticSYSReadV36(void *context,uint32_t offset,size_t bytes,void *out) {
 VM27RunDiagnosticSYSV36 *d=context;
 return PendingReadMappedV14(d->access,offset,bytes,out);
}
static bool VM27RunDiagnosticSYSWriteV36(void *context,uint32_t offset,size_t bytes,const void *value) {
 (void)context;(void)offset;(void)bytes;(void)value;return false;
}
static VZKernelStatus VM27RunDiagnosticSYSSyncV36(void *context,bool *invoked) {
 VM27RunDiagnosticSYSV36 *d=context;*invoked=false;d->syncRequired=true;
 if(d->syncAttempted)return VZ_KERNEL_UNSUPPORTED;
 d->syncAttempted=true;
 if(!PendingBoundaryV14(d->access))return d->syncStatus=d->access->init.boundaryStatus;
 d->syncStatus=PrepareSystemNative8V8(&d->access->init,invoked);
 d->syncInvoked=*invoked;
 if(*invoked)d->syncNativeReturn=d->access->init.lifecycle->nativeReturn;
 if(d->syncStatus==VZ_KERNEL_OK && !PendingBoundaryV14(d->access))
  d->syncStatus=d->access->init.boundaryStatus;
 return d->syncStatus;
}
typedef struct {
 unsigned reason; // 0 read, 1 unknown MMU, 2 unsupported translation, 3 non-EL1, 4 range, 5 VM busy, 6 identity, 7 RAM, 8 self read, 9 post boundary, 10 invalid descriptor, 11 PA size/alignment, 12 walk changed, 13 new-map publication unavailable.
 uint64_t guestAddress,regionGuestAddress,regionBytes,regionFlags;
 uintptr_t hostAddress;
 bool borrowedHost;
 uint8_t bytes[64];
 uint64_t virtualAddress,descriptorAddress[6],descriptorValue[6],chunkGPA[2];
 unsigned walkCount,chunkCount,descriptorLevel[6],actualBytes,tableNumber;
 bool translated;
 uint64_t ramGeneration;bool ramGenerationKnown;
} VM27RunDiagnosticCodeV36;
static void VM27RunDiagnosticRAMReadV37(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t address,size_t bytes,VM27RunDiagnosticCodeV36 *out) {
 out->guestAddress=address;
 if(!bytes || bytes>sizeof(out->bytes) || address>UINT64_MAX-bytes){out->reason=4;return;}
 if(!PendingBoundaryV14(a)){out->reason=9;return;}
 VZKernelCPU *cpu=a->init.cpu;VZKernelVM *vm=cpu->vm;
 for(unsigned attempt=0;attempt<2;++attempt) {
  Lock(&RegistryMutex);Lock(&vm->mutex);
  bool valid=RegisteredVM==vm && vm->live && cpu->live &&
   (vm->cpuHandles || vm->cpuRegistry) && CPURegisteredLockedV5(cpu) &&
   cpu->registryEntry->identityIssued && cpu->registryEntry->published &&
   cpu->registryEntry->creationComplete && !cpu->registryEntry->draining &&
   !cpu->mutationPoisoned && cpu->runPostReturnActive && a->post &&
   cpu->runToken==a->post->token && vm->generation==q->expectedVMEpoch &&
   cpu->generation==q->expectedCPUGeneration && cpu->owner==q->expectedOwnerThread &&
   cpu->registryEntry->publicIdentity==q->expectedPublicIdentity &&
   OutputAllPrivateDisjointLockedV5(vm,out,sizeof(*out));
  bool pending=valid && (vm->ramMapVersion&1);uint64_t generation=vm->ramMapVersion;
  out->reason=valid?7:6;VZKernelRAMV9 *root=NULL;VZKernelRAMSegmentV54 *selected=NULL;unsigned matches=0;
  if(valid && !pending)for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next) {
   if(r->vm!=vm || r->epoch!=vm->generation)continue;
   for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next)
    if(address<g->guestAddress+g->bytes && g->guestAddress<address+bytes){++matches;selected=g;root=r;}
  }
  if(valid && !pending && matches==1 && selected && selected->mapped && !selected->uncertain &&
   (selected->flags&1) && address>=selected->guestAddress && bytes<=selected->bytes &&
   address-selected->guestAddress<=selected->bytes-bytes) {
   uint64_t offset=selected->hostOffset+address-selected->guestAddress;uintptr_t host=(uintptr_t)root->host;
   if(host && offset<=root->bytes && bytes<=root->bytes-offset && offset<=UINTPTR_MAX-host &&
    host+(uintptr_t)offset<=UINTPTR_MAX-bytes) {
    out->hostAddress=host+(uintptr_t)offset;out->regionGuestAddress=selected->guestAddress;
    out->regionBytes=selected->bytes;out->regionFlags=selected->flags;out->borrowedHost=root->borrowedHost;
    // Real self-task copy completes under the same mutex used to publish every
    // interval transaction. No interval pointer survives unlocking this mutex.
    out->reason=VM27CPUSelfReadV1(NULL,(const void *)out->hostAddress,bytes,out->bytes)?0:8;
    if(!out->reason){out->actualBytes=(unsigned)bytes;out->ramGeneration=generation;out->ramGenerationKnown=true;}
   }
  }
  Unlock(&vm->mutex);Unlock(&RegistryMutex);
  if(pending) {
   struct timespec deadline={0};bool complete=false;
   if(!attempt && !clock_gettime(CLOCK_REALTIME,&deadline)) {
    ++deadline.tv_sec;Lock(&vm->mutex);int waitResult=0;
    while(vm->ramMapVersion==generation && (vm->ramMapVersion&1) && !waitResult)
     waitResult=pthread_cond_timedwait(&vm->ramPublication,&vm->mutex,&deadline);
    complete=!waitResult && !(vm->ramMapVersion&1);Unlock(&vm->mutex);
   }
   if(!PendingBoundaryV14(a)){out->reason=9;return;}
   if(complete)continue;
   out->reason=13;return;
  }
  if(!PendingBoundaryV14(a))out->reason=9;return;
 }
 out->reason=13;
}
static bool VM27RAMReadGenerationV54(VM27RunDiagnosticCodeV36 *out,const VM27RunDiagnosticCodeV36 *part) {
 if(!part->ramGenerationKnown || (out->ramGenerationKnown && out->ramGeneration!=part->ramGeneration)) {
  out->reason=12;return false;
 }
 out->ramGeneration=part->ramGeneration;out->ramGenerationKnown=true;return true;
}
static bool VM27RAMReadGenerationStableV54(PendingRunAccessV14 *a,VM27RunDiagnosticCodeV36 *out) {
 VZKernelVM *vm=a->init.cpu->vm;Lock(&RegistryMutex);Lock(&vm->mutex);
 bool same=RegisteredVM==vm && vm->live && out->ramGenerationKnown &&
  !(vm->ramMapVersion&1) && vm->ramMapVersion==out->ramGeneration;
 Unlock(&vm->mutex);Unlock(&RegistryMutex);if(!same)out->reason=12;return same;
}
static bool VM27RunDiagnosticTranslateV37(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t ttbr,uint64_t va,
 bool kernel,VM27RunDiagnosticCodeV36 *out,uint64_t *gpa) {
 // Both exact profiles start at L1. Firmware uses low42-bit VA/36-bit PA;
 // the observed kernel uses high-canonical47-bit VA/40-bit PA via TTBR1.
 // 16KiB L1 block entries are not supported here; L2 blocks are 32MiB.
 const uint64_t addressField=UINT64_C(0x0000ffffffffc000);
 const uint64_t paLimit=UINT64_C(1)<<(kernel?40:36);
 const uint64_t ttbrReserved=kernel?UINT64_C(0x0000ff0000003ffe):UINT64_C(0x0000fff000003ffe);
 uint64_t table=ttbr&addressField;
 bool inRange=kernel?(va>>47)==UINT64_C(0x1ffff):va<(UINT64_C(1)<<42);
 if(!inRange || (ttbr&ttbrReserved) || table>=paLimit) {
  out->reason=11;return false;
 }
 for(unsigned level=1;level<=3;++level) {
  unsigned shift=14+11*(3-level);uint64_t index=(va>>shift)&(level==1 && !kernel?63:2047);
  uint64_t at=table+8*index;VM27RunDiagnosticCodeV36 entry={0};
  if(at>=paLimit || out->walkCount>=6){out->reason=11;return false;}
  VM27RunDiagnosticRAMReadV37(a,q,at,8,&entry);
  if(entry.reason){out->reason=entry.reason;return false;}
  if(!VM27RAMReadGenerationV54(out,&entry))return false;
  uint64_t descriptor=0;memcpy(&descriptor,entry.bytes,8);
  unsigned ordinal=out->walkCount++;
  out->descriptorAddress[ordinal]=at;out->descriptorValue[ordinal]=descriptor;
  out->descriptorLevel[ordinal]=level;
  // Non-LPA2 16KiB table/block/page formats reserve descriptor [13:12].
  // Reject them explicitly rather than silently masking an invalid encoding.
  if(descriptor&UINT64_C(0x3000)){out->reason=10;return false;}
  unsigned type=(unsigned)(descriptor&3);uint64_t output=descriptor&addressField;
  if(output>=paLimit){out->reason=11;return false;}
  if(level<3 && type==3){table=output;continue;}
  if(!((level==2 && type==1) || (level==3 && type==3)) || !(descriptor&(UINT64_C(1)<<10))) {
   out->reason=10;return false;
  }
  uint64_t lowMask=(UINT64_C(1)<<shift)-1;
  if(output&lowMask){out->reason=11;return false;}
  *gpa=output|(va&lowMask);return true;
 }
 out->reason=10;return false;
}
static void VM27RunDiagnosticVirtualReadV37(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t address,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,size_t bytes,bool instruction,VM27RunDiagnosticCodeV36 *out) {
 out->virtualAddress=address;out->guestAddress=0;out->translated=true;
 bool kernel=tcr==UINT64_C(0x000800226511a511);
 out->tableNumber=kernel?1:0;
 // Only the two actual TCR profiles are supported; no tag stripping,
 // guessed identity mapping, big-endian walk or LPA2 interpretation.
 if((!kernel && tcr!=UINT64_C(0x001800616556a516)) || (sctlr&(UINT64_C(1)<<25)) ||
  !bytes || bytes>sizeof(out->bytes) || (instruction && (address&3)) ||
  address>UINT64_MAX-bytes || (!kernel && address>=(UINT64_C(1)<<42)-bytes) ||
  (kernel && (address>>47)!=UINT64_C(0x1ffff))) {out->reason=2;return;}
 size_t done=0;
 for(unsigned page=0;done<bytes && page<2;++page) {
  uint64_t va=address+done,gpa=0;
  if(!VM27RunDiagnosticTranslateV37(a,q,ttbr,va,kernel,out,&gpa))return;
  size_t chunk=0x4000-(size_t)(va&0x3fff);
  if(chunk>bytes-done)chunk=bytes-done;
  VM27RunDiagnosticCodeV36 payload={0};
  VM27RunDiagnosticRAMReadV37(a,q,gpa,chunk,&payload);
  if(payload.reason){out->reason=payload.reason;return;}
  if(!VM27RAMReadGenerationV54(out,&payload))return;
  if(!done) {
   out->guestAddress=gpa;out->hostAddress=payload.hostAddress;
   out->regionGuestAddress=payload.regionGuestAddress;out->regionBytes=payload.regionBytes;
   out->regionFlags=payload.regionFlags;out->borrowedHost=payload.borrowedHost;
  }
  out->chunkGPA[page]=gpa;++out->chunkCount;
  memcpy(out->bytes+done,payload.bytes,chunk);done+=chunk;
 }
 if(done!=bytes){out->reason=4;return;}
 // This is a bounded observation of actual guest tables, not a TLB query.
 // Re-read each observed descriptor once; any change rejects the code bytes.
 for(unsigned i=0;i<out->walkCount;++i) {
  VM27RunDiagnosticCodeV36 entry={0};uint64_t value=0;
  VM27RunDiagnosticRAMReadV37(a,q,out->descriptorAddress[i],8,&entry);
  if(entry.reason){out->reason=entry.reason;return;}
  if(!VM27RAMReadGenerationV54(out,&entry))return;
  memcpy(&value,entry.bytes,8);
  if(value!=out->descriptorValue[i]){out->reason=12;return;}
 }
 if(!VM27RAMReadGenerationStableV54(a,out))return;
 out->actualBytes=(unsigned)bytes;out->reason=0;
}
static bool VM27RunDiagnosticUserTranslateV63(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t ttbr,uint64_t va,
 VM27RunDiagnosticCodeV36 *out,uint64_t *gpa) {
 // Diagnostic EL0 instruction observation only: actual kernel low47/PA40 TTBR0.
 // 16KiB L1 block entries are not supported here; L2 blocks are 32MiB.
 const uint64_t addressField=UINT64_C(0x0000ffffffffc000);
 const uint64_t paLimit=UINT64_C(1)<<40;
 const uint64_t ttbrReserved=UINT64_C(0x0000ff0000003ffe);
 uint64_t table=ttbr&addressField;
 bool inRange=va<(UINT64_C(1)<<47);
 if(!inRange || (ttbr&ttbrReserved) || table>=paLimit) {
  out->reason=11;return false;
 }
 for(unsigned level=1;level<=3;++level) {
  unsigned shift=14+11*(3-level);uint64_t index=(va>>shift)&2047;
  uint64_t at=table+8*index;VM27RunDiagnosticCodeV36 entry={0};
  if(at>=paLimit || out->walkCount>=6){out->reason=11;return false;}
  VM27RunDiagnosticRAMReadV37(a,q,at,8,&entry);
  if(entry.reason){out->reason=entry.reason;return false;}
  if(!VM27RAMReadGenerationV54(out,&entry))return false;
  uint64_t descriptor=0;memcpy(&descriptor,entry.bytes,8);
  unsigned ordinal=out->walkCount++;
  out->descriptorAddress[ordinal]=at;out->descriptorValue[ordinal]=descriptor;
  out->descriptorLevel[ordinal]=level;
  // Non-LPA2 16KiB table/block/page formats reserve descriptor [13:12].
  // Reject them explicitly rather than silently masking an invalid encoding.
  if(descriptor&UINT64_C(0x3000)){out->reason=10;return false;}
  unsigned type=(unsigned)(descriptor&3);uint64_t output=descriptor&addressField;
  if(output>=paLimit){out->reason=11;return false;}
  if(level<3 && type==3){table=output;continue;}
  if(!((level==2 && type==1) || (level==3 && type==3)) || !(descriptor&(UINT64_C(1)<<10))) {
   out->reason=10;return false;
  }
  uint64_t lowMask=(UINT64_C(1)<<shift)-1;
  if(output&lowMask){out->reason=11;return false;}
  *gpa=output|(va&lowMask);return true;
 }
 out->reason=10;return false;
}
static void VM27RunDiagnosticUserReadV63(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t address,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,size_t bytes,bool instruction,VM27RunDiagnosticCodeV36 *out) {
 out->virtualAddress=address;out->guestAddress=0;out->translated=true;
 out->tableNumber=0;
 // Only the exact observed kernel TCR is supported here; no tag stripping,
 // guessed identity mapping, big-endian walk or LPA2 interpretation.
 if((tcr!=UINT64_C(0x000800226511a511)) || (sctlr&(UINT64_C(1)<<25)) ||
  !bytes || bytes>sizeof(out->bytes) || (instruction && (address&3)) ||
  address>UINT64_MAX-bytes || address>=(UINT64_C(1)<<47)-bytes) {out->reason=2;return;}
 size_t done=0;
 for(unsigned page=0;done<bytes && page<2;++page) {
  uint64_t va=address+done,gpa=0;
  if(!VM27RunDiagnosticUserTranslateV63(a,q,ttbr,va,out,&gpa))return;
  size_t chunk=0x4000-(size_t)(va&0x3fff);
  if(chunk>bytes-done)chunk=bytes-done;
  VM27RunDiagnosticCodeV36 payload={0};
  VM27RunDiagnosticRAMReadV37(a,q,gpa,chunk,&payload);
  if(payload.reason){out->reason=payload.reason;return;}
  if(!VM27RAMReadGenerationV54(out,&payload))return;
  if(!done) {
   out->guestAddress=gpa;out->hostAddress=payload.hostAddress;
   out->regionGuestAddress=payload.regionGuestAddress;out->regionBytes=payload.regionBytes;
   out->regionFlags=payload.regionFlags;out->borrowedHost=payload.borrowedHost;
  }
  out->chunkGPA[page]=gpa;++out->chunkCount;
  memcpy(out->bytes+done,payload.bytes,chunk);done+=chunk;
 }
 if(done!=bytes){out->reason=4;return;}
 // This is a bounded observation of actual guest tables, not a TLB query.
 // Re-read each observed descriptor once; any change rejects the code bytes.
 for(unsigned i=0;i<out->walkCount;++i) {
  VM27RunDiagnosticCodeV36 entry={0};uint64_t value=0;
  VM27RunDiagnosticRAMReadV37(a,q,out->descriptorAddress[i],8,&entry);
  if(entry.reason){out->reason=entry.reason;return;}
  if(!VM27RAMReadGenerationV54(out,&entry))return;
  memcpy(&value,entry.bytes,8);
  if(value!=out->descriptorValue[i]){out->reason=12;return;}
 }
 if(!VM27RAMReadGenerationStableV54(a,out))return;
 out->actualBytes=(unsigned)bytes;out->reason=0;
}
static void VM27RunDiagnosticCodeLogV36(const char *label,const VM27RunDiagnosticCodeV36 *code) {
 static const char hex[]="0123456789abcdef";char text[129]={0};
 if(!code->reason)for(unsigned i=0;i<code->actualBytes;++i) {
  text[2*i]=hex[code->bytes[i]>>4];text[2*i+1]=hex[code->bytes[i]&15];
 }
 dprintf(2,"[Independent27HV] diagnostic-wake-code label=%s known=%u reason=%u GPA=0x%016llx HVA=0x%016llx regionGPA=0x%016llx regionBytes=0x%llx flags=0x%llx borrowedHost=%u bytes=%u hex=%s\n",
  label,!code->reason,code->reason,(unsigned long long)code->guestAddress,
  (unsigned long long)code->hostAddress,(unsigned long long)code->regionGuestAddress,
  (unsigned long long)code->regionBytes,(unsigned long long)code->regionFlags,
  code->borrowedHost,code->reason?0u:code->actualBytes,text);
 if(code->translated) {
  dprintf(2,"[Independent27HV] diagnostic-wake-walk label=%s VA=0x%016llx actualTable=%u softwareTableWalkOnly=1 TLBNotObserved=1 chunks=%u GPA0=0x%016llx GPA1=0x%016llx descriptorCount=%u\n",label,
   (unsigned long long)code->virtualAddress,code->tableNumber,code->chunkCount,(unsigned long long)code->chunkGPA[0],
   (unsigned long long)code->chunkGPA[1],code->walkCount);
  for(unsigned i=0;i<code->walkCount;++i)
   dprintf(2,"[Independent27HV] diagnostic-wake-walk-entry label=%s ordinal=%u level=%u GPA=0x%016llx value=0x%016llx\n",label,i,
    code->descriptorLevel[i],(unsigned long long)code->descriptorAddress[i],(unsigned long long)code->descriptorValue[i]);
 }
}
static void VM27RunDiagnosticCPUCodeLogV63(uint64_t identity,const char *label,const VM27RunDiagnosticCodeV36 *code) {
 static const char hex[]="0123456789abcdef";char text[129]={0};
 if(!code->reason)for(unsigned i=0;i<code->actualBytes;++i) {
  text[2*i]=hex[code->bytes[i]>>4];text[2*i+1]=hex[code->bytes[i]&15];
 }
 dprintf(2,"[Independent27HV] diagnostic-wake-code id=%llu label=%s known=%u reason=%u GPA=0x%016llx HVA=0x%016llx regionGPA=0x%016llx regionBytes=0x%llx flags=0x%llx borrowedHost=%u bytes=%u hex=%s\n",
  (unsigned long long)identity,label,!code->reason,code->reason,(unsigned long long)code->guestAddress,
  (unsigned long long)code->hostAddress,(unsigned long long)code->regionGuestAddress,
  (unsigned long long)code->regionBytes,(unsigned long long)code->regionFlags,
  code->borrowedHost,code->reason?0u:code->actualBytes,text);
 if(code->translated) {
  dprintf(2,"[Independent27HV] diagnostic-wake-walk id=%llu label=%s VA=0x%016llx actualTable=%u softwareTableWalkOnly=1 TLBNotObserved=1 chunks=%u GPA0=0x%016llx GPA1=0x%016llx descriptorCount=%u\n",(unsigned long long)identity,label,
   (unsigned long long)code->virtualAddress,code->tableNumber,code->chunkCount,(unsigned long long)code->chunkGPA[0],
   (unsigned long long)code->chunkGPA[1],code->walkCount);
  for(unsigned i=0;i<code->walkCount;++i)
   dprintf(2,"[Independent27HV] diagnostic-wake-walk-entry id=%llu label=%s ordinal=%u level=%u GPA=0x%016llx value=0x%016llx\n",(unsigned long long)identity,label,i,
    code->descriptorLevel[i],(unsigned long long)code->descriptorAddress[i],(unsigned long long)code->descriptorValue[i]);
 }
}
static void VM27RunDiagnosticStringLogV42(const char *label,const VM27RunDiagnosticCodeV36 *value) {
 char preview[65]={0};unsigned length=0;bool terminated=false;
 if(!value->reason)for(;length<value->actualBytes;++length) {
  unsigned char c=value->bytes[length];if(!c){terminated=true;break;}
  preview[length]=c>=32 && c<=126?(char)c:'.';
 }
 dprintf(2,"[Independent27HV] diagnostic-wake-string label=%s known=%u terminatedWithinRead=%u previewBytes=%u preview=%s\n",
  label,!value->reason,terminated,length,preview);
}
static _Atomic bool VM27Raw7FaultSampledV43;
static void VM27Raw7FaultSnapshotV43(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,uint64_t pc,uint32_t pstate) {
 bool expected=false;
 if(!atomic_compare_exchange_strong_explicit(&VM27Raw7FaultSampledV43,&expected,true,
  memory_order_acq_rel,memory_order_acquire))return;
 const int saved=errno;
 // Called only by the actual raw7 producer after its real bank1 sync,
 // before any exception-frame/PC mutation. Diagnostics get local receipts.
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 uint64_t sctlr=0,tcr=0,ttbr1=0;unsigned known=0;
 bool owned=PendingRequestOwnedV14(a.init.cpu,q)==VZ_KERNEL_OK && PendingBoundaryV14(&a);
 if(owned) {
  if(PendingReadMappedV14(&a,0x400,8,&sctlr))known|=1;
  if(PendingReadMappedV14(&a,0x3b0,8,&tcr))known|=2;
  if(PendingReadMappedV14(&a,0x3a8,8,&ttbr1))known|=4;
 }
 VM27RunDiagnosticCodeV36 code={.reason=2,.virtualAddress=pc};
 if(known==7 && (pstate&0xc)==4 && !(pstate&0x10) && !(pc&3) &&
  (sctlr&1) && tcr==UINT64_C(0x000800226511a511))
  VM27RunDiagnosticVirtualReadV37(&a,q,pc,sctlr,tcr,ttbr1,64,true,&code);
 dprintf(2,"[Independent27HV] raw7-fault-snapshot id=%llu epoch=%llu generation=%llu owner=%llu token=%llu owned=%u knownSYS=0x%x actualFaultPC=0x%016llx actualPSTATE=0x%08x SCTLR=0x%016llx TCR=0x%016llx TTBR1=0x%016llx sampledBeforeInjection=1 extraNative8Calls=0 maxPayloadBytes=64\n",
  (unsigned long long)q->expectedPublicIdentity,(unsigned long long)q->expectedVMEpoch,
  (unsigned long long)q->expectedCPUGeneration,(unsigned long long)q->expectedOwnerThread,
  (unsigned long long)post.token,owned,known,(unsigned long long)pc,pstate,
  (unsigned long long)sctlr,(unsigned long long)tcr,(unsigned long long)ttbr1);
 VM27RunDiagnosticCodeLogV36("raw7-faultPC",&code);
 errno=saved;
}
#include "modern_cpu_kernel_reset_snapshot_v58.inc"

// Classification affects diagnostic selection only; the original HVC route
// receives unchanged X0/CPSR/ESR. Separate budgets keep unknown traffic from
// consuming the16 real reset observations (32 new lines/process total).
static _Atomic unsigned VM27ResetRequestLogsV56,VM27UnknownRequestLogsV56;
static void VM27ResetOriginLogV56(const VZKernelRunStepReceiptV7 *step,
 const VZKernelRunPendingRequestV14 *q,uint64_t x0,uint32_t cpsr) {
 const uint32_t function=(uint32_t)x0;
 bool psci=x0==function && ((function&UINT32_C(0xffff0000))==UINT32_C(0x84000000) ||
  (function&UINT32_C(0xffff0000))==UINT32_C(0xc4000000));
 unsigned operation=function&UINT32_C(0xffff);
 bool reset=psci && (operation==9 || operation==18),ordinary=false;
 if(psci)switch(operation) {
  case 0:case 1:case 2:case 3:case 4:case 5:case 6:case 7:case 8:
  case 10:case 11:case 12:case 13:case 14:case 15:case 16:case 17:
  case 19:case 20:ordinary=true;break;
  default:break;
 }
 // The unchanged C1 service below already implements its operations0..6.
 bool knownC1=x0==function && (function&UINT32_C(0xff000000))==UINT32_C(0xc1000000) &&
  (function&UINT32_C(0xffffff))<=6;
 if(!reset && (ordinary || knownC1))return;
 const int saved=errno;
 unsigned ordinal=VM27RunDiagnosticReserveV29(reset?&VM27ResetRequestLogsV56:&VM27UnknownRequestLogsV56,16);
 if(ordinal)dprintf(2,"[Independent27HV] cpu-reset-origin id=%llu epoch=%llu generation=%llu owner=%llu token=%llu class=%s ordinal=%u X0=0x%016llx CPSR=0x%08x ESR=0x%08x resetRequest=%u psciFamily=%u convention64=%u classificationDiagnosticOnly=1 originalHVCResultUnchanged=1\n",
  (unsigned long long)q->expectedPublicIdentity,(unsigned long long)step->vmEpoch,
  (unsigned long long)step->cpuGeneration,
  (unsigned long long)step->ownerThread,(unsigned long long)step->runToken,
  reset?"system-reset":"unknown-nonordinary",ordinal,(unsigned long long)x0,cpsr,
  step->nativeValues.syndrome32,reset,psci,(function&UINT32_C(0x40000000))!=0);
 errno=saved;
}
static _Atomic unsigned VM27HVCDiagnosticLogsV39;
typedef struct {
 unsigned ordinal,known,attemptedWrites,completedWrites,syncCalls;
 uint8_t policy;
 uint64_t readyBefore,activeBefore,dirtyBefore,readyAfter,activeAfter,dirtyAfter;
 uint64_t syncNeededBanks,response,pcBefore,pcAfter;
 int32_t syncNativeReturn;
 bool handled,responseKnown,pcBeforeKnown,pcAfterKnown;
} VM27PACReceiptV39;
static VZKernelStatus VM27PACWriteV39(PendingRunAccessV14 *a,uint32_t offset,
 uint64_t value,VM27PACReceiptV39 *r,bool *mutated) {
 *mutated=true;++r->attemptedWrites;
 if(!PendingWriteMappedV14(a,offset,8,&value))return VZ_KERNEL_CONTEXT_UNREADABLE;
 ++r->completedWrites;return VZ_KERNEL_OK;
}
#include "modern_cpu_production_pac_batch_v14.h"
/* Only the real Production adapter may combine these private key writes.
 * Generic callbacks retain their original per-field sequence. The caller's
 * CPU-operation guard spans the complete HVC. No guest entry or native8 is
 * allowed inside the batch; the real bank sync still precedes it. */
static VZKernelStatus VM27PACKeysV68(PendingRunAccessV14 *a,
 const uint32_t *offsets,const uint64_t *values,unsigned count,
 VM27PACReceiptV39 *r,bool *mutated) {
 if(!VM27ProductionPACBatchEligibleV14(&a->init.cpu->vm->ops,a->init.writer)) {
  for(unsigned i=0;i<count;++i) {
   VZKernelStatus status=VM27PACWriteV39(a,offsets[i],values[i],r,mutated);
   if(status!=VZ_KERNEL_OK)return status;
  }
  return VZ_KERNEL_OK;
 }
 if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
 uint64_t packed=0;
 for(unsigned i=0;i<count;++i)packed|=(uint64_t)offsets[i]<<(16*i);
 VM27PACBatchResultV14 result=VM27ProductionPACBatchWriteV14(
  a->init.cpu->nativeContext,packed,values,count);
 if(result.attempted)*mutated=true;
 r->attemptedWrites+=result.attempted;r->completedWrites+=result.completed;
 if(!result.ok)return VZ_KERNEL_CONTEXT_UNREADABLE;
 return PendingBoundaryV14(a)?VZ_KERNEL_OK:a->init.boundaryStatus;
}
static VZKernelStatus VM27PACBankV39(PendingRunAccessV14 *a,uint64_t mask,
 VM27PACReceiptV39 *r,bool *mutated) {
 uint64_t ready=0,dirty=0,active=0;
 VZKernelCPU *cpu=a->init.cpu;
 const uint64_t forbidden=cpu->vm->nativeHVISA==1?
  UINT64_C(0xdf00000000000000):UINT64_C(0xcf00000000000000);
 if((mask&forbidden) || !GICPostFieldV20(a,0x4110,false,&active))return VZ_KERNEL_UNSUPPORTED;
 if(!(active&mask))return VZ_KERNEL_UNSUPPORTED;
 if(!GICPostFieldV20(a,0x4100,false,&ready))return VZ_KERNEL_CONTEXT_UNREADABLE;
 if(!(ready&mask)) {
  r->syncNeededBanks|=mask;
  // Exact original13 helper78a8: only a genuinely absent ready bank calls
  // native8(NULL), then the real owner/version/post-token is revalidated.
  bool invoked=false;VZKernelStatus status=PrepareSystemNative8V8(&a->init,&invoked);
  if(invoked){++r->syncCalls;r->syncNativeReturn=a->init.lifecycle->nativeReturn;}
  if(status!=VZ_KERNEL_OK)return status;
  if(!PendingBoundaryV14(a))return a->init.boundaryStatus;
 }
 if(!GICPostFieldV20(a,0x748,false,&dirty))return VZ_KERNEL_CONTEXT_UNREADABLE;
 return VM27PACWriteV39(a,0x748,dirty|mask,r,mutated);
}
static VZKernelStatus VM27PACServiceV39(PendingRunAccessV14 *access,uint64_t function,
 VM27PACReceiptV39 *r,bool *mutated) {
 // Original13 EL1 HVC imm0 CPU-service family C1, not modern C6 and not a
 // new native opcode. Every field below already has a typed SYS allowlist.
 r->handled=true;
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 VZKernelStatus status=VZ_KERNEL_OK;uint64_t response=UINT32_MAX;
 if(!PendingReadMappedV14(&a,0x4030,1,&r->policy))status=VZ_KERNEL_CONTEXT_UNREADABLE;
 else r->known|=1;
 uint32_t operation=(uint32_t)function&0xffffff;
 if(status==VZ_KERNEL_OK && (r->policy&0x10) && operation<=6) {
  const uint64_t bank60=UINT64_C(1)<<60,bank61=UINT64_C(1)<<61;
  const uint64_t base=UINT64_C(0xfeedfacefeedfacf);
  uint64_t value=0,mode=0,control=0;
  // Stage actual input operands before any response register is modified.
  if(operation>=2 && operation<=6 &&
   !GICPostFieldV20(&a,operation==5?0x18:0x10,false,&value))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  if(status==VZ_KERNEL_OK && operation==5 && !GICPostFieldV20(&a,0x10,false,&mode))
   status=VZ_KERNEL_CONTEXT_UNREADABLE;
  if(status==VZ_KERNEL_OK && operation==0) {
   status=VM27PACBankV39(&a,bank60,r,mutated);
   if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x7b0,0x11,r,mutated);
   if(status==VZ_KERNEL_OK)status=VM27PACBankV39(&a,bank61,r,mutated);
   const uint32_t offsets[]={0x7c8,0x7d0,0x7e8,0x7f0,0x7d8,0x7e0,0x7f8,0x800,0x7b8,0x7c0};
   const uint8_t additions[]={1,0,3,2,7,6,9,8,11,10};
   for(unsigned i=0;i<10 && status==VZ_KERNEL_OK;++i)
    status=VM27PACWriteV39(&a,offsets[i],base+additions[i],r,mutated);
   if(status==VZ_KERNEL_OK)status=VM27PACBankV39(&a,bank60,r,mutated);
   if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x808,base+5,r,mutated);
   if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x810,base+4,r,mutated);
  } else if(status==VZ_KERNEL_OK && operation==1) {
   // Original query response, not a host-generated or guest feature claim.
   const uint64_t values[]={base,base+6,base+4,base+10};
   for(unsigned i=0;i<4 && status==VZ_KERNEL_OK;++i)
    status=VM27PACWriteV39(&a,0x10+8*i,values[i],r,mutated);
  } else if(status==VZ_KERNEL_OK) {
   status=VM27PACBankV39(&a,(operation==4 || operation==5)?bank60:bank61,r,mutated);
   if(status==VZ_KERNEL_OK && operation==2) {
    const uint32_t offsets[]={0x7d0,0x7c8,0x7e8,0x7f0};
    const uint64_t values[]={value,value+1,value+3,value+2};
    status=VM27PACKeysV68(&a,offsets,values,4,r,mutated);
   } else if(status==VZ_KERNEL_OK && operation==3) {
    const uint32_t offsets[]={0x7e0,0x7d8,0x7f8,0x800};
    const uint64_t values[]={value,value+1,value+3,value+2};
    status=VM27PACKeysV68(&a,offsets,values,4,r,mutated);
   } else if(status==VZ_KERNEL_OK && (operation==4 || operation==5)) {
    const uint32_t offsets[]={0x810,0x808};const uint64_t values[]={value,value+1};
    status=VM27PACKeysV68(&a,offsets,values,2,r,mutated);
    if(status==VZ_KERNEL_OK && operation==5 && mode<=1) {
     if(!PendingReadMappedV14(&a,0x7b0,8,&control))status=VZ_KERNEL_CONTEXT_UNREADABLE;
     else status=VM27PACWriteV39(&a,0x7b0,mode?control|2:control&~UINT64_C(2),r,mutated);
    }
   } else if(status==VZ_KERNEL_OK && operation==6) {
    const uint32_t offsets[]={0x7c0,0x7b8};const uint64_t values[]={value,value+1};
    status=VM27PACKeysV68(&a,offsets,values,2,r,mutated);
   }
  }
  if(status==VZ_KERNEL_OK)response=0;
 }
 // Both real policy rejection and an unsupported C1 operation return the
 // original MOV W8,#-1 value, zero-extended to64. No policy bit is forced.
 if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,8,response,r,mutated);
 if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&a))status=a.init.boundaryStatus;
 if(status==VZ_KERNEL_OK){r->response=response;r->responseKnown=true;}
 else if(r->attemptedWrites)GICPoisonV20(a.init.cpu);
 return status;
}
static void VM27HVCLogBeforeV39(PendingRunAccessV14 *a,VM27PACReceiptV39 *r) {
 const int saved=errno;
 r->ordinal=VM27RunDiagnosticReserveV29(&VM27HVCDiagnosticLogsV39,8);
 if(!r->ordinal)return;
 if(PendingReadMappedV14(a,0x4030,1,&r->policy))r->known|=1;
 if(GICPostFieldV20(a,0x4100,false,&r->readyBefore))r->known|=2;
 if(GICPostFieldV20(a,0x4110,false,&r->activeBefore))r->known|=4;
 if(GICPostFieldV20(a,0x748,false,&r->dirtyBefore))r->known|=8;
 r->pcBeforeKnown=GICPostFieldV20(a,0x108,false,&r->pcBefore);
 errno=saved;
}
static void VM27HVCLogAfterV39(PendingRunAccessV14 *a,VM27PACReceiptV39 *r,
 uint64_t function,uint32_t cpsr,uint32_t esr,VZKernelStatus status) {
 if(!r->ordinal)return;
 const int saved=errno;
 if(GICPostFieldV20(a,0x4100,false,&r->readyAfter))r->known|=16;
 if(GICPostFieldV20(a,0x4110,false,&r->activeAfter))r->known|=32;
 if(GICPostFieldV20(a,0x748,false,&r->dirtyAfter))r->known|=64;
 r->pcAfterKnown=GICPostFieldV20(a,0x108,false,&r->pcAfter);
 dprintf(2,"[Independent27HV] actual-hvc ordinal=%u X0=0x%016llx CPSR=0x%08x ESR=0x%08x known=0x%x policy4030=0x%02x policyPAC=%u readyBefore=0x%016llx activeBefore=0x%016llx dirtyBefore=0x%016llx handledC1=%u status=%u syncNeededBanks=0x%016llx syncCalls=%u syncNativeReturn=0x%08x attemptedWrites=%u completedWrites=%u responseKnown=%u response=0x%016llx readyAfter=0x%016llx activeAfter=0x%016llx dirtyAfter=0x%016llx PCbeforeKnown=%u PCbefore=0x%016llx PCafterKnown=%u PCafter=0x%016llx PCWriteAttempted=0\n",
  r->ordinal,(unsigned long long)function,cpsr,esr,r->known,r->policy,(r->policy&0x10)!=0,
  (unsigned long long)r->readyBefore,(unsigned long long)r->activeBefore,(unsigned long long)r->dirtyBefore,
  r->handled,(unsigned)status,(unsigned long long)r->syncNeededBanks,r->syncCalls,(unsigned)r->syncNativeReturn,
  r->attemptedWrites,r->completedWrites,r->responseKnown,(unsigned long long)r->response,
  (unsigned long long)r->readyAfter,(unsigned long long)r->activeAfter,(unsigned long long)r->dirtyAfter,
  r->pcBeforeKnown,(unsigned long long)r->pcBefore,r->pcAfterKnown,(unsigned long long)r->pcAfter);
 errno=saved;
}
static _Atomic unsigned VM27DisabledAMXLogsV44;
static _Atomic unsigned VM27DisabledAMXEligibilityLogsV45;
static bool VM27TryDisabledAMXConfigUnleasedV54(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,uint64_t pc,uint32_t pstate,
 VM27PACReceiptV39 *writes,bool *mutated,VZKernelStatus *outStatus) {
 const int saved=errno;
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 // This exact native profile forbids bank57. Never activate its backing760,
 // set its dirty bit or claim support for AMX data or arithmetic operations.
 uint64_t forbidden=q->nativeHVISA==1?UINT64_C(0xdf00000000000000):
  UINT64_C(0xcf00000000000000),active=0,sctlr=0,tcr=0,ttbr1=0;
 bool owned=(q->nativeHVISA==1 || q->nativeHVISA==2) &&
  q->validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  PendingRequestOwnedV14(a.init.cpu,q)==VZ_KERNEL_OK && PendingBoundaryV14(&a);
 bool activeKnown=false;
 bool eligible=owned && !(pstate&0x10) && (pstate&0xc)==4 && !(pc&3) &&
  pc<=UINT64_MAX-4 && (forbidden&(UINT64_C(1)<<57)) &&
  (activeKnown=GICPostFieldV20(&a,0x4110,false,&active)) && !(active&forbidden) &&
  PendingReadMappedV14(&a,0x400,8,&sctlr) && (sctlr&1) &&
  PendingReadMappedV14(&a,0x3b0,8,&tcr) && tcr==UINT64_C(0x000800226511a511) &&
  PendingReadMappedV14(&a,0x3a8,8,&ttbr1);
 VM27RunDiagnosticCodeV36 code={.reason=2,.virtualAddress=pc};
 if(eligible)VM27RunDiagnosticVirtualReadV37(&a,q,pc,sctlr,tcr,ttbr1,4,true,&code);
 if(eligible && code.reason) {
  // Unavailable or changed instruction backing is unknown, never a true UND.
  *outStatus=VZ_KERNEL_CONTEXT_UNREADABLE;errno=saved;return true;
 }
 if(!eligible || code.reason || code.actualBytes!=4) {
  unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27DisabledAMXEligibilityLogsV45,8);
  if(ordinal)dprintf(2,"[Independent27HV] raw7-disabled-amx-eligibility ordinal=%u owned=%u profile=%u nativeISA=%u activeKnown=%u active=0x%016llx eligible=%u codeReason=%u codeBytes=%u PC=0x%016llx PSTATE=0x%08x UNDfallback=1\n",
   ordinal,owned,q->validatedKernelProfile,q->nativeHVISA,activeKnown,
   (unsigned long long)active,eligible,code.reason,code.actualBytes,(unsigned long long)pc,pstate);
  errno=saved;return false;
 }
 uint32_t instruction=(uint32_t)code.bytes[0]|((uint32_t)code.bytes[1]<<8)|
  ((uint32_t)code.bytes[2]<<16)|((uint32_t)code.bytes[3]<<24);
 uint32_t operation=instruction&UINT32_C(0xffffffe0);unsigned rt=instruction&31;
 bool write=operation==UINT32_C(0xd51cf180),read=operation==UINT32_C(0xd53cf180);
 if(!write && !read){errno=saved;return false;}
 uint64_t operand=0;bool operandKnown=read || rt==31 ||
  GICPostFieldV20(&a,8+8*rt,false,&operand);
 // The actual iPad kernel boot sequence at7f2880c..20 writes exactly100,
 // with every higher bit zero; its native context code toggles enable63.
 // Admit only zero or that exact disabled boot policy in this read-zero
 // virtual profile. No AMX execution or arbitrary nonzero policy is exposed.
 bool accept=operandKnown && (!write || !operand || operand==UINT64_C(0x100)) && PendingBoundaryV14(&a);
 VZKernelStatus status=VZ_KERNEL_OK;unsigned beforeWrites=writes->completedWrites;
 if(accept && read && rt!=31)status=VM27PACWriteV39(&a,8+8*rt,0,writes,mutated);
 if(accept && status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x108,pc+4,writes,mutated);
 if(accept && status==VZ_KERNEL_OK && !PendingBoundaryV14(&a))status=a.init.boundaryStatus;
 if(accept && status!=VZ_KERNEL_OK)GICPoisonV20(a.init.cpu);
 unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27DisabledAMXLogsV44,8);
 if(ordinal)dprintf(2,"[Independent27HV] raw7-disabled-amx-config ordinal=%u id=%llu epoch=%llu generation=%llu token=%llu actualInstruction=0x%08x selector=S3_4_C15_C1_4 write=%u rt=%u operandKnown=%u operand=0x%016llx active=0x%016llx bank57Forbidden=1 accepted=%u status=%u completedEmulationWrites=%u PCbefore=0x%016llx PCrequested=0x%016llx actualDisabledProfile=1 AMXExecutionSupported=0 UNDfallback=%u\n",
  ordinal,(unsigned long long)q->expectedPublicIdentity,(unsigned long long)q->expectedVMEpoch,
  (unsigned long long)q->expectedCPUGeneration,(unsigned long long)post.token,instruction,
  write,rt,operandKnown,(unsigned long long)operand,(unsigned long long)active,accept,
  (unsigned)status,writes->completedWrites-beforeWrites,(unsigned long long)pc,
  (unsigned long long)(accept?pc+4:pc),!accept);
 if(accept)*outStatus=status;
 errno=saved;return accept;
}
static bool VM27TryDisabledAMXConfigV44(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,uint64_t pc,uint32_t pstate,
 VM27PACReceiptV39 *writes,bool *mutated,VZKernelStatus *outStatus) {
 const int saved=errno;VZKernelVM *vm=access->init.cpu->vm;
 if(!RAMCodeLeaseBeginV54(vm)){*outStatus=VZ_KERNEL_CONTEXT_UNREADABLE;errno=saved;return true;}
 bool accepted=VM27TryDisabledAMXConfigUnleasedV54(access,q,pc,pstate,writes,mutated,outStatus);
 RAMCodeLeaseEndV54(vm);errno=saved;return accepted;
}
static _Atomic unsigned VM27UndefinedLogsV40;
static VZKernelStatus VM27InjectUndefinedV40(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,bool *mutated,bool actualRaw7) {
 // Original13 raw7 table target71f0 calls77e4 and resumes native9. It
 // injects a real undefined exception, not a decoded public raw7 exit.
 const int saved=errno;
 unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27UndefinedLogsV40,8),known=0;
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 VM27PACReceiptV39 writes={0};uint64_t pc=0,vbar=0,vector=0;
 uint32_t pstate=0,newPstate=0;
 VZKernelStatus status=VZ_KERNEL_OK;
 if(GICPostFieldV20(&a,0x108,false,&pc))known|=1;else status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK) {
  if(GICPostPSTATEV20(&a,&pstate))known|=2;else status=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 // The original asserts for AArch32. Reject before mutation instead of
 // manufacturing an AArch64 exception frame for an unsupported state.
 if(status==VZ_KERNEL_OK && (pstate&0x10))status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK)status=VM27PACBankV39(&a,1,&writes,mutated);
 if(status==VZ_KERNEL_OK && actualRaw7 && VM27TryDisabledAMXConfigV44(&a,q,pc,pstate,&writes,mutated,&status)) {
  errno=saved;return status;
 }
 // Keep the existing single64-byte sample for the first genuinely unhandled
 // raw7, rather than consuming it on a successfully emulated disabled config.
 if(status==VZ_KERNEL_OK && actualRaw7)VM27Raw7FaultSnapshotV43(&a,q,pc,pstate);
 if(status==VZ_KERNEL_OK) {
  if(PendingReadMappedV14(&a,0x3e0,8,&vbar))known|=4;else status=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 if(status==VZ_KERNEL_OK) {
  unsigned mode=pstate&31;uint64_t offset=mode>3?((mode&1)?0x200:0):0x400;
  if(vbar>UINT64_MAX-offset)status=VZ_KERNEL_BAD_ARGUMENT;
  else {vector=vbar+offset;newPstate=(pstate&~UINT32_C(31))|UINT32_C(0x3c5);}
 }
 if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x3b8,pc,&writes,mutated);
 if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x3c8,UINT64_C(0x02000000),&writes,mutated);
 if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x410,pstate,&writes,mutated);
 if(status==VZ_KERNEL_OK)status=VM27PACWriteV39(&a,0x108,vector,&writes,mutated);
 if(status==VZ_KERNEL_OK) {
  *mutated=true;++writes.attemptedWrites;
  if(!PendingWriteMappedV14(&a,0x110,4,&newPstate))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else ++writes.completedWrites;
 }
 if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&a))status=a.init.boundaryStatus;
 if(status!=VZ_KERNEL_OK && writes.attemptedWrites)GICPoisonV20(a.init.cpu);
 if(ordinal) {
  uint64_t actualELR=0,actualSPSR=0,actualESR=0,actualPC=0;uint32_t actualPstate=0;
  if(PendingReadMappedV14(&a,0x3b8,8,&actualELR))known|=8;
  if(PendingReadMappedV14(&a,0x410,8,&actualSPSR))known|=16;
  if(PendingReadMappedV14(&a,0x3c8,8,&actualESR))known|=32;
  if(GICPostFieldV20(&a,0x108,false,&actualPC))known|=64;
  if(GICPostPSTATEV20(&a,&actualPstate))known|=128;
  dprintf(2,"[Independent27HV] raw7-undefined ordinal=%u status=%u known=0x%x PCbefore=0x%016llx PSTATEbefore=0x%08x VBAR=0x%016llx vectorRequested=0x%016llx PSTATErequested=0x%08x syncNeededBanks=0x%016llx syncCalls=%u syncNativeReturn=0x%08x attemptedWrites=%u completedWrites=%u actualELR=0x%016llx actualSPSR=0x%016llx actualESR=0x%016llx actualPC=0x%016llx actualPSTATE=0x%08x realInjectionCommitted=%u publicExitProduced=0 PCPlus4=0\n",
   ordinal,(unsigned)status,known,(unsigned long long)pc,pstate,(unsigned long long)vbar,
   (unsigned long long)vector,newPstate,(unsigned long long)writes.syncNeededBanks,writes.syncCalls,
   (unsigned)writes.syncNativeReturn,writes.attemptedWrites,writes.completedWrites,
   (unsigned long long)actualELR,(unsigned long long)actualSPSR,(unsigned long long)actualESR,
   (unsigned long long)actualPC,actualPstate,status==VZ_KERNEL_OK);
 }
 errno=saved;return status;
}
#include "modern_cpu_kernel_guest_msgbuf_v65.inc"
static void VM27RunWakePostSnapshotV34(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,const VZKernelRunStepReceiptV7 *step) {
 VM27RunWakeSlotV63 *slot=VM27RunWakeSlotForV63(q,false);if(!slot)return;
 unsigned phase=atomic_load_explicit(&slot->phase,memory_order_acquire);
 if((phase!=3 && phase!=4) || q->expectedPublicIdentity!=slot->identity ||
  step->vmEpoch!=slot->epoch || step->cpuGeneration!=slot->generation)return;
 bool expected=false;
 if(!atomic_compare_exchange_strong_explicit(&slot->sampled,&expected,true,
  memory_order_acq_rel,memory_order_acquire))return;
 const int saved=errno;
 // Keep diagnostic read results separate from the real Run receipt/status.
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 diagnostic=*access;diagnostic.init.lifecycle=&lifecycle;diagnostic.post=&post;
 uint64_t pc=0;uint32_t pstate=0;unsigned known=0;
 if(GICPostFieldV20(&diagnostic,0x108,false,&pc))known|=1;
 if(GICPostPSTATEV20(&diagnostic,&pstate))known|=2;
 bool resultKnown=phase==4;int32_t wakeResult=resultKnown?slot->result:0;
 dprintf(2,"[Independent27HV] diagnostic-wake-post phase=%u requestResultKnown=%u requestStatus=0x%08x id=%llu epoch=%llu generation=%llu token=%llu owner=%llu actualNativeReturn=0x%08x raw=0x%x known=0x%x PC=0x%016llx PSTATE=0x%08x actualRunReturned=1\n",
  phase,resultKnown,(unsigned)wakeResult,(unsigned long long)q->expectedPublicIdentity,
  (unsigned long long)step->vmEpoch,(unsigned long long)step->cpuGeneration,
  (unsigned long long)step->runToken,(unsigned long long)step->ownerThread,
  (unsigned)step->lifecycle.nativeReturn,step->nativeValues.rawReason,known,
  (unsigned long long)pc,pstate);
 // All reads below retain the actual owner's original post-return lease.
 // Local lifecycle/receipt copies isolate any lazy SYS bank synchronization
 // from the enclosing native9 receipt and the real Run status.
 const unsigned registers[]={0,1,2,3,4,5,6,7,19,20,21,22,23,24,25,26,27,28,29,30};
 uint64_t gpr[20]={0};unsigned gprKnown=0;
 for(unsigned i=0;i<20;++i)
  if(GICPostFieldV20(&diagnostic,8+8*registers[i],false,&gpr[i]))gprKnown|=1u<<i;
 dprintf(2,"[Independent27HV] diagnostic-wake-gpr id=%llu known=0x%05x x0=%016llx x1=%016llx x2=%016llx x3=%016llx x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",(unsigned long long)q->expectedPublicIdentity,gprKnown,
  (unsigned long long)gpr[0],(unsigned long long)gpr[1],(unsigned long long)gpr[2],(unsigned long long)gpr[3],
  (unsigned long long)gpr[4],(unsigned long long)gpr[5],(unsigned long long)gpr[6],(unsigned long long)gpr[7]);
 dprintf(2,"[Independent27HV] diagnostic-wake-gpr id=%llu known=0x%05x x19=%016llx x20=%016llx x21=%016llx x22=%016llx x23=%016llx x24=%016llx x25=%016llx x26=%016llx x27=%016llx x28=%016llx FP=%016llx LR=%016llx\n",(unsigned long long)q->expectedPublicIdentity,gprKnown,
  (unsigned long long)gpr[8],(unsigned long long)gpr[9],(unsigned long long)gpr[10],(unsigned long long)gpr[11],
  (unsigned long long)gpr[12],(unsigned long long)gpr[13],(unsigned long long)gpr[14],(unsigned long long)gpr[15],
  (unsigned long long)gpr[16],(unsigned long long)gpr[17],(unsigned long long)gpr[18],(unsigned long long)gpr[19]);
 const uint32_t identifiers[]={0xc208,0xe208,0xc080,0xc102,0xc100,0xc101};
 uint64_t sys[6]={0};unsigned sysKnown=0;VZKernelStatus sysStatus[6];
 VM27RunDiagnosticSYSV36 sysAccess={.access=&diagnostic,.syncStatus=VZ_KERNEL_OK};
 VZKernelInitAccess sysPort={&sysAccess,VM27RunDiagnosticSYSReadV36,VM27RunDiagnosticSYSWriteV36};
 VZKernelSysFeatureCache featureCache={0};
 for(unsigned i=0;i<6;++i) {
  VZKernelSysRequest request={1,q->validatedKernelProfile,q->expectedOwnerThread,
   q->expectedCPUGeneration,q->expectedReturnedSlotWord,q->nativeHVISA,VZ_KERNEL_SYS_READ,identifiers[i],0};
  VZKernelSysReceipt receipt={0};
  sysStatus[i]=PendingRequestOwnedV14(diagnostic.init.cpu,q);
  if(sysStatus[i]==VZ_KERNEL_OK && PendingBoundaryV14(&diagnostic))
   sysStatus[i]=VZKernelSysApplyVerifiedRouteV3(&request,&sysPort,&featureCache,&sys[i],&receipt,VM27RunDiagnosticSYSSyncV36);
  else if(sysStatus[i]==VZ_KERNEL_OK)sysStatus[i]=diagnostic.init.boundaryStatus;
  if(sysStatus[i]==VZ_KERNEL_OK && !PendingBoundaryV14(&diagnostic))sysStatus[i]=diagnostic.init.boundaryStatus;
  if(sysStatus[i]==VZ_KERNEL_OK)sysKnown|=1u<<i;
 }
 bool el1=(known&2) && (pstate&0xc)==4;
 bool el0=(known&2) && (pstate&0x1f)==0;
 bool mmuKnown=(el1 || el0) && (sysKnown&4);bool mmuOn=mmuKnown && (sys[2]&1);
 unsigned spIndex=pstate&1;bool spKnown=el1 && (sysKnown&(1u<<spIndex));
 dprintf(2,"[Independent27HV] diagnostic-wake-sys id=%llu known=0x%x SP0=%016llx SP1=%016llx SCTLR=%016llx TCR=%016llx TTBR0=%016llx TTBR1=%016llx statuses=%u,%u,%u,%u,%u,%u syncRequired=%u syncAttempted=%u syncInvoked=%u syncStatus=%u syncNativeReturn=0x%08x EL1=%u EL0=%u MMUknown=%u MMUon=%u SPknown=%u SP=%016llx originalRunReceiptPreserved=1\n",
  (unsigned long long)q->expectedPublicIdentity,sysKnown,(unsigned long long)sys[0],(unsigned long long)sys[1],(unsigned long long)sys[2],
  (unsigned long long)sys[3],(unsigned long long)sys[4],(unsigned long long)sys[5],
  (unsigned)sysStatus[0],(unsigned)sysStatus[1],(unsigned)sysStatus[2],(unsigned)sysStatus[3],(unsigned)sysStatus[4],(unsigned)sysStatus[5],
  sysAccess.syncRequired,sysAccess.syncAttempted,sysAccess.syncInvoked,(unsigned)sysAccess.syncStatus,
  (unsigned)sysAccess.syncNativeReturn,el1,el0,mmuKnown,mmuOn,spKnown,(unsigned long long)(spKnown?sys[spIndex]:0));
 // Keep the original firmware128-byte budget unchanged. The exact observed
 // kernel wake sample is PC32, precedingPC32 and actual x19 data64.
 // Together with first-raw7 faultPC64 the total remains192. No x2/LR/x27/x28 read.
 bool kernelProfile=el1 && mmuOn && (sysKnown&0x28)==0x28 && sys[3]==UINT64_C(0x000800226511a511);
 size_t codeBytes=(kernelProfile || el0)?32:64;
 VM27RunDiagnosticCodeV36 codePC={.reason=1,.guestAddress=pc},codeBefore={.reason=1};
 VM27RunDiagnosticCodeV36 stringX19={.reason=2,.virtualAddress=gpr[8]};
 bool pcKnown=(known&1) && !(pc&3);
 bool beforeKnown=pcKnown && pc>=codeBytes;uint64_t before=beforeKnown?pc-codeBytes:0;
 codeBefore.guestAddress=before;
 if(el0 && mmuOn && (sysKnown&0x1c)==0x1c && sys[3]==UINT64_C(0x000800226511a511)) {
  if(pcKnown)VM27RunDiagnosticUserReadV63(&diagnostic,q,pc,sys[2],sys[3],sys[4],codeBytes,true,&codePC);
  if(beforeKnown)VM27RunDiagnosticUserReadV63(&diagnostic,q,before,sys[2],sys[3],sys[4],codeBytes,true,&codeBefore);
 }
 else if(!el1){codePC.reason=3;codeBefore.reason=3;}
 else if(mmuOn) {
  codePC.reason=2;codeBefore.reason=2;
  unsigned required=kernelProfile?0x2c:0x1c;
  if((sysKnown&required)==required) {
   uint64_t ttbr=sys[kernelProfile?5:4];
   if(pcKnown)VM27RunDiagnosticVirtualReadV37(&diagnostic,q,pc,sys[2],sys[3],ttbr,codeBytes,true,&codePC);
   if(beforeKnown)VM27RunDiagnosticVirtualReadV37(&diagnostic,q,before,sys[2],sys[3],ttbr,codeBytes,true,&codeBefore);
   if(kernelProfile && (gprKnown&(1u<<8)))
    VM27RunDiagnosticVirtualReadV37(&diagnostic,q,gpr[8],sys[2],sys[3],ttbr,64,false,&stringX19);
  }
 }
 else if(mmuKnown) {
  if(pcKnown)VM27RunDiagnosticRAMReadV37(&diagnostic,q,pc,codeBytes,&codePC);
  if(beforeKnown)VM27RunDiagnosticRAMReadV37(&diagnostic,q,before,codeBytes,&codeBefore);
 }
 if(kernelProfile && !codePC.reason && codePC.translated && codePC.tableNumber==1 &&
  codePC.ramGenerationKnown && (codePC.regionFlags&5)==5 && codePC.regionBytes &&
  codePC.regionBytes<=UINT64_C(67108864)) {
  bool claim=false;
  if(atomic_compare_exchange_strong_explicit(&VM27KernelInspectionClaimedV63,&claim,true,memory_order_acq_rel,memory_order_acquire))
   VM27GuestMsgbufReadV59(&diagnostic,q,pc,sys[2],sys[3],sys[5],&codePC);
 }
 VM27RunDiagnosticCPUCodeLogV63(q->expectedPublicIdentity,"PC",&codePC);VM27RunDiagnosticCPUCodeLogV63(q->expectedPublicIdentity,"PC-before",&codeBefore);
 if(kernelProfile) {
  VM27RunDiagnosticCPUCodeLogV63(q->expectedPublicIdentity,"x19-string",&stringX19);VM27RunDiagnosticStringLogV42("x19",&stringX19);
 }
 errno=saved;
}
static VZKernelStatus GICTimerTrapV20(VZKernelCPUGICOwnerV18 *o,PendingRunAccessV14 *a,
 uint16_t selector,bool write,uint64_t source,uint64_t *result,bool *mutated) {
 VZKernelPhysicalTimerReceiptV19 timer={0};VZKernelStatus s;
 // Timer19 reports any real native8 in its own receipt. Its shared lifecycle
 // assignment must not replace the actual enclosing native9 producer facts.
 bool runNativeInvoked=a->init.lifecycle->nativeInvoked;
 VZKernelHVReturn runNativeReturn=a->init.lifecycle->nativeReturn;
 if(selector==0xdf00 || selector==0xdf01) {
  if(write)return VZ_KERNEL_UNSUPPORTED;
  s=PhysicalTimerPostCounterV19(o->timer,a,selector,result,&timer);
 }else s=PhysicalTimerPostAccessV19(o->timer,a,write?VZ_KERNEL_PHYSICAL_TIMER_WRITE_V19:
  VZ_KERNEL_PHYSICAL_TIMER_READ_V19,selector,write?source:0,write?NULL:result,&timer);
 a->init.lifecycle->nativeInvoked=runNativeInvoked;
 a->init.lifecycle->nativeReturn=runNativeReturn;
 *mutated=timer.attemptedWrites || timer.irqRouteAttempted || timer.deadlineAttempted;
 return s;
}
static VZKernelStatus GICWFxPendingV30(void *context,bool *pending,uint64_t *delay) {
 (void)delay;
 VZKernelCPUGICOwnerV18 *o=context;
 if(atomic_load_explicit(&o->exitRequested,memory_order_acquire)){*pending=true;return VZ_KERNEL_OK;}
 return VM27GICHasWakePendingV30(o->engine,&o->identity,pending);
}
static VZKernelStatus GICHandlePostV20(VZKernelCPUGICOwnerV18 *o,PendingRunAccessV14 *a,
 VZKernelRunStepReceiptV7 *step,bool *resume,bool *stateMutation,
 VM27GICLocalDiagnosticV33 *local) {
 if(!o)return VZ_KERNEL_UNSUPPORTED;
 const uint32_t esr=step->nativeValues.syndrome32,ec=esr>>26;
 if(ec==1) {
  // The original modern predicate means an actual GIC was created/attached.
  // This registered, retained owner is that predicate in the independent GIC.
  if(o->draining || !o->engine || !(esr&(1u<<25)))return VZ_KERNEL_UNSUPPORTED;
  uint64_t pc=0;
  if(!GICPostFieldV20(a,0x108,false,&pc))return VZ_KERNEL_CONTEXT_UNREADABLE;
  local->pc=pc;local->known|=1;
  if(pc>UINT64_MAX-4)return VZ_KERNEL_BAD_ARGUMENT;
  pc+=4;*stateMutation=true;
  if(!GICPostFieldV20(a,0x108,true,&pc)){GICPoisonV20(a->init.cpu);return VZ_KERNEL_CONTEXT_UNREADABLE;}
  VZKernelStatus status=VM27WFxArmV30(&o->wfx,GICWFxPendingV30,o);
  if(status==VZ_KERNEL_OK && !PendingBoundaryV14(a))status=a->init.boundaryStatus;
  if(status!=VZ_KERNEL_OK){GICPoisonV20(a->init.cpu);return status;}
  *resume=true;return VZ_KERNEL_OK;
 }
 if(ec!=0x18 && ec!=0x24)return VZ_KERNEL_UNSUPPORTED;
 uint32_t rt=ec==0x18?(esr>>5)&31:(esr>>16)&31;
 local->rt=rt;local->known|=2;
 uint64_t pc=0,source=0;
 if(!GICPostFieldV20(a,0x108,false,&pc) || (rt!=31 && !GICPostFieldV20(a,8+8*rt,false,&source)))
  return VZ_KERNEL_CONTEXT_UNREADABLE;
 local->pc=pc;local->source=source;local->known|=1|4;
 if(pc>UINT64_MAX-4)return VZ_KERNEL_BAD_ARGUMENT;
 VM27GICTrapResultV1 trap={0};VZKernelStatus s;bool mutated=false;
 uint16_t selector=(uint16_t)((((esr>>20)&3)<<14)|(((esr>>14)&7)<<11)|
  (((esr>>10)&15)<<7)|(((esr>>1)&15)<<3)|((esr>>17)&7));
 if(ec==0x18){local->selector=selector;local->known|=8;}
 if(ec==0x18 && (esr&(1u<<25)) && (selector==0xdf11 || selector==0xdf12 || selector==0xdf00 || selector==0xdf01)) {
  trap=(VM27GICTrapResultV1){.write=(esr&1)==0,.is64Bit=true,.registerIndex=rt,.bytes=8};
  s=GICTimerTrapV20(o,a,selector,trap.write,rt==31?0:source,&trap.readValue,&mutated);
  trap.handled=s==VZ_KERNEL_OK;trap.controllerStateCommitted=mutated;
 } else if(ec==0x18)s=VM27GICHandleSystemV1(o->engine,&o->identity,esr,source,&trap);
 else s=VM27GICHandleAbortV1(o->engine,&o->identity,esr,step->nativeValues.physicalAddress,source,&trap);
 if(s==VZ_KERNEL_OK) {
  local->handled=trap.handled;local->write=trap.write;local->known|=16;
  if(trap.handled && !trap.write){local->readValue=trap.readValue;local->known|=32;}
 }
 mutated=mutated || trap.controllerStateCommitted;
 if(s==VZ_KERNEL_OK && !PendingBoundaryV14(a))s=a->init.boundaryStatus;
 if(s==VZ_KERNEL_OK && trap.handled) {
  if(!trap.write && trap.registerIndex!=31) {
   mutated=true;if(!GICPostFieldV20(a,8+8*trap.registerIndex,true,&trap.readValue))s=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
  if(s==VZ_KERNEL_OK){pc+=4;mutated=true;if(!GICPostFieldV20(a,0x108,true,&pc))s=VZ_KERNEL_CONTEXT_UNREADABLE;}
  if(s==VZ_KERNEL_OK)*resume=true;
 }
 if(s!=VZ_KERNEL_OK && mutated)GICPoisonV20(a->init.cpu);
 *stateMutation=mutated;
 return s;
}

static _Atomic unsigned VM27EncodedExitLogsV47;
static bool VM27EncodedExitFieldV47(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint32_t *out) {
 // Exact original13 EC3f/raw8 source at71d0: native4010 is encoded SYS/SMC
 // metadata, not the actual native400c ESR or a guessed guest instruction.
 VZKernelCPU *cpu=a->init.cpu;
 if(!a->post || PendingRequestOwnedV14(cpu,q)!=VZ_KERNEL_OK || !PendingBoundaryV14(a) ||
  cpu->nativeContext>UINTPTR_MAX-0x4010-4 ||
  !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+0x4010),4,false,NULL))return false;
 bool ok=cpu->vm->ops.readMemory(cpu->vm->ops.context,
  (const void *)(cpu->nativeContext+0x4010),4,out);
 return ok && PendingBoundaryV14(a);
}
static VZKernelStatus VM27HandleEncodedExitV47(VZKernelCPUGICOwnerV18 *gic,
 PendingRunAccessV14 *access,const VZKernelRunPendingRequestV14 *q,
 VZKernelRunStepReceiptV7 *step,VZKernelRunPublicReceiptV20 *publication,
 bool *resume,VM27GICLocalDiagnosticV33 *local) {
 const int saved=errno;unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27EncodedExitLogsV47,8);
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 uint32_t field=0,decoded=step->nativeValues.syndrome32;uint8_t policy=0;
 unsigned route=0;bool fieldKnown=false,policyKnown=false,decodedKnown=false;
 uint64_t pc=0;bool pcKnown=false;unsigned writes=0;
 VZKernelStatus status=VZ_KERNEL_OK;
 if(step->nativeValues.rawReason!=8 || (step->nativeValues.syndrome32>>26)!=0x3f ||
  !step->postReturnIdentityValidated || step->nativeValues.knownFields!=VZ_CPU_EXIT_ALL_KNOWN_V1)
  status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK) {
  fieldKnown=VM27EncodedExitFieldV47(&a,q,&field);
  if(!fieldKnown)status=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 bool privatePAC=fieldKnown && (field&UINT32_C(0x00302c00))==UINT32_C(0x00302c00);
 bool specialID=fieldKnown && (field&UINT32_C(0x003ffc1e))==UINT32_C(0x003e4000);
 if(status==VZ_KERNEL_OK && (privatePAC || specialID)) {
  policyKnown=PendingReadMappedV14(&a,0x4030,1,&policy);
  if(!policyKnown)status=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 // Actual original13 policy is bit4, mask10 (not mask4).
 bool pacPolicy=policyKnown && (policy&UINT8_C(0x10));
 // The native context path80aa6a8/6c4 reads this exact status and tests
 // zero for no active AMX context. The independent profile forbids bank57,
 // so its inactive virtual state reads zero without activating that bank.
 bool amxStateRead=fieldKnown && (field&UINT32_C(0xfffffc1f))==UINT32_C(0x00373c03);
 uint64_t amxActive=0,forbidden=q->nativeHVISA==1?
  UINT64_C(0xdf00000000000000):UINT64_C(0xcf00000000000000);
 bool amxActiveKnown=false;
 bool disabledAMX=status==VZ_KERNEL_OK && amxStateRead &&
  (q->nativeHVISA==1 || q->nativeHVISA==2) &&
  q->validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  PendingRequestOwnedV14(a.init.cpu,q)==VZ_KERNEL_OK && PendingBoundaryV14(&a) &&
  (forbidden&(UINT64_C(1)<<57)) &&
  (amxActiveKnown=GICPostFieldV20(&a,0x4110,false,&amxActive)) && !(amxActive&forbidden);
 if(status==VZ_KERNEL_OK && privatePAC && !disabledAMX) {
  if(pacPolicy) {
   route=1;status=VM27InjectUndefinedV40(&a,q,&publication->runStateMutationAttempted,false);
   if(status==VZ_KERNEL_OK)*resume=true;
  }else {route=2;decodedKnown=true;}
 }else if(status==VZ_KERNEL_OK && (field&UINT32_C(0x01ff0000))==UINT32_C(0x01c00000)) {
  route=3;decoded=UINT32_C(0x5e000000)|(field&UINT32_C(0xffff));decodedKnown=true;
 }else if(status==VZ_KERNEL_OK && ((specialID && pacPolicy) || disabledAMX)) {
  route=disabledAMX?6:4;unsigned rt=(field>>5)&31;uint32_t pstate=0;
  pcKnown=GICPostFieldV20(&a,0x108,false,&pc);
  if(!pcKnown || !GICPostPSTATEV20(&a,&pstate))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else if((pstate&0x10) || (disabledAMX && (pstate&0xc)!=4) || pc>UINT64_MAX-4)status=VZ_KERNEL_UNSUPPORTED;
  if(status==VZ_KERNEL_OK && rt!=31) {
   uint64_t value=disabledAMX?0:UINT64_C(0x00980200);publication->runStateMutationAttempted=true;++writes;
   if(!GICPostFieldV20(&a,8+8*rt,true,&value))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
  if(status==VZ_KERNEL_OK) {
   uint64_t next=pc+4;publication->runStateMutationAttempted=true;++writes;
   if(!GICPostFieldV20(&a,0x108,true,&next))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  }
  if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&a))status=a.init.boundaryStatus;
  if(status!=VZ_KERNEL_OK && writes)GICPoisonV20(a.init.cpu);
  if(status==VZ_KERNEL_OK)*resume=true;
 }else if(status==VZ_KERNEL_OK) {
  route=5;decoded=UINT32_C(0x62000000)|(field&UINT32_C(0x01ffffff));decodedKnown=true;
 }
 if(status==VZ_KERNEL_OK && decodedKnown) {
  // Only the local decoded view reaches existing real GIC handlers. Preserve
  // original raw8/native ESR and the enclosing native9 producer receipt.
  if(gic && (decoded>>26)==0x18) {
   VZKernelRunStepReceiptV7 decodedStep=*step;decodedStep.nativeValues.syndrome32=decoded;
   VZKernelStatus handled=GICHandlePostV20(gic,&a,&decodedStep,resume,
    &publication->runStateMutationAttempted,local);
   if(handled!=VZ_KERNEL_UNSUPPORTED || a.init.cpu->mutationPoisoned)status=handled;
  }
  if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&a))status=a.init.boundaryStatus;
  if(status==VZ_KERNEL_OK && !*resume) {
   VZCPUDecodedPublicExceptionV1 value={1,0,decoded,
    step->nativeValues.virtualAddress,step->nativeValues.physicalAddress};
   step->reduction=(VZCPUExitReductionV1){VZ_CPU_EXIT_REDUCER_SCHEMA_V1,
    VZ_CPU_EXIT_DECODED_EXCEPTION_V1,1,8,value};
   step->reductionValid=true;step->publicExceptionProduced=true;
   publication->publicExit=value;publication->publicExitProduced=true;
  }
 }
 if(ordinal)dprintf(2,"[Independent27HV] raw8-encoded-exit ordinal=%u token=%llu originalRaw=%u originalESR=0x%08x field4010Known=%u actualField4010=0x%08x policyKnown=%u policy4030=0x%02x PACPolicyBit4Mask10=%u route=%u decodedKnown=%u decodedESR=0x%08x status=%u resume=%u publicProduced=%u PCKnown=%u PCbefore=0x%016llx actualStateWriteAttempts=%u disabledAMXStateRead0=%u AMXActiveKnown=%u AMXActive=0x%016llx originalNativeReceiptPreserved=1\n",
  ordinal,(unsigned long long)step->runToken,step->nativeValues.rawReason,
  step->nativeValues.syndrome32,fieldKnown,field,policyKnown,policy,pacPolicy,route,decodedKnown,
  decoded,(unsigned)status,*resume,publication->publicExitProduced,pcKnown,(unsigned long long)pc,writes,
  disabledAMX && status==VZ_KERNEL_OK && *resume,amxActiveKnown,(unsigned long long)amxActive);
 errno=saved;return status;
}

// Preserves frozen Pending14 entry/return CONTROL0 order, including native9 error cleanup.
static VZKernelStatus GICRunActualStepV20(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,const VZKernelInitWriter *writer,
 VZKernelRunPublicReceiptV20 *publicOut,VZKernelCPUGICOwnerV18 *gic,bool *resume) {
 if(!cpu || !input || !writer || !publicOut)return VZ_KERNEL_BAD_ARGUMENT;
 const unsigned diagnosticOrdinal=VM27RunSparseOrdinalV33();
 VM27GICLocalDiagnosticV33 diagnosticLocal={0};
 VZKernelStatus status=BeginCPUOperation(cpu);
 if(status!=VZ_KERNEL_OK){if(status!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return status;}
 const void *p[]={input,writer,publicOut};const size_t n[]={sizeof(*input),sizeof(*writer),sizeof(*publicOut)};
 if(!PendingRangesV14(cpu,p,n,3)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelRunPendingRequestV14 q=*input;VZKernelInitWriter ownWriter=*writer;
 VZKernelRunPublicReceiptV20 publicReceipt={0};
 publicReceipt.initialVtimerMaskKnown=publicOut->initialVtimerMaskKnown;
 publicReceipt.initialVtimerMask=publicOut->initialVtimerMask;
 VZKernelRunPendingReceiptV14 r={0};VZKernelRunStepReceiptV7 *step=&r.step;
 r.entryControl.failedNativeOffset=r.returnControl.failedNativeOffset=UINT32_MAX;
 r.entryControl.failedWriteOrdinal=r.returnControl.failedWriteOrdinal=UINT32_MAX;
 status=PendingRequestOwnedV14(cpu,&q);
 if(status==VZ_KERNEL_OK && (!ownWriter.writeMemory || ownWriter.context!=cpu->vm->ops.context))
  status=VZ_KERNEL_BAD_ARGUMENT;
 if(status==VZ_KERNEL_OK && (cpu->creationConfig.fineGrainedTraps || cpu->creationConfig.trapTLBISW))
  status=VZ_KERNEL_UNSUPPORTED;
 if(status==VZ_KERNEL_OK && cpu->runToken==UINT64_MAX)status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1((const void *)cpu->nativeContext,0x4118,false,NULL))
  status=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(status==VZ_KERNEL_OK)status=Version(cpu,&step->lifecycle);
 PendingRunAccessV14 access={{cpu,&ownWriter,&step->lifecycle,VZ_KERNEL_OK},NULL};
 VZCPUControl0EntryValuePlanV1 entry={0};uint64_t control0=0;bool progressControl0KnownV55=false;
 if(status==VZ_KERNEL_OK) {
  // Zero pending skips both control slices, exactly like the original Run.
  uint64_t mask=(cpu->pendingInterrupts.irqPending?UINT64_C(0x80):0)|
   (cpu->pendingInterrupts.fiqPending?UINT64_C(0x40):0);
  if(mask) {
   const uint32_t fields[]={0x670,0x678,0x748};
   for(unsigned i=0;i<3 && status==VZ_KERNEL_OK;++i)
    if(!VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+fields[i]),8,true,NULL))
     status=VZ_KERNEL_CONTEXT_UNREADABLE;
   if(status==VZ_KERNEL_OK) {
    ++r.entryControl.attemptedReads;
    if(!PendingReadMappedV14(&access,0x670,8,&control0)) {
     r.entryControl.failedNativeOffset=0x670;status=VZ_KERNEL_CONTEXT_UNREADABLE;
    }else progressControl0KnownV55=true;
   }
  }
  if(status==VZ_KERNEL_OK)status=PendingValueStatusV3(VZCPUPlanControl0EntryValueV1(
   &cpu->pendingInterrupts,step->lifecycle.nativeContextVersion,control0,&entry));
  r.entryPendingMask=entry.latchedPendingMask;
  if(status==VZ_KERNEL_OK && entry.needsControl0Slice) {
   status=PendingControl0V14(&access,entry.requestedControl0Value,&r.entryControl);
   r.entryControlComplete=status==VZ_KERNEL_OK;
  }
 }
 if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&access))status=access.init.boundaryStatus;
 if(status==VZ_KERNEL_OK) {
  if(!VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+0x4110),8,false,NULL) ||
   !cpu->vm->ops.readMemory(cpu->vm->ops.context,(const void *)(cpu->nativeContext+0x4110),8,&publicReceipt.entryActiveBanks) ||
   !PendingBoundaryV14(&access))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else publicReceipt.entryActiveBanksRead=true;
 }
 // Observe only the already-read Control0 and completed verified slice.
 // requestedControl0 is not a fresh native read; the slice also sets bit18.
 if(status==VZ_KERNEL_OK || r.entryControl.attemptedWrites) {
  const int saved=errno;unsigned ordinal=0;
  unsigned kind=VM27RunProgressSampleV55(&q,1,r.entryPendingMask!=0,&ordinal);
  if(kind)dprintf(2,"[Independent27HV] cpu-progress-entry id=%llu epoch=%llu generation=%llu ordinal=%u sampleKind=%u status=%u irq=%u fiq=%u entryPendingMask=0x%llx control0ReadKnown=%u nativeControl0Before=0x%llx control0SliceRequired=%u control0Requested=0x%llx control0SliceComplete=%u sliceStatus=%u writesAttempted=%u writesCompleted=%u native9NotYetInvoked=1\n",
   (unsigned long long)q.expectedPublicIdentity,(unsigned long long)q.expectedVMEpoch,
   (unsigned long long)q.expectedCPUGeneration,ordinal,kind,(unsigned)status,
   cpu->pendingInterrupts.irqPending,cpu->pendingInterrupts.fiqPending,
   (unsigned long long)r.entryPendingMask,progressControl0KnownV55,
   (unsigned long long)control0,entry.needsControl0Slice,
   (unsigned long long)entry.requestedControl0Value,r.entryControlComplete,
   (unsigned)r.entryControl.status,r.entryControl.attemptedWrites,r.entryControl.completedWrites);
  errno=saved;
 }
 if(status==VZ_KERNEL_OK) {
  step->vmEpoch=cpu->vm->generation;step->cpuGeneration=cpu->generation;
  step->ownerThread=cpu->owner;step->runToken=++cpu->runToken;
  step->lifecycle.nativeInvoked=true;
  step->lifecycle.nativeReturn=cpu->vm->ops.nativeTrap(cpu->vm->ops.context,9,NULL);
  memcpy(&step->nativeValues.nativeReturnBits,&step->lifecycle.nativeReturn,4);
  step->nativeValues.schemaVersion=VZ_CPU_EXIT_REDUCER_SCHEMA_V1;
  cpu->runPostReturnActive=true;
  RunPostAccessV7 post={cpu,step->vmEpoch,step->cpuGeneration,step->ownerThread,
   step->runToken,&step->lifecycle,VZ_KERNEL_OK};access.post=&post;
  if(!RunPostOwnedV7(&post))status=post.status;
  else if(step->lifecycle.nativeReturn)status=VZ_KERNEL_NATIVE_ERROR;
  r.runStatusBeforeCleanup=status;
  if(entry.needsControl0Slice) {
   // Nonzero native status is NOT permission to skip this protocol. Only a
   // failed real ownership/version boundary forbids touching the live state.
   VZKernelStatus cleanup=VZ_KERNEL_OK;
   if(!PendingBoundaryV14(&access))cleanup=access.init.boundaryStatus;
   if(cleanup==VZ_KERNEL_OK) {
    cpu->pendingInterrupts.irqPending=0;cpu->pendingInterrupts.fiqPending=0;r.pendingCleared=true;
    ++r.returnControl.attemptedReads;
    if(!PendingReadMappedV14(&access,0x670,8,&control0)) {
     r.returnControl.failedNativeOffset=0x670;cleanup=VZ_KERNEL_CONTEXT_UNREADABLE;
    }
    VZCPUControl0ReturnValuePlanV1 returned={0};
    if(cleanup==VZ_KERNEL_OK)cleanup=PendingValueStatusV3(VZCPUPlanControl0ReturnValueV1(
     &entry,&cpu->pendingInterrupts,step->lifecycle.nativeContextVersion,control0,
     step->nativeValues.nativeReturnBits,&returned));
    if(cleanup==VZ_KERNEL_OK)cleanup=PendingControl0V14(&access,
     returned.requestedControl0Value,&r.returnControl);
    r.returnControlComplete=cleanup==VZ_KERNEL_OK;
   }
   if(access.init.boundaryStatus!=VZ_KERNEL_OK)cleanup=access.init.boundaryStatus;
   r.cleanupStatus=cleanup;r.returnControl.status=cleanup;
   if(cleanup!=VZ_KERNEL_OK)status=cleanup;
  }
  if(status==VZ_KERNEL_OK) {
   step->nativeValues.nativeContextVersion=step->lifecycle.nativeContextVersion;
   if(!RunPostReadV7(&post,0x4008,4,&step->nativeValues.rawReason))status=post.status;
   else {
    step->nativeValues.knownFields=VZ_CPU_EXIT_REASON_KNOWN_V1;
    uint32_t reason=step->nativeValues.rawReason;
    if(reason==1 || reason==6 || reason==8) {
     if(!RunPostReadV7(&post,0x400c,4,&step->nativeValues.syndrome32) ||
      !RunPostReadV7(&post,0x4018,8,&step->nativeValues.virtualAddress) ||
      !RunPostReadV7(&post,0x4020,8,&step->nativeValues.physicalAddress))status=post.status;
     else step->nativeValues.knownFields=VZ_CPU_EXIT_ALL_KNOWN_V1;
    }
    if(status==VZ_KERNEL_OK && !RunPostOwnedV7(&post))status=post.status;
    if(status==VZ_KERNEL_OK) {
     step->postReturnIdentityValidated=true;
     VM27RunWakePostSnapshotV34(&access,&q,step);
     if(reason==7) {
      status=VM27InjectUndefinedV40(&access,&q,&publicReceipt.runStateMutationAttempted,true);
      if(status==VZ_KERNEL_OK)*resume=true;
     }
     bool encoded=reason==8 && (step->nativeValues.syndrome32>>26)==0x3f;
     if(status==VZ_KERNEL_OK && encoded)
      status=VM27HandleEncodedExitV47(gic,&access,&q,step,&publicReceipt,resume,&diagnosticLocal);
     if(gic && !encoded && (reason==1 || reason==6 || reason==8)) {
      VZKernelStatus handled=GICHandlePostV20(gic,&access,step,resume,&publicReceipt.runStateMutationAttempted,&diagnosticLocal);
      if(handled!=VZ_KERNEL_UNSUPPORTED || cpu->mutationPoisoned)status=handled;
     }
     if(status==VZ_KERNEL_OK && !*resume && (reason==1 || reason==6 || reason==8) &&
      (step->nativeValues.syndrome32>>26)==0x16) {
      // This VM profile was created only with EL2/VHE disabled. The modern
      // generic view returns the real HVC exception for ordinary EL1. Its
      // EL0 injection and private imm0 families remain explicitly outside it.
      if((cpu->vm->nativeHVISA!=1 && cpu->vm->nativeHVISA!=2) ||
       !GICPostPSTATEV20(&access,&publicReceipt.nativeHVCCPSR) ||
       !GICPostFieldV20(&access,8,false,&publicReceipt.nativeHVCX0))status=VZ_KERNEL_CONTEXT_UNREADABLE;
      else {
       publicReceipt.nativeHVCCPSRRead=true;publicReceipt.nativeHVCX0Read=true;
       VM27ResetOriginLogV56(step,&q,publicReceipt.nativeHVCX0,publicReceipt.nativeHVCCPSR);
       VM27ResetSnapshotV58(&access,&q,step,publicReceipt.nativeHVCX0,publicReceipt.nativeHVCCPSR);
       VM27PACReceiptV39 pac={0};VM27HVCLogBeforeV39(&access,&pac);
       uint64_t x0=publicReceipt.nativeHVCX0;bool privateFamily=!(step->nativeValues.syndrome32&0xffff) &&
        !(x0>>32) && ((x0>=UINT64_C(0xc6000000) && x0<=UINT64_C(0xc600001f)) || x0==UINT64_C(0xc3000006));
       if((publicReceipt.nativeHVCCPSR&0xc)!=4 || privateFamily)status=VZ_KERNEL_UNSUPPORTED;
       else {
        bool oldPAC=!(step->nativeValues.syndrome32&0xffff) && !(x0>>32) &&
         ((uint32_t)x0&UINT32_C(0xff000000))==UINT32_C(0xc1000000);
        if(oldPAC) {
         status=VM27PACServiceV39(&access,x0,&pac,&publicReceipt.runStateMutationAttempted);
         if(status==VZ_KERNEL_OK)*resume=true;
        } else {
         publicReceipt.publicExit=(VZCPUDecodedPublicExceptionV1){1,0,step->nativeValues.syndrome32,
          step->nativeValues.virtualAddress,step->nativeValues.physicalAddress};
         publicReceipt.ordinaryHVCProduced=true;publicReceipt.publicExitProduced=true;
        }
       }
       VM27HVCLogAfterV39(&access,&pac,x0,publicReceipt.nativeHVCCPSR,step->nativeValues.syndrome32,status);
      }
     }
     if(status==VZ_KERNEL_OK && !*resume && (reason==0 || reason==3 || reason==4 || reason==5 || reason==9 || reason==10)) {
      // Exact signed original13 table: raw0 canceled; 3/4 use the saved
      // pre-Run mask and full64 fresh native CNTV_CTL; 5/9/10 unknown.
      publicReceipt.publicExit.reason=reason==0?0:3;
      if(reason==3 || reason==4) {
       if(!publicReceipt.initialVtimerMaskKnown)status=VZ_KERNEL_NOT_LIVE;
       else if(!publicReceipt.entryActiveBanksRead || !(publicReceipt.entryActiveBanks&1))status=VZ_KERNEL_UNSUPPORTED;
       else if(!GICPostFieldV20(&access,0x4100,false,&publicReceipt.returnReadyBanks) ||
        !GICPostFieldV20(&access,0x430,false,&publicReceipt.nativeCNTVControl))status=VZ_KERNEL_CONTEXT_UNREADABLE;
       else {
        // Exact kernel: entry ready &= ~active; active bank0=1 clears the
        // ready bit before guest entry. Exit ready0 uses MRS430; ready1 is
        // produced only after the actual bank-save MRS430 and ORready.
        publicReceipt.returnReadyBanksRead=true;publicReceipt.nativeCNTVControlFresh=true;
        publicReceipt.nativeCNTVControlRead=true;
        if(!publicReceipt.initialVtimerMask && publicReceipt.nativeCNTVControl==UINT64_C(5)) {
         uint64_t mask=0;
         if(!GICPostFieldV20(&access,0x6d8,false,&mask))status=VZ_KERNEL_CONTEXT_UNREADABLE;
         else {
          mask|=1;++publicReceipt.autoMaskWritesAttempted;
          if(!GICPostFieldV20(&access,0x6d8,true,&mask)) {GICPoisonV20(cpu);status=VZ_KERNEL_CONTEXT_UNREADABLE;}
          else {++publicReceipt.autoMaskWritesCompleted;publicReceipt.autoMaskCommitted=true;publicReceipt.publicExit.reason=2;}
         }
        }
       }
      }
      if(status==VZ_KERNEL_OK && !PendingBoundaryV14(&access))status=access.init.boundaryStatus;
      if(status==VZ_KERNEL_OK) {
       if(gic && publicReceipt.publicExit.reason==2) {
        // Original modern GIC Run wrapper 9a9c..9aa4 consumes this exact
        // timer result internally, then refreshes real timer/GIC lines.
        *resume=true;
        unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27VirtualTimerConsumedLogsV35,8);
        if(ordinal){int saved=errno;
         dprintf(2,"[Independent27HV] virtual-timer-consumed ordinal=%u token=%llu raw=0x%x initialMask=%u CTL=0x%llx realMaskCommitted=%u publicExitProduced=0 PCUnchanged=1\n",
          ordinal,(unsigned long long)step->runToken,reason,publicReceipt.initialVtimerMask,
          (unsigned long long)publicReceipt.nativeCNTVControl,publicReceipt.autoMaskCommitted);errno=saved;}
       }else publicReceipt.publicExitProduced=true;
      }
      else if(publicReceipt.autoMaskWritesAttempted)GICPoisonV20(cpu);
     }
     if(status==VZ_KERNEL_OK && !*resume && !publicReceipt.publicExitProduced) {
      VZCPUExitReducerStatusV1 reduced=VZCPUReduceNativeExitV1(&step->nativeValues,&step->reduction);
      if(reduced!=VZ_CPU_EXIT_REDUCER_OK_V1)status=VZ_KERNEL_UNSUPPORTED;
      else {step->reductionValid=true;step->publicExceptionProduced=step->reduction.hasPublicException==1;
       if(!step->publicExceptionProduced)status=VZ_KERNEL_BUSY;
       else {publicReceipt.publicExit=step->reduction.exception;publicReceipt.publicExitProduced=true;}}
     }
     if(gic && status==VZ_KERNEL_BUSY && (reason==2 || reason==11)) {*resume=true;status=VZ_KERNEL_OK;}
    }
   }
  }
  cpu->runPostReturnActive=false;
 }
 // Successful cleanup followed by a BUSY/unsupported guest exit does not
 // poison the CPU. Partial native mutation or failed cleanup always does.
 if((r.entryControl.attemptedWrites && (!r.entryControlComplete ||
     (!step->lifecycle.nativeInvoked && status!=VZ_KERNEL_OK))) ||
  (step->lifecycle.nativeInvoked && entry.needsControl0Slice && !r.returnControlComplete)) {
  cpu->mutationPoisoned=true;Lock(&cpu->vm->mutex);
  cpu->registryEntry->published=false;cpu->registryEntry->draining=true;
  Unlock(&cpu->vm->mutex);r.identityWithdrawn=true;
 }
 if(access.init.boundaryStatus!=VZ_KERNEL_OK)status=access.init.boundaryStatus;
 r.mutationPoisoned=cpu->mutationPoisoned;
 r.entryControl.mutationPoisoned=r.returnControl.mutationPoisoned=r.mutationPoisoned;
 CPUResult(cpu,&step->lifecycle);step->lifecycle.status=status;step->status=status;
 publicReceipt.pending=r;
 VM27RunDiagnosticReceiptV29("internal-step",diagnosticOrdinal,
  &publicReceipt,(unsigned)status,*resume);
 VM27GICLogLocalV33(diagnosticOrdinal,step,&diagnosticLocal);
 *publicOut=publicReceipt;EndOperation(&cpu->operationInProgress);return status;
}

static VZKernelStatus GICPollBeforeRunV20(VZKernelCPUGICOwnerV18 *o,bool *mutated,uint64_t *entryMask) {
 VZKernelPhysicalTimerReceiptV19 timer={0};VZKernelLifecycleResult lifecycle={0};
 VZKernelStatus s=VZKernelPhysicalTimerOwnerAccessV19(o->timer,VZ_KERNEL_PHYSICAL_TIMER_POLL_V19,
  0,0,NULL,&timer,&lifecycle);
 *mutated=timer.attemptedWrites || timer.irqRouteAttempted || timer.deadlineAttempted;
 if(s!=VZ_KERNEL_OK)return s;
 s=BeginCPUOperation(o->cpu);bool entered=s!=VZ_KERNEL_BUSY;
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(s==VZ_KERNEL_OK)s=Version(o->cpu,&lifecycle);
 // PhysicalTimerOwnerAccess has just obtained the actual bank0 state and
 // validated counter-domain sample under this same CPU/owner identity.
 InitializationAccess access={o->cpu,&o->writer,&lifecycle,VZ_KERNEL_OK};
 uint64_t ctl=0,cval=0,mask=0,newMask=0,now=0;bool asserted=false,aggregate=false,virtualMutation=false;
 if(s==VZ_KERNEL_OK && (!timer.physicalStateRead || !timer.domainValidated ||
  VZKernelValidateCounterDomainV19(&timer.counterDomain)!=VZ_COUNTER_DOMAIN_VALID_V19 ||
  timer.vtimerOffset-timer.counterDomain.commpageBaseBefore>timer.counterDomain.physicalBefore))s=VZ_KERNEL_UNSUPPORTED;
 if(s==VZ_KERNEL_OK && (!SystemReadMappedV8(&access,0x430,8,&ctl) ||
  !SystemReadMappedV8(&access,0x3e8,8,&cval) || !VtimerMaskNativeV20(&access,false,&mask)))s=VZ_KERNEL_CONTEXT_UNREADABLE;
 if(s==VZ_KERNEL_OK) {
  now=timer.counterDomain.machAbsolute-timer.vtimerOffset;
  asserted=(ctl&UINT64_C(3))==UINT64_C(1) && now>=cval;
  // Native6d8 masks duplicate host exits, not the real software GIC level.
  // Guest reprogramming/disable clears it so the next real expiry can exit.
  newMask=(mask&~UINT64_C(1))|(uint64_t)asserted;
  if(newMask!=mask){*mutated=true;virtualMutation=true;if(!VtimerMaskNativeV20(&access,true,&newMask))s=VZ_KERNEL_CONTEXT_UNREADABLE;}
 }
 if(s==VZ_KERNEL_OK) {
  *mutated=true;virtualMutation=true;s=VM27GICRouteVirtualTimerV35(o->engine,&o->identity,asserted,&aggregate);
 }
 if(s==VZ_KERNEL_OK && !InitializationOwned(&access))s=access.boundaryStatus;
 if(asserted || newMask!=mask) {
  unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27VirtualTimerStateLogsV35,8);
  if(ordinal){int saved=errno;
   dprintf(2,"[Independent27HV] virtual-timer-state ordinal=%u status=%u CTL=0x%llx CVAL=0x%llx logicalCounter=0x%llx nativeOffset=0x%llx maskBefore=0x%llx maskRequested=0x%llx PPI27Requested=%u aggregateIRQ=%u\n",
    ordinal,(unsigned)s,(unsigned long long)ctl,(unsigned long long)cval,(unsigned long long)now,
    (unsigned long long)timer.vtimerOffset,(unsigned long long)mask,(unsigned long long)newMask,asserted,aggregate);errno=saved;}
 }
 VM27GICLinesV1 lines={0};
 if(s==VZ_KERNEL_OK)s=VM27GICGetLinesV1(o->engine,&o->identity,&lines);
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(s==VZ_KERNEL_OK){o->cpu->pendingInterrupts.irqPending=(uint32_t)lines.irq;
  o->cpu->pendingInterrupts.fiqPending=(uint32_t)lines.fiq;if(entryMask)*entryMask=newMask;}
 if(s==VZ_KERNEL_OK) {
  const int saved=errno;unsigned ordinal=0;
  unsigned kind=VM27RunProgressSampleV55(&o->identity,0,lines.irq || lines.fiq,&ordinal);
  if(kind)dprintf(2,"[Independent27HV] cpu-progress-poll id=%llu epoch=%llu generation=%llu ordinal=%u sampleKind=%u status=%u CTL=0x%llx CVAL=0x%llx logicalCounter=0x%llx nativeOffset=0x%llx counterFrequency=%llu timebaseNumer=%u timebaseDenom=%u hostCounterBias=0x%llx maskBefore=0x%llx maskRequested=0x%llx PPI27Requested=%u irq=%u fiq=%u group0Candidate=%u group1Candidate=%u domainValidated=%u\n",
   (unsigned long long)o->identity.expectedPublicIdentity,
   (unsigned long long)o->identity.expectedVMEpoch,(unsigned long long)o->identity.expectedCPUGeneration,
   ordinal,kind,(unsigned)s,(unsigned long long)ctl,(unsigned long long)cval,
   (unsigned long long)now,(unsigned long long)timer.vtimerOffset,
   (unsigned long long)timer.counterDomain.counterFrequency,timer.counterDomain.timebaseNumer,
   timer.counterDomain.timebaseDenom,(unsigned long long)timer.counterDomain.commpageBaseBefore,
   (unsigned long long)mask,(unsigned long long)newMask,asserted,lines.irq,lines.fiq,
   lines.highestGroup0,lines.highestGroup1,timer.domainValidated);
  errno=saved;
 }
 if(s!=VZ_KERNEL_OK && virtualMutation)GICPoisonV20(o->cpu);
 if(entered)EndOperation(&o->cpu->operationInProgress);return s;
}
typedef struct {VZKernelCPUGICOwnerV18 *owner;bool mutated;} GICWFxPollContextV30;
static _Atomic unsigned VM27WFxCNTVErrorsV32;
// Native kernel abc84/abc98 loads CVAL3e8/CTL430; abb7c subtracts the
// commpage counter bias from native6a0 before CNTVOFF_EL2. Use that same
// validated domain, never a host elapsed-time estimate of guest timer state.
static VZKernelStatus GICWFxCNTVDeadlineV31(VZKernelCPUGICOwnerV18 *o,bool *due,uint64_t *delay) {
 VZKernelStatus status=BeginCPUOperation(o->cpu);bool entered=status!=VZ_KERNEL_BUSY;
 VZKernelLifecycleResult lifecycle={0};
 if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(o->cpu,&o->identity);
 if(status==VZ_KERNEL_OK)status=Version(o->cpu,&lifecycle);
 InitializationAccess access={o->cpu,&o->writer,&lifecycle,VZ_KERNEL_OK};
 uint64_t dirty=0,ready=0,ctl=0,cval=0,offset=0,mask=0;bool synced=false,banksKnown=false;
 if(status==VZ_KERNEL_OK) {
  banksKnown=SystemReadMappedV8(&access,0x748,8,&dirty) && SystemReadMappedV8(&access,0x4100,8,&ready);
  if(!banksKnown)status=VZ_KERNEL_CONTEXT_UNREADABLE;
 }
 if(status==VZ_KERNEL_OK && !((dirty|ready)&UINT64_C(1)))
  status=PrepareSystemNative8V8(&access,&synced);
 if(status==VZ_KERNEL_OK && (!SystemReadMappedV8(&access,0x430,8,&ctl) ||
  !SystemReadMappedV8(&access,0x3e8,8,&cval) || !SystemReadMappedV8(&access,0x6a0,8,&offset) ||
  !VtimerMaskNativeV20(&access,false,&mask)))status=VZ_KERNEL_CONTEXT_UNREADABLE;
 // A native host-exit mask must not suppress the real GIC timer deadline.
 if(status==VZ_KERNEL_OK && (ctl&3)==1) {
  VZKernelCounterDomainSampleV19 sample={0};
  if(!InitializationOwned(&access) ||
   !o->timer->binding.readCounterDomain(o->timer->binding.nativeContext,&sample) ||
   !InitializationOwned(&access))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  else if(VZKernelValidateCounterDomainV19(&sample)!=VZ_COUNTER_DOMAIN_VALID_V19 ||
   offset-sample.commpageBaseBefore>sample.physicalBefore)status=VZ_KERNEL_UNSUPPORTED;
  else {
   uint64_t now=sample.machAbsolute-offset;
   // Timer level was refreshed by the preceding poll. An expired timer
   // cannot wake WFx unless its real GIC pending interrupt is enabled.
   if(cval<=now)status=GICWFxPendingV30(o,due,delay);
   else {
    __uint128_t ns=((__uint128_t)(cval-now)*UINT64_C(1000000000)+sample.counterFrequency-1)/sample.counterFrequency;
    if(ns<*delay)*delay=(uint64_t)ns;
   }
  }
 }
 if(status==VZ_KERNEL_OK && !InitializationOwned(&access))status=access.boundaryStatus;
 if(status!=VZ_KERNEL_OK) {
  unsigned ordinal=atomic_load_explicit(&VM27WFxCNTVErrorsV32,memory_order_relaxed);
  while(ordinal<8 && !atomic_compare_exchange_weak_explicit(&VM27WFxCNTVErrorsV32,&ordinal,ordinal+1,memory_order_relaxed,memory_order_relaxed)){}
  if(ordinal<8) {
   int saved=errno;
   dprintf(2,"[Independent27HV] wfx-cntv-error ordinal=%u kernelStatus=%u banksKnown=%u bankReady=0x%llx bankDirty=0x%llx syncInvoked=%u nativeInvoked=%u nativeReturn=0x%x\n",
    ordinal+1,(unsigned)status,banksKnown,(unsigned long long)ready,(unsigned long long)dirty,synced,
    lifecycle.nativeInvoked,(unsigned)lifecycle.nativeReturn);
   errno=saved;
  }
 }
 if(entered)EndOperation(&o->cpu->operationInProgress);return status;
}
static VZKernelStatus GICWFxPollV30(void *context,bool *ready,uint64_t *delay) {
 GICWFxPollContextV30 *c=context;bool mutated=false;
 VZKernelStatus status=GICPollBeforeRunV20(c->owner,&mutated,NULL);c->mutated=c->mutated || mutated;
 if(status==VZ_KERNEL_OK)status=GICWFxPendingV30(c->owner,ready,delay);
 if(status==VZ_KERNEL_OK && !*ready)status=GICWFxCNTVDeadlineV31(c->owner,ready,delay);
 return status;
}
VZKernelStatus VZKernelCPURunGICPublicBoundedV20(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,uint64_t limit,
 VZKernelRunPublicReceiptV20 *out) {
 if(!cpu || !q || !writer || !out)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPUGICOwnerV18 *needle=GICFindOwnerV18(cpu);
 if(!needle) {
  const void *p[]={q,writer,out};const size_t n[]={sizeof(*q),sizeof(*writer),sizeof(*out)};
  if(!PendingRangesV14(cpu,p,n,3) || !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))return VZ_KERNEL_BAD_ARGUMENT;
  VZKernelRunPublicReceiptV20 receipt={0};VZKernelStatus s=VZKernelCPURunOwnedPendingStepV14(cpu,q,writer,&receipt.pending);
  if(s==VZ_KERNEL_OK && receipt.pending.step.publicExceptionProduced) {
   receipt.publicExit=receipt.pending.step.reduction.exception;receipt.publicExitProduced=true;
  }
  if(!PendingRangesV14(cpu,p,n,3) || !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))return VZ_KERNEL_BAD_ARGUMENT;
  *out=receipt;return s;
 }
 VZKernelCPUGICOwnerV18 *o=NULL;VZKernelStatus status=GICOwnerBeginV18(needle,&o);
 if(status!=VZ_KERNEL_OK)return status;
 const void *p[]={q,writer,out};const size_t n[]={sizeof(*q),sizeof(*writer),sizeof(*out)};
 bool valid=PendingRangesV14(cpu,p,n,3);
 for(unsigned i=0;i<3 && valid;++i)valid=VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]);
 if(!valid){EndOperation(&o->operation);return VZ_KERNEL_BAD_ARGUMENT;}
 if(!pthread_equal(o->owner,pthread_self()))status=VZ_KERNEL_WRONG_THREAD;
 else if(o->draining || memcmp(q,&o->identity,sizeof(*q)) || writer->context!=o->writer.context ||
  writer->writeMemory!=o->writer.writeMemory)status=VZ_KERNEL_NOT_LIVE;
 VZKernelRunPendingRequestV14 ownQ=*q;VZKernelInitWriter ownWriter=*writer;
 VZKernelRunPublicReceiptV20 receipt={0};bool begun=false;
 if(status==VZ_KERNEL_OK) {
  status=BeginCPUOperation(cpu);bool entered=status!=VZ_KERNEL_BUSY;
  if(status==VZ_KERNEL_OK)status=PendingRequestOwnedV14(cpu,&ownQ);
  if(status==VZ_KERNEL_OK)status=Version(cpu,&receipt.pending.step.lifecycle);
  uint64_t initialMask=0;InitializationAccess a={cpu,&ownWriter,&receipt.pending.step.lifecycle,VZ_KERNEL_OK};
  if(status==VZ_KERNEL_OK && !VtimerMaskNativeV20(&a,false,&initialMask))status=VZ_KERNEL_CONTEXT_UNREADABLE;
  if(status==VZ_KERNEL_OK){receipt.initialVtimerMaskKnown=true;receipt.initialVtimerMask=(initialMask&1)!=0;}
  if(entered)EndOperation(&cpu->operationInProgress);
 }
 if(status==VZ_KERNEL_OK){status=VM27GICBeginRunV1(o->engine,&o->identity);begun=status==VZ_KERNEL_OK;}
 if(status==VZ_KERNEL_OK)atomic_store_explicit(&o->running,true,memory_order_release);
 if(status==VZ_KERNEL_OK)VM27RunWakeArmV34(&ownQ);
 for(uint64_t count=0;status==VZ_KERNEL_OK;++count) {
  if(atomic_load_explicit(&o->exitRequested,memory_order_acquire)){status=VZ_KERNEL_BUSY;break;}
  if(limit && count==limit){status=VZ_KERNEL_BUSY;break;}
  GICWFxPollContextV30 waiting={o,false};
  status=VM27WFxAwaitV30(&o->wfx,GICWFxPollV30,&waiting);
  receipt.runStateMutationAttempted=receipt.runStateMutationAttempted || waiting.mutated;
  if(status!=VZ_KERNEL_OK)break;
  bool pollMutated=false;uint64_t entryMask=0;status=GICPollBeforeRunV20(o,&pollMutated,&entryMask);
  receipt.runStateMutationAttempted=receipt.runStateMutationAttempted || pollMutated;
  if(status!=VZ_KERNEL_OK)break;
  // Recheck immediately before the actual entry producer. A concurrent exit
  // while running=true also issues native10, so the native cancellation record
  // closes the interval from this check through the actual native9 entry.
  if(atomic_load_explicit(&o->exitRequested,memory_order_acquire)){status=VZ_KERNEL_BUSY;break;}
  // Like original modern Run 98d8..98e0, latch the actual mask immediately
  // before each native9, after the genuine timer/GIC poll may rearm it.
  bool resume=false;bool initialKnown=true,initialMask=(entryMask&1)!=0;
  bool earlierMutation=receipt.runStateMutationAttempted;
  memset(&receipt,0,sizeof(receipt));receipt.initialVtimerMaskKnown=initialKnown;receipt.initialVtimerMask=initialMask;
  status=GICRunActualStepV20(cpu,&ownQ,&ownWriter,&receipt,o,&resume);
  receipt.runStateMutationAttempted=receipt.runStateMutationAttempted || earlierMutation;
  if(status!=VZ_KERNEL_OK || !resume)break;
  if(count==UINT64_MAX-1){status=VZ_KERNEL_BUSY;break;}
 }
 atomic_store_explicit(&o->running,false,memory_order_release);
 if(begun) {
  VZKernelStatus ended=VM27GICEndRunV1(o->engine,&o->identity);
  if(ended!=VZ_KERNEL_OK){GICPoisonV20(cpu);status=ended;}
 }
 receipt.pending.mutationPoisoned=cpu->mutationPoisoned;
 receipt.pending.identityWithdrawn=receipt.pending.identityWithdrawn || cpu->mutationPoisoned;
 receipt.pending.step.status=receipt.pending.step.lifecycle.status=status;
 valid=PendingRangesV14(cpu,p,n,3);
 for(unsigned i=0;i<3 && valid;++i)valid=VZKernelCPUControllerOutputRangeDisjointV18(p[i],n[i]);
 if(!valid || !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL)) {
  status=VZ_KERNEL_BAD_ARGUMENT;if(receipt.autoMaskWritesAttempted || receipt.runStateMutationAttempted)GICPoisonV20(cpu);
 }else *out=receipt;
 EndOperation(&o->operation);return status;
}
VZKernelStatus VZKernelCPURunGICPublicV20(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,VZKernelRunPublicReceiptV20 *out) {
 return VZKernelCPURunGICPublicBoundedV20(cpu,q,writer,0,out);
}
// Compatibility for frozen private exception diagnostics. The new SDK Run
// consumes PublicReceipt20; this inherited lane never invents exception flags.
VZKernelStatus VZKernelCPURunGICPendingBoundedV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,uint64_t limit,VZKernelRunPendingReceiptV14 *out) {
 if(!out)return VZ_KERNEL_BAD_ARGUMENT;
 if(!GICFindOwnerV18(cpu))return VZKernelCPURunOwnedPendingStepV14(cpu,q,writer,out);
 const void *p[]={q,writer,out};const size_t n[]={sizeof(*q),sizeof(*writer),sizeof(*out)};
 if(!PendingRangesV14(cpu,p,n,3) || !VZKernelCPUControllerOutputRangeDisjointV18(out,sizeof(*out)) ||
  !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPublicReceiptV20 receipt={0};VZKernelStatus s=VZKernelCPURunGICPublicBoundedV20(cpu,q,writer,limit,&receipt);
 if(s==VZ_KERNEL_OK && receipt.publicExitProduced && receipt.publicExit.reason!=1)s=VZ_KERNEL_UNSUPPORTED;
 if(!PendingRangesV14(cpu,p,n,3) || !VM27CPUSelfMappedRangeV1(out,sizeof(*out),true,NULL))return VZ_KERNEL_BAD_ARGUMENT;
 *out=receipt.pending;return s;
}
VZKernelStatus VZKernelCPURunGICPendingV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,const VZKernelInitWriter *writer,VZKernelRunPendingReceiptV14 *out) {
 return VZKernelCPURunGICPendingBoundedV18(cpu,q,writer,0,out);
}
