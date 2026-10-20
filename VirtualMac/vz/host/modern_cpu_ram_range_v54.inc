// Same VM operation owns every transaction. Native calls occur outside locks.
// Native4/5 own real VM-map/PTE synchronization; no userspace TLB surrogate.
static void RAMSegmentsFreeV54(VZKernelRAMSegmentV54 *g) {
 while(g){VZKernelRAMSegmentV54 *next=g->next;free(g);g=next;}
}
static void RAMPlansFreeV54(VZKernelRAMRangePlanV54 *p) {
 while(p){VZKernelRAMRangePlanV54 *next=p->next;RAMSegmentsFreeV54(p->segments);free(p);p=next;}
}
static bool RAMSegmentAppendV54(VZKernelRAMSegmentV54 ***tail,
 const VZKernelRAMSegmentV54 *source,uint64_t start,uint64_t end,bool target) {
 if(start==end)return true;
 VZKernelRAMSegmentV54 *g=calloc(1,sizeof(*g));if(!g)return false;
 *g=*source;g->next=NULL;g->hostOffset+=start-source->guestAddress;
 g->guestAddress=start;g->bytes=end-start;g->target=target;
 if(target)g->uncertain=true;
 **tail=g;*tail=&g->next;return true;
}
static void RAMSegmentsCoalesceV54(VZKernelRAMSegmentV54 *g) {
 while(g && g->next) {
  VZKernelRAMSegmentV54 *next=g->next;
  if(!g->target && !next->target && g->mapped==next->mapped && g->uncertain==next->uncertain &&
   g->flags==next->flags && g->guestAddress+g->bytes==next->guestAddress &&
   g->hostOffset+g->bytes==next->hostOffset) {
   g->bytes+=next->bytes;g->next=next->next;free(next);
  }else g=next;
 }
}
static void RAMRootRefreshV54(VZKernelRAMV9 *r) {
 bool flagsKnown=true,first=true;r->mapped=false;r->uncertain=false;
 uint64_t flags=0;
 for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next) {
  r->mapped|=g->mapped;r->uncertain|=g->uncertain;
  if(first){flags=g->flags;first=false;}else if(flags!=g->flags)flagsKnown=false;
 }
 r->flags=!first && flagsKnown?flags:0;
}
// The real task VM remains pinned by its existing VM operation exclusion.
// Read-side leases protect instruction decode through its actual CPU writes.
static bool RAMMutationBeginV54(VZKernelVM *vm,VZKernelRAMRangePlanV54 *plan) {
 struct timespec deadline={0};if(clock_gettime(CLOCK_REALTIME,&deadline))return false;
 ++deadline.tv_sec;Lock(&vm->mutex);int waitResult=0;
 while(vm->ramCodeReaders && !waitResult)
  waitResult=pthread_cond_timedwait(&vm->ramPublication,&vm->mutex,&deadline);
 bool ready=!waitResult && !vm->ramCodeReaders && !(vm->ramMapVersion&1) &&
  vm->ramMapVersion<=UINT64_MAX-2;
 if(ready){vm->ramRangePlan=plan;++vm->ramMapVersion;}
 Unlock(&vm->mutex);return ready;
}
static void RAMMutationEndLockedV54(VZKernelVM *vm) {
 if(!(vm->ramMapVersion&1))abort();
 vm->ramRangePlan=NULL;++vm->ramMapVersion;
 if(pthread_cond_broadcast(&vm->ramPublication))abort();
}
static bool RAMCodeLeaseBeginV54(VZKernelVM *vm) {
 struct timespec deadline={0};if(clock_gettime(CLOCK_REALTIME,&deadline))return false;
 ++deadline.tv_sec;Lock(&vm->mutex);int waitResult=0;
 while((vm->ramMapVersion&1) && !waitResult)
  waitResult=pthread_cond_timedwait(&vm->ramPublication,&vm->mutex,&deadline);
 bool ready=!waitResult && vm->live && !(vm->ramMapVersion&1) && vm->ramCodeReaders<UINT_MAX;
 if(ready)++vm->ramCodeReaders;
 Unlock(&vm->mutex);return ready;
}
static void RAMCodeLeaseEndV54(VZKernelVM *vm) {
 Lock(&vm->mutex);if(!vm->ramCodeReaders)abort();--vm->ramCodeReaders;
 if(pthread_cond_broadcast(&vm->ramPublication))abort();Unlock(&vm->mutex);
}
// Protect requires complete known coverage. Unmap may include known holes:
// the real native4 receives the exact requested range even for an empty range.
static VZKernelStatus RAMProtectCoverageV54(VZKernelVM *vm,uint64_t start,
 uint64_t end,uint64_t flags) {
 uint64_t cursor=start;
 while(cursor<end) {
  VZKernelRAMV9 *root=NULL;VZKernelRAMSegmentV54 *found=NULL;unsigned matches=0;
  for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next)
   for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next)
    if(g->guestAddress<=cursor && cursor-g->guestAddress<g->bytes){root=r;found=g;++matches;}
  if(matches!=1 || !found || !found->mapped || found->uncertain)return VZ_KERNEL_BAD_ARGUMENT;
  uint64_t stop=found->guestAddress+found->bytes;if(stop>end)stop=end;
  uint64_t offset=found->hostOffset+cursor-found->guestAddress;
  uintptr_t host=(uintptr_t)root->host;
  if(offset>root->bytes || stop-cursor>root->bytes-offset || offset>UINTPTR_MAX-host ||
   !VM27CPUSelfMappedRangeV1((const void *)(host+(uintptr_t)offset),(size_t)(stop-cursor),
    (flags&UINT64_C(2))!=0,NULL))return VZ_KERNEL_CONTEXT_UNREADABLE;
  cursor=stop;
 }
 return VZ_KERNEL_OK;
}
static VZKernelStatus RAMBuildRangePlanV54(VZKernelVM *vm,uint64_t start,
 uint64_t end,VZKernelRAMRangePlanV54 **out) {
 VZKernelRAMRangePlanV54 **tail=out;
 for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next) {
  bool affected=false;
  for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next)
   if(start<g->guestAddress+g->bytes && g->guestAddress<end)affected=true;
  if(!affected)continue;
  VZKernelRAMRangePlanV54 *p=calloc(1,sizeof(*p));if(!p)return VZ_KERNEL_OUT_OF_MEMORY;
  p->root=r;*tail=p;tail=&p->next;VZKernelRAMSegmentV54 **at=&p->segments;
  for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next) {
   uint64_t a=g->guestAddress,b=a+g->bytes;
   if(start>=b || end<=a) {
    if(!RAMSegmentAppendV54(&at,g,a,b,false))return VZ_KERNEL_OUT_OF_MEMORY;
   }else {
    uint64_t lo=start>a?start:a,hi=end<b?end:b;
    if(!RAMSegmentAppendV54(&at,g,a,lo,false) || !RAMSegmentAppendV54(&at,g,lo,hi,true) ||
     !RAMSegmentAppendV54(&at,g,hi,b,false))return VZ_KERNEL_OUT_OF_MEMORY;
   }
  }
 }
 return VZ_KERNEL_OK;
}
static void RAMPublishRangeLockedV54(VZKernelRAMRangePlanV54 *plan,
 VZKernelMemoryOperation operation,uint64_t flags,bool success) {
 for(VZKernelRAMRangePlanV54 *p=plan;p;p=p->next) {
  VZKernelRAMSegmentV54 **link=&p->segments;
  while(*link) {
   VZKernelRAMSegmentV54 *g=*link;
   if(g->target && success && operation==VZKernelMemoryUnmap){*link=g->next;free(g);continue;}
   if(g->target){g->target=false;g->uncertain=!success;if(success){g->mapped=true;g->flags=flags;}}
   link=&g->next;
  }
  RAMSegmentsFreeV54(p->root->segments);p->root->segments=p->segments;p->segments=NULL;
  RAMSegmentsCoalesceV54(p->root->segments);RAMRootRefreshV54(p->root);
 }
}
// Caller already owns the exact kernel VM operation, not a CPU execution lock.
static VZKernelStatus RAMRangeOwnedV54(VZKernelVM *vm,VZKernelMemoryOperation operation,
 uint64_t ipa,uint64_t bytes,uint64_t flags,VZKernelRAMResultV9 *out) {
 VZKernelStatus status=RAMTaskCallerV53(vm)?VZ_KERNEL_OK:VZ_KERNEL_WRONG_THREAD;
 if((operation!=VZKernelMemoryUnmap && operation!=VZKernelMemoryProtect) ||
  (operation==VZKernelMemoryUnmap && flags))status=VZ_KERNEL_BAD_ARGUMENT;
 VZKernelMemoryPacket packet;
 if(status==VZ_KERNEL_OK)status=VZKernelMemoryPacketEncode(vm->ops.validatedKernelProfile,
  operation,0,ipa,bytes,operation==VZKernelMemoryUnmap?0:flags,0,&packet);
 if(status==VZ_KERNEL_OK && operation==VZKernelMemoryProtect)
  status=RAMProtectCoverageV54(vm,ipa,ipa+bytes,flags);
 VZKernelRAMRangePlanV54 *plan=NULL;
 if(status==VZ_KERNEL_OK)status=RAMBuildRangePlanV54(vm,ipa,ipa+bytes,&plan);
 bool invoked=false,outputValid=true;int32_t nativeReturn=0;
 if(status==VZ_KERNEL_OK) {
  // Publish all new control allocations before the actual native callback.
  if(!RAMMutationBeginV54(vm,plan))status=VZ_KERNEL_BUSY;
  else {
   Lock(&vm->mutex);bool disjoint=RAMDisjointV9(vm,out,sizeof(*out));Unlock(&vm->mutex);
   if(!disjoint){status=VZ_KERNEL_BAD_ARGUMENT;outputValid=false;}
   if(status==VZ_KERNEL_OK){invoked=true;nativeReturn=vm->ops.nativeTrap(vm->ops.context,operation,&packet);
    status=nativeReturn?VZ_KERNEL_NATIVE_ERROR:RAMTaskCallerV53(vm)?VZ_KERNEL_OK:VZ_KERNEL_WRONG_THREAD;}
   Lock(&vm->mutex);
   // A pre-native validation failure preserves the original interval ledger.
   if(invoked)RAMPublishRangeLockedV54(plan,operation,flags,status==VZ_KERNEL_OK);
   RAMMutationEndLockedV54(vm);Unlock(&vm->mutex);
  }
 }
 RAMPlansFreeV54(plan);if(!outputValid)return status;
 VZKernelRAMResultV9 receipt={0};receipt.status=status;receipt.vmEpoch=vm->generation;
 receipt.ownerThread=vm->owner;receipt.guestAddress=ipa;receipt.bytes=bytes;receipt.flags=flags;
 receipt.nativeInvoked=invoked;receipt.nativeReturn=nativeReturn;
 receipt.mapped=invoked && status==VZ_KERNEL_OK && operation==VZKernelMemoryProtect;
 receipt.mappingUncertain=invoked && status!=VZ_KERNEL_OK;receipt.cleanupPending=true;
 memcpy(out,&receipt,sizeof(receipt));return status;
}
VZKernelStatus VZKernelRAMRangeChangeV54(VZKernelVM *needle,uint64_t epoch,
 VZKernelMemoryOperation operation,uint64_t ipa,uint64_t bytes,uint64_t flags,VZKernelRAMResultV9 *out) {
 if(!needle || !epoch)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelVM *vm=NULL;VZKernelRAMV9 *unused=NULL;
 VZKernelStatus status=RAMBeginV9(needle,NULL,&vm,&unused);if(status)return status;
 Lock(&vm->mutex);bool valid=RAMDisjointV9(vm,out,sizeof(*out));Unlock(&vm->mutex);
 if(!valid){EndOperation(&vm->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 status=VZKernelRAMTaskScopeV53(vm,epoch);
 if(status==VZ_KERNEL_OK)status=RAMRangeOwnedV54(vm,operation,ipa,bytes,flags,out);
 EndOperation(&vm->operationInProgress);return status;
}
VZKernelStatus VZKernelRAMMapV9(VZKernelRAMV9 *needle,uint64_t ipa,uint64_t flags,VZKernelRAMResultV9 *out) {
 VZKernelVM *vm=NULL;VZKernelRAMV9 *ram=NULL;
 VZKernelStatus status=RAMAdmitV9(needle,out,&vm,&ram);
 if(status){RAMFailureV52("map-admission",status,ipa,0,false);return status;}
 status=RAMReadyV50(vm,ram,true);const char *failure="map-owner-or-state";
 if(status==VZ_KERNEL_OK && (ram->mapped || ram->uncertain || ram->segments))status=VZ_KERNEL_BUSY;
 VZKernelMemoryPacket packet;
 if(status==VZ_KERNEL_OK){failure="map-packet";status=VZKernelMemoryPacketEncode(vm->ops.validatedKernelProfile,
  VZKernelMemoryMap,(uintptr_t)ram->host,ipa,ram->bytes,flags,0,&packet);}
 if(status==VZ_KERNEL_OK) {
  for(VZKernelRAMV9 *r=vm->ramRegistry;r;r=r->next)
   for(VZKernelRAMSegmentV54 *g=r->segments;g;g=g->next)
    if(ipa<g->guestAddress+g->bytes && g->guestAddress<ipa+ram->bytes){status=VZ_KERNEL_BUSY;failure="map-gpa-overlap";}
 }
 if(status==VZ_KERNEL_OK && !VM27CPUSelfMappedRangeV1(ram->host,(size_t)ram->bytes,(flags&UINT64_C(2))!=0,NULL))
  {status=VZ_KERNEL_CONTEXT_UNREADABLE;failure="map-host-permissions";}
 VZKernelRAMSegmentV54 *segment=NULL;bool invoked=false;int32_t nativeReturn=0;
 if(status==VZ_KERNEL_OK){segment=calloc(1,sizeof(*segment));if(!segment)status=VZ_KERNEL_OUT_OF_MEMORY;}
 if(status==VZ_KERNEL_OK && !RAMMutationBeginV54(vm,NULL))status=VZ_KERNEL_BUSY;
 else if(status==VZ_KERNEL_OK) {
  segment->guestAddress=ipa;segment->bytes=ram->bytes;segment->flags=flags;segment->uncertain=true;
  Lock(&vm->mutex);uint64_t previousIPA=ram->guestAddress;
  ram->guestAddress=ipa;ram->segments=segment;ram->mapInFlight=true;RAMRootRefreshV54(ram);
  bool outputValid=RAMDisjointV9(vm,out,sizeof(*out));
  if(!outputValid){ram->segments=NULL;ram->guestAddress=previousIPA;ram->mapInFlight=false;
   RAMRootRefreshV54(ram);RAMMutationEndLockedV54(vm);}
  Unlock(&vm->mutex);
  if(!outputValid){free(segment);EndOperation(&vm->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
  invoked=true;nativeReturn=vm->ops.nativeTrap(vm->ops.context,3,&packet);
  status=nativeReturn?VZ_KERNEL_NATIVE_ERROR:RAMTaskCallerV53(vm)?VZ_KERNEL_OK:VZ_KERNEL_WRONG_THREAD;
  failure=nativeReturn?"map-native":"map-native-owner";
  Lock(&vm->mutex);segment->mapped=status==VZ_KERNEL_OK;segment->uncertain=status!=VZ_KERNEL_OK;
  ram->mapInFlight=false;RAMRootRefreshV54(ram);RAMMutationEndLockedV54(vm);Unlock(&vm->mutex);
 }
 if(!invoked)free(segment);
 RAMResultV9(vm,ram,status,invoked,nativeReturn,out);RAMFailureV52(failure,status,ipa,ram->bytes,invoked);
 EndOperation(&vm->operationInProgress);return status;
}
// Legacy handle cleanup keeps creator-thread and no-CPU admission. It drains
// only surviving segments, and never repeats a completed native4 after retry.
static VZKernelStatus RAMHandleRangeV54(VZKernelRAMV9 *needle,bool unmap,uint64_t flags,VZKernelRAMResultV9 *out) {
 VZKernelVM *vm=NULL;VZKernelRAMV9 *ram=NULL;VZKernelStatus status=RAMAdmitV9(needle,out,&vm,&ram);
 if(status)return status;status=RAMReadyV9(vm,ram);bool invoked=false;int32_t nativeReturn=0;
 if(status==VZ_KERNEL_OK && !unmap && ram->uncertain)status=VZ_KERNEL_BUSY;
 if(status==VZ_KERNEL_OK) {
  // Snapshot the next surviving GPA before each real range operation.
  uint64_t cursor=0;bool first=true;
  for(;;) {
   VZKernelRAMSegmentV54 *g=ram->segments;
   while(g && !first && g->guestAddress<cursor)g=g->next;
   if(!g)break;
   uint64_t ipa=g->guestAddress,bytes=g->bytes;cursor=ipa+bytes;first=false;
   VZKernelRAMResultV9 receipt={0};status=RAMRangeOwnedV54(vm,
    unmap?VZKernelMemoryUnmap:VZKernelMemoryProtect,ipa,bytes,unmap?0:flags,&receipt);
   invoked|=receipt.nativeInvoked;nativeReturn=receipt.nativeReturn;if(status)break;
  }
 }
 RAMResultV9(vm,ram,status,invoked,nativeReturn,out);EndOperation(&vm->operationInProgress);return status;
}
VZKernelStatus VZKernelRAMProtectV9(VZKernelRAMV9 *r,uint64_t flags,VZKernelRAMResultV9 *out) {
 return RAMHandleRangeV54(r,false,flags,out);
}
VZKernelStatus VZKernelRAMUnmapV9(VZKernelRAMV9 *r,VZKernelRAMResultV9 *out) {
 return RAMHandleRangeV54(r,true,0,out);
}
