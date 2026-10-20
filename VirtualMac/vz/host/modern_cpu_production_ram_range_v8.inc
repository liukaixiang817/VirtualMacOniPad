static void FreeMapsProductionV8(ProductionMapV1 *m) {
 while(m){ProductionMapV1 *next=m->next;free(m);m=next;}
}
static bool AppendMapProductionV8(ProductionMapV1 ***tail,const ProductionMapV1 *source,
 uint64_t start,uint64_t end,bool target) {
 if(start==end)return true;
 ProductionMapV1 *m=calloc(1,sizeof(*m));if(!m)return false;
 *m=*source;m->next=NULL;m->packet.hostAddress+=start-source->packet.guestAddress;
 m->packet.guestAddress=start;m->packet.bytes=end-start;m->target=target;
 if(target)m->uncertain=true;
 **tail=m;*tail=&m->next;return true;
}
static void CoalesceMapsProductionV8(ProductionMapV1 *m) {
 while(m && m->next) {
  ProductionMapV1 *next=m->next;
  if(!m->target && !next->target && m->mapped==next->mapped && m->uncertain==next->uncertain &&
   m->packet.flags==next->packet.flags && m->packet.spaceWord==next->packet.spaceWord &&
   m->packet.guestAddress+m->packet.bytes==next->packet.guestAddress &&
   m->packet.hostAddress+m->packet.bytes==next->packet.hostAddress) {
   m->packet.bytes+=next->packet.bytes;m->next=next->next;free(next);
  }else m=next;
 }
}
// Called under ProductionMutex. This is metadata and actual self permissions,
// never a substituted kernel protect or a fabricated successful unmap.
static bool ProtectCoverageProductionV8(const VZKernelMemoryPacket *q) {
 uint64_t cursor=q->guestAddress,end=cursor+q->bytes;
 while(cursor<end) {
  ProductionMapV1 *found=NULL;unsigned matches=0;
  for(ProductionMapV1 *m=ProductionV1.maps;m;m=m->next)
   if(m->packet.guestAddress<=cursor && cursor-m->packet.guestAddress<m->packet.bytes){found=m;++matches;}
  if(matches!=1 || !found || !found->mapped || found->uncertain)return false;
  uint64_t stop=found->packet.guestAddress+found->packet.bytes;if(stop>end)stop=end;
  uint64_t delta=cursor-found->packet.guestAddress;
  if(delta>UINTPTR_MAX-found->packet.hostAddress ||
   !VM27CPUSelfMappedRangeV1((const void *)(uintptr_t)(found->packet.hostAddress+delta),
    (size_t)(stop-cursor),(q->flags&UINT64_C(2))!=0,NULL))return false;
  cursor=stop;
 }
 return true;
}
// Takes the existing Production mutex on entry and always releases it.
// The exact native4/5 packet executes once, even if native4 covers known holes.
static int32_t NativeRangeProductionV8(uint64_t op,const VZKernelMemoryPacket *q) {
 if(op==5 && !ProtectCoverageProductionV8(q)){UnlockProductionV1();return PRODUCTION_BAD_V1;}
 uint64_t start=q->guestAddress,end=start+q->bytes;
 ProductionMapV1 *staged=NULL,**tail=&staged;bool allocated=true;
 for(ProductionMapV1 *m=ProductionV1.maps;m && allocated;m=m->next) {
  uint64_t a=m->packet.guestAddress,b=a+m->packet.bytes;
  if(start>=b || end<=a)allocated=AppendMapProductionV8(&tail,m,a,b,false);
  else {
   uint64_t lo=start>a?start:a,hi=end<b?end:b;
   allocated=AppendMapProductionV8(&tail,m,a,lo,false) &&
    AppendMapProductionV8(&tail,m,lo,hi,true) && AppendMapProductionV8(&tail,m,hi,b,false);
  }
 }
 if(!allocated){FreeMapsProductionV8(staged);UnlockProductionV1();return PRODUCTION_BUSY_V1;}
 ProductionV1.pendingMaps=staged;ProductionV1.vmMutation=true;UnlockProductionV1();
 // Native worker owns real VM-map locks, stage-2 updates and synchronization.
 // No live CPU is destroyed, no host bytes are freed and no map is replayed.
 VZKernelMemoryPacket packet=*q;int32_t result=VM27ProductionNativeTrapV1(op,&packet);
 LockProductionV1();ProductionMapV1 **link=&staged;
 while(*link) {
  ProductionMapV1 *m=*link;
  if(m->target && !result && op==4){*link=m->next;free(m);continue;}
  if(m->target){m->target=false;m->uncertain=result!=0;if(!result){m->mapped=true;m->packet.flags=q->flags;}}
  link=&m->next;
 }
 CoalesceMapsProductionV8(staged);
 ProductionMapV1 *old=ProductionV1.maps;ProductionV1.maps=staged;ProductionV1.pendingMaps=NULL;
 ProductionV1.vmMutation=false;FreeMapsProductionV8(old);UnlockProductionV1();return result;
}
