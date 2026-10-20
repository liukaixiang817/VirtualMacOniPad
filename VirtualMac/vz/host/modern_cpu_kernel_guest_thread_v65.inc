/* Optional PID1 task/thread observer. Layout comes only from exact 25G83
 * accessor/queue/wait instructions. Raw continuation/parameter/event values
 * are never executed, authenticated, stripped, or followed as pointers. */
typedef struct {
 uint64_t process,task,readOnly,taskOffset,limits[2],readOnlyLimits[2],allocationBytes,zoneMap,head,stackBytes;
 uint64_t owners[2];uint32_t pid,taskFlags,suspend[3],processROMultiplier,threadROMultiplier;uint8_t processFlags,name[17];
 uint16_t processROTag;
} VM27GuestThreadTaskV65;
typedef struct {
 uint64_t thread,next,readOnly,tid,event,waitq,continuation,parameter;
 uint64_t owner,task,stackBase,savedContextRaw,userAllocationBase,userStateRaw;uint32_t state;uint16_t threadTag,readOnlyTag;
} VM27GuestThreadRowV65;
static bool VM27GuestThreadTagV65(VM27GuestProcessReaderV63 *r,
 uint64_t zoneMap,uint64_t address,uint16_t *tag) {
 uint64_t offset=(address>>10)&UINT64_C(0xffffffff0);
 if(zoneMap>UINT64_MAX-offset ||
  !VM27GuestProcessPointerV63(zoneMap+offset,2,2))return false;
 return VM27GuestProcessPartV63(r,zoneMap+offset,2,tag);
}
static bool VM27GuestThreadTaskReadV65(VM27GuestProcessReaderV63 *r,
 uint64_t slide,const VM27GuestProcessRowV63 *process,VM27GuestThreadTaskV65 *out,
 bool *invalid) {
 *invalid=false;out->process=process->process;
 if(!VM27GuestProcessPartV63(r,UINT64_C(0xfffffe000a8e9b30)+slide,8,&out->taskOffset) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00077f6b50)+slide,16,out->limits) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00077f6ba0)+slide,16,out->readOnlyLimits) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00077fc9e0)+slide,4,&out->processROMultiplier) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00077fc9d0)+slide,4,&out->threadROMultiplier) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00078bc620)+slide,8,&out->stackBytes) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe000a966108)+slide,8,&out->allocationBytes) ||
  !VM27GuestProcessPartV63(r,UINT64_C(0xfffffe00077f6c00)+slide,8,&out->zoneMap) ||
  !VM27GuestProcessPartV63(r,out->process+0x468,1,&out->processFlags) ||
  !VM27GuestProcessPartV63(r,out->process+0x18,8,&out->readOnly) ||
  !VM27GuestProcessPartV63(r,out->process+0x60,4,&out->pid) ||
  !VM27GuestProcessPartV63(r,out->process+0x5cc,17,out->name))return false;
 *invalid=true;
 if(out->pid!=1 || process->pid!=1 || out->readOnly!=process->readOnly ||
  memcmp(out->name,process->name,17) || memcmp(out->name,"launchd",8) ||
  !(out->processFlags&2) || !out->taskOffset || (out->taskOffset&7) ||
  out->taskOffset>UINT64_C(1048576) || out->allocationBytes>UINT64_C(1048576) ||
  out->taskOffset>out->allocationBytes || out->allocationBytes-out->taskOffset<0x404 ||
  out->process>UINT64_MAX-out->allocationBytes ||
  out->process<out->limits[0] || out->process+out->allocationBytes>out->limits[1] ||
  out->readOnly<out->readOnlyLimits[0] || out->readOnly>=out->readOnlyLimits[1] ||
  out->readOnly>UINT64_MAX-16 || out->readOnly+16>out->readOnlyLimits[1] ||
  (uint32_t)((uint32_t)(0x4000-(out->readOnly&0x3fff))*out->processROMultiplier)>=out->processROMultiplier ||
  !VM27GuestProcessPointerV63(out->readOnly,8,16) ||
  !VM27GuestProcessPointerV63(out->zoneMap,2,2))return false;
 out->task=out->process+out->taskOffset;
 if(!VM27GuestProcessPointerV63(out->task,8,0x404) ||
  out->task-out->taskOffset!=out->process)return false;
 *invalid=false;
 uint64_t taskRO=0;
 if(!VM27GuestThreadTagV65(r,out->zoneMap,out->readOnly,&out->processROTag) ||
  !VM27GuestProcessPartV63(r,out->readOnly,16,out->owners) ||
  !VM27GuestProcessPartV63(r,out->task+0x3d0,8,&taskRO) ||
  !VM27GuestProcessPartV63(r,out->task+0x400,4,&out->taskFlags) ||
  !VM27GuestProcessPartV63(r,out->task+0x50,8,&out->head) ||
  !VM27GuestProcessPartV63(r,out->task+0x80,12,out->suspend))return false;
 *invalid=true;
 if((out->processROTag&0x3ff)!=5 || out->owners[0]!=out->process ||
  out->owners[1]!=out->task || taskRO!=out->readOnly ||
  !(out->taskFlags&UINT32_C(0x800000)) ||
  !VM27GuestProcessPointerV63(out->head,8,8))return false;
 *invalid=false;return true;
}
static bool VM27GuestThreadRowReadV65(VM27GuestProcessReaderV63 *r,
 const VM27GuestThreadTaskV65 *task,uint64_t thread,VM27GuestThreadRowV65 *out,
 bool *invalid) {
 *invalid=true;
 if(!VM27GuestProcessPointerV63(thread,8,0x588) ||
  thread<task->limits[0] || thread>UINT64_MAX-0x588 ||
  thread+0x588>task->limits[1])return false;
 out->thread=thread;*invalid=false;
 if(!VM27GuestThreadTagV65(r,task->zoneMap,thread,&out->threadTag))return false;
 *invalid=true;if((out->threadTag&0x3ff)!=0x1a)return false;
 *invalid=false;
 uint64_t links[3]={0};
 if(!VM27GuestProcessPartV63(r,thread+0x3d8,24,links))return false;
 out->next=links[0];out->readOnly=links[2];*invalid=true;
 if(!VM27GuestProcessPointerV63(out->next,8,8) ||
  !VM27GuestProcessPointerV63(out->readOnly,8,0x30) ||
  out->readOnly<task->readOnlyLimits[0] || out->readOnly>=task->readOnlyLimits[1] ||
  out->readOnly+0x30>task->readOnlyLimits[1] ||
  (uint32_t)((uint32_t)(0x4000-(out->readOnly&0x3fff))*task->threadROMultiplier)>=task->threadROMultiplier)return false;
 *invalid=false;
 if(!VM27GuestThreadTagV65(r,task->zoneMap,out->readOnly,&out->readOnlyTag) ||
  !VM27GuestProcessPartV63(r,out->readOnly,8,&out->owner) ||
  !VM27GuestProcessPartV63(r,out->readOnly+0x28,8,&out->task))return false;
 *invalid=true;
 if((out->readOnlyTag&0x3ff)!=3 || out->owner!=thread || out->task!=task->task)return false;
 *invalid=false;
 uint64_t block[2]={0},user[2]={0};
 if(!VM27GuestProcessPartV63(r,thread+0x4e0,8,&out->tid) ||
  !VM27GuestProcessPartV63(r,thread+0x18,8,&out->event) ||
  !VM27GuestProcessPartV63(r,thread+0x28,8,&out->waitq) ||
  !VM27GuestProcessPartV63(r,thread+0xd0,16,block) ||
  !VM27GuestProcessPartV63(r,thread+0x1c8,4,&out->state) ||
  !VM27GuestProcessPartV63(r,thread+0xe0,8,&out->stackBase) ||
  !VM27GuestProcessPartV63(r,thread+0x148,8,&out->savedContextRaw) ||
  !VM27GuestProcessPartV63(r,thread+0xf8,16,user))return false;
 out->continuation=block[0];out->parameter=block[1];
 out->userAllocationBase=user[0];out->userStateRaw=user[1];return true;
}
static bool VM27GuestThreadTaskSameV65(const VM27GuestThreadTaskV65 *a,
 const VM27GuestThreadTaskV65 *b) {
 return a->process==b->process && a->task==b->task && a->readOnly==b->readOnly &&
  a->taskOffset==b->taskOffset && !memcmp(a->limits,b->limits,16) &&
  !memcmp(a->readOnlyLimits,b->readOnlyLimits,16) &&
  a->processROMultiplier==b->processROMultiplier && a->threadROMultiplier==b->threadROMultiplier &&
  a->stackBytes==b->stackBytes &&
  a->allocationBytes==b->allocationBytes && a->zoneMap==b->zoneMap &&
  a->head==b->head && !memcmp(a->owners,b->owners,16) && a->pid==b->pid &&
  a->taskFlags==b->taskFlags && !memcmp(a->suspend,b->suspend,12) &&
  a->processFlags==b->processFlags && !memcmp(a->name,b->name,17) &&
  a->processROTag==b->processROTag;
}
static bool VM27GuestThreadRowSameV65(const VM27GuestThreadRowV65 *a,
 const VM27GuestThreadRowV65 *b) {
 return a->thread==b->thread && a->next==b->next && a->readOnly==b->readOnly &&
  a->tid==b->tid && a->event==b->event && a->waitq==b->waitq &&
  a->continuation==b->continuation && a->parameter==b->parameter &&
  a->owner==b->owner && a->task==b->task && a->state==b->state &&
  a->stackBase==b->stackBase && a->savedContextRaw==b->savedContextRaw &&
  a->userAllocationBase==b->userAllocationBase && a->userStateRaw==b->userStateRaw &&
  a->threadTag==b->threadTag && a->readOnlyTag==b->readOnlyTag;
}
/* Independent optional subreaders; failure cannot replace thread/process results. */
static bool VM27GuestThreadIdentityV65(VM27GuestProcessReaderV63 *reader,
 uint64_t slide,const VM27GuestProcessRowV63 *process,
 const VM27GuestThreadTaskV65 *task,const VM27GuestThreadRowV65 *row) {
 VM27GuestThreadTaskV65 afterTask={0};VM27GuestThreadRowV65 afterRow={0};bool invalid=false;
 return VM27GuestThreadTaskReadV65(reader,slide,process,&afterTask,&invalid) &&
  VM27GuestThreadTaskSameV65(task,&afterTask) &&
  VM27GuestThreadRowReadV65(reader,&afterTask,row->thread,&afterRow,&invalid) &&
  VM27GuestThreadRowSameV65(row,&afterRow);
}
static bool VM27GuestThreadBytesV65(VM27GuestProcessReaderV63 *reader,
 uint64_t address,size_t bytes,uint8_t *out) {
 for(size_t offset=0;offset<bytes;offset+=64) {
  size_t count=bytes-offset;if(count>64)count=64;
  if(!VM27GuestProcessPartV63(reader,address+offset,count,out+offset))return false;
 }
 return true;
}
static void VM27GuestThreadContextReadV65(const VM27GuestProcessReaderV63 *parent,
 uint64_t slide,const VM27GuestProcessRowV63 *process,
 const VM27GuestThreadTaskV65 *task,const VM27GuestThreadRowV65 *row) {
 const int saved=errno;unsigned reason=1,frameReason=0,frames=0;
 bool known=false,framesComplete=false;uint64_t context=0,fp=0,lr=0,sp=0,limit=0;
 uint8_t before[208]={0},after[208]={0};
 struct {uint64_t address,previous,returnRaw;} staged[8]={0};
 VM27GuestProcessReaderV63 reader=*parent;reader.reads=0;reader.bytes=0;reader.budgetHit=false;
 PendingRunAccessV14 access=*parent->access;RunPostAccessV7 post=*parent->access->post;
 VZKernelLifecycleResult lifecycle=*parent->access->init.lifecycle;
 access.init.lifecycle=&lifecycle;post.lifecycle=&lifecycle;access.post=&post;reader.access=&access;
 if(task->stackBytes<208 || task->stackBytes>UINT64_C(1048576) ||
  (task->stackBytes&15) ||
  !VM27GuestProcessPointerV63(row->stackBase,16,(size_t)task->stackBytes))goto done;
 limit=row->stackBase+task->stackBytes;context=limit-208;reason=2;
 if(!VM27GuestThreadBytesV65(&reader,context,208,before))goto done;
 memcpy(&fp,before+0x50,8);memcpy(&lr,before+0x58,8);memcpy(&sp,before+0x60,8);
 uint64_t frame=fp;
 for(;;) {
  if(!frame){framesComplete=true;break;}
  if(frames==8){frameReason=1;break;}
  if(!VM27GuestProcessPointerV63(frame,16,16) || frame<row->stackBase ||
   frame>context || context-frame<16){frameReason=2;break;}
  if(frames && frame<=staged[frames-1].address){frameReason=3;break;}
  uint64_t pair[2]={0};reason=3;
  if(!VM27GuestProcessPartV63(&reader,frame,16,pair))goto done;
  staged[frames].address=frame;staged[frames].previous=pair[0];
  staged[frames].returnRaw=pair[1];++frames;frame=pair[0];
 }
 reason=4;
 for(unsigned i=0;i<frames;++i) {
  uint64_t pair[2]={0};
  if(!VM27GuestProcessPartV63(&reader,staged[i].address,16,pair) ||
   pair[0]!=staged[i].previous || pair[1]!=staged[i].returnRaw)goto done;
 }
 reason=5;
 if(!VM27GuestThreadIdentityV65(&reader,slide,process,task,row))goto done;
 reason=6;
 if(!VM27GuestThreadBytesV65(&reader,context,208,after) || memcmp(before,after,208) ||
  !VM27RAMReadGenerationStableV54(reader.access,&reader.generation) ||
  !PendingBoundaryV14(reader.access))goto done;
 known=true;reason=0;
done:
 dprintf(2,"[Independent27HV] guest-thread-context known=%u reason=%u readerReason=%u pid=1 tid=%llu thread=0x%016llx stackBase=0x%016llx stackBytes=%llu independentlyDerivedContext=0x%016llx savedContextRaw=0x%016llx lastSavedFPRaw=0x%016llx lastSavedLRRaw=0x%016llx lastSavedSPRaw=0x%016llx frames=%u framesComplete=%u framesPartial=%u frameReason=%u reads=%u bytes=%zu ramGeneration=%llu lastSavedContextNotCurrentExecution=1 pointerAuthenticationKnown=0 nonAtomic=1 extraNativeCalls=0 guestWrites=0\n",
  known,reason,reader.generation.reason,(unsigned long long)row->tid,
  (unsigned long long)row->thread,(unsigned long long)row->stackBase,
  (unsigned long long)task->stackBytes,(unsigned long long)context,
  (unsigned long long)row->savedContextRaw,(unsigned long long)(known?fp:0),
  (unsigned long long)(known?lr:0),(unsigned long long)(known?sp:0),
  known?frames:0,known&&framesComplete,known&&!framesComplete,frameReason,
  reader.reads,reader.bytes,(unsigned long long)reader.generation.ramGeneration);
 if(known)for(unsigned i=0;i<frames;++i)
  dprintf(2,"[Independent27HV] guest-thread-frame ordinal=%u pid=1 tid=%llu frameAddress=0x%016llx previousFPRaw=0x%016llx returnAddressRaw=0x%016llx ownStackOnly=1 lastSavedContextNotCurrentExecution=1 pointerAuthenticationKnown=0 nonAtomic=1\n",
   i,(unsigned long long)row->tid,(unsigned long long)staged[i].address,
   (unsigned long long)staged[i].previous,(unsigned long long)staged[i].returnRaw);
 errno=saved;
}
static void VM27GuestThreadUserStateReadV65(const VM27GuestProcessReaderV63 *parent,
 uint64_t slide,const VM27GuestProcessRowV63 *process,
 const VM27GuestThreadTaskV65 *task,const VM27GuestThreadRowV65 *row) {
 const int saved=errno;unsigned reason=1;bool observed=false;
 bool rawLowAddressMatches=((row->userStateRaw&UINT64_C(0x00007fffffffffff))|
  UINT64_C(0xffff800000000000))==row->userAllocationBase;
 uint64_t zone=0,afterZone=0,pc=0,fp=0;
 uint32_t flavor=0,count=0,pstate=0;uint16_t tag=0,elementBytes=0,afterTag=0,afterElement=0;
 uint8_t before[304]={0},after[304]={0};
 VM27GuestProcessReaderV63 reader=*parent;reader.reads=0;reader.bytes=0;reader.budgetHit=false;
 PendingRunAccessV14 access=*parent->access;RunPostAccessV7 post=*parent->access->post;
 VZKernelLifecycleResult lifecycle=*parent->access->init.lifecycle;
 access.init.lifecycle=&lifecycle;post.lifecycle=&lifecycle;access.post=&post;reader.access=&access;
 if((task->taskFlags&3)!=3 ||
  !VM27GuestProcessPointerV63(row->userAllocationBase,16,304) ||
  row->userAllocationBase<task->limits[0] || row->userAllocationBase+304>task->limits[1])goto done;
 reason=2;
 if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe0007889780)+slide,8,&zone) ||
  !VM27GuestThreadTagV65(&reader,task->zoneMap,row->userAllocationBase,&tag))goto done;
 reason=3;
 if(!VM27GuestProcessPointerV63(zone,8,0x36) ||
  zone!=UINT64_C(0xfffffe000a927b80)+slide+UINT64_C(0xc0)*(tag&0x3ff))goto done;
 reason=4;
 if(!VM27GuestProcessPartV63(&reader,zone+0x34,2,&elementBytes))goto done;
 reason=5;
 if(elementBytes<304 || elementBytes>16384 ||
  row->userAllocationBase>UINT64_MAX-elementBytes ||
  row->userAllocationBase+elementBytes>task->limits[1])goto done;
 reason=6;
 if(!VM27GuestThreadBytesV65(&reader,row->userAllocationBase,304,before))goto done;
 memcpy(&flavor,before,4);memcpy(&count,before+4,4);
 reason=7;if(flavor!=21 || count!=74)goto done;
 memcpy(&fp,before+0xf0,8);
 memcpy(&pc,before+0x108,8);memcpy(&pstate,before+0x110,4);
 reason=8;
 if(!VM27GuestThreadIdentityV65(&reader,slide,process,task,row))goto done;
 reason=9;
 if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe0007889780)+slide,8,&afterZone) ||
  afterZone!=zone ||
  !VM27GuestThreadTagV65(&reader,task->zoneMap,row->userAllocationBase,&afterTag) || afterTag!=tag ||
  !VM27GuestProcessPartV63(&reader,zone+0x34,2,&afterElement) || afterElement!=elementBytes ||
  !VM27GuestThreadBytesV65(&reader,row->userAllocationBase,304,after) || memcmp(before,after,304) ||
  !VM27RAMReadGenerationStableV54(reader.access,&reader.generation) ||
  !PendingBoundaryV14(reader.access))goto done;
 observed=true;reason=0;
done:
 dprintf(2,"[Independent27HV] guest-thread-user-state userStateCandidateBytesObserved=%u reason=%u readerReason=%u pid=1 tid=%llu thread=0x%016llx unsignedAllocationBase=0x%016llx savedStatePointerRaw=0x%016llx rawLowAddressMatchesUnsignedBase=%u zoneDescriptor=0x%016llx zoneTag=0x%04x elementBytes=%u flavor=%u count=%u savedUserPCCandidateRaw=0x%016llx savedUserFPCandidateRaw=0x%016llx savedUserPSTATECandidateRaw=0x%x pointerAuthenticationKnown=0 userPCVerified=0 lastSavedUserStateNotCurrentExecution=1 nonAtomic=1 reads=%u bytes=%zu ramGeneration=%llu extraNativeCalls=0 guestWrites=0\n",
  observed,reason,reader.generation.reason,(unsigned long long)row->tid,
  (unsigned long long)row->thread,(unsigned long long)row->userAllocationBase,
  (unsigned long long)row->userStateRaw,rawLowAddressMatches,(unsigned long long)zone,
  tag,elementBytes,flavor,count,(unsigned long long)(observed?pc:0),
  (unsigned long long)(observed?fp:0),observed?pstate:0,reader.reads,reader.bytes,
  (unsigned long long)reader.generation.ramGeneration);
 if(observed)for(size_t offset=0;offset<304;offset+=64) {
  static const char hex[]="0123456789abcdef";char text[129]={0};
  size_t bytes=304-offset;if(bytes>64)bytes=64;
  for(size_t i=0;i<bytes;++i){text[2*i]=hex[before[offset+i]>>4];text[2*i+1]=hex[before[offset+i]&15];}
  dprintf(2,"[Independent27HV] guest-thread-user-state-data tid=%llu unsignedAllocationBase=0x%016llx offset=%zu bytes=%zu hex=%s rawSavedUserState=1 pointerAuthenticationKnown=0 userPCVerified=0 nonAtomic=1\n",
   (unsigned long long)row->tid,(unsigned long long)row->userAllocationBase,offset,bytes,text);
 }
 errno=saved;
}
static void VM27GuestThreadReadV65(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t slide,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,const VM27GuestProcessRowV63 *process,
 const VM27RunDiagnosticCodeV36 *parentGeneration) {
 const int saved=errno;unsigned reason=1,rows=0;
 bool known=false,complete=false,capped=false,invalid=false;
 VM27GuestProcessReaderV63 reader={0};VM27GuestThreadTaskV65 task={0},afterTask={0};
 VM27GuestThreadRowV65 *staged=NULL;
 PendingRunAccessV14 diagnostic={0};RunPostAccessV7 post={0};
 VZKernelLifecycleResult lifecycle={0};
 if(!a || !q || !a->post || !a->init.lifecycle || !process || process->pid!=1 ||
  !parentGeneration || parentGeneration->reason || !parentGeneration->ramGenerationKnown ||
  (parentGeneration->ramGeneration&1) || slide>UINT64_C(0x40000000) ||
  (slide&0x3fff) || tcr!=UINT64_C(0x000800226511a511))goto done;
 diagnostic=*a;post=*a->post;lifecycle=*a->init.lifecycle;
 diagnostic.init.lifecycle=&lifecycle;post.lifecycle=&lifecycle;diagnostic.post=&post;
 reader.access=&diagnostic;reader.request=q;reader.sctlr=sctlr;reader.tcr=tcr;reader.ttbr=ttbr;
 reader.generation.ramGeneration=parentGeneration->ramGeneration;
 reader.generation.ramGenerationKnown=true;
 reason=2;
 if(!VM27GuestThreadTaskReadV65(&reader,slide,process,&task,&invalid)) {
  if(invalid)reason=3;goto done;
 }
 reason=4;staged=calloc(32,sizeof(*staged));if(!staged)goto done;
 uint64_t node=task.head,sentinel=task.task+0x50;
 while(node!=sentinel) {
  reason=5;
  for(unsigned i=0;i<rows;++i)if(staged[i].thread==node)goto done;
  if(rows==32){capped=true;break;}
  VM27GuestThreadRowV65 row={0};reason=6;
  if(!VM27GuestThreadRowReadV65(&reader,&task,node,&row,&invalid)) {
   if(invalid)reason=7;goto done;
  }
  reason=5;
  for(unsigned i=0;i<rows;++i)
   if((row.tid && row.tid==staged[i].tid) || row.next==staged[i].thread)goto done;
  if(row.next==node)goto done;
  staged[rows++]=row;node=row.next;
 }
 complete=!capped;reason=8;
 if(!VM27GuestThreadTaskReadV65(&reader,slide,process,&afterTask,&invalid) ||
  !VM27GuestThreadTaskSameV65(&task,&afterTask))goto done;
 reason=9;
 for(unsigned i=0;i<rows;++i) {
  VM27GuestThreadRowV65 after={0};
  if(!VM27GuestThreadRowReadV65(&reader,&task,staged[i].thread,&after,&invalid) ||
   !VM27GuestThreadRowSameV65(&staged[i],&after))goto done;
 }
 reason=10;
 {
  uint64_t finalOffset=0,finalHead=0;
  if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a8e9b30)+slide,8,&finalOffset) ||
   finalOffset!=task.taskOffset ||
   !VM27GuestProcessPartV63(&reader,task.task+0x50,8,&finalHead) || finalHead!=task.head ||
   !VM27RAMReadGenerationStableV54(&diagnostic,&reader.generation) ||
   !PendingBoundaryV14(&diagnostic))goto done;
 }
 known=true;reason=0;
done:
 if(reader.budgetHit)reason=11;
 dprintf(2,"[Independent27HV] guest-thread known=%u complete=%u partial=%u reason=%u readerReason=%u capped=%u pid=1 process=0x%016llx task=0x%016llx taskOffset=0x%llx allocationBytes=0x%llx processFlags=0x%x taskFlags=0x%x suspendRaw80=%u suspendRaw84=%u suspendRaw88=%u head=0x%016llx stagedRows=%u rows=%u reads=%u bytes=%zu freshSlide=0x%llx ramGeneration=%llu nonAtomic=1 extraNativeCalls=0 guestWrites=0\n",
  known,known&&complete,known&&!complete,reason,reader.generation.reason,capped,
  (unsigned long long)task.process,(unsigned long long)task.task,
  (unsigned long long)task.taskOffset,(unsigned long long)task.allocationBytes,
  task.processFlags,task.taskFlags,task.suspend[0],task.suspend[1],task.suspend[2],
  (unsigned long long)task.head,rows,known?rows:0,reader.reads,reader.bytes,
  (unsigned long long)slide,(unsigned long long)reader.generation.ramGeneration);
 if(known)for(unsigned i=0;i<rows;++i)
  dprintf(2,"[Independent27HV] guest-thread-row ordinal=%u pid=1 tid=%llu thread=0x%016llx next=0x%016llx readOnly=0x%016llx task=0x%016llx stateRaw=0x%x waitEventRaw=0x%016llx waitqRaw=0x%016llx continuationRaw=0x%016llx parameterRaw=0x%016llx kernelStackBaseRaw=0x%016llx stackBytes=%llu savedContextRaw=0x%016llx threadTag=0x%04x readOnlyTag=0x%04x nonAtomic=1\n",
   i,(unsigned long long)staged[i].tid,(unsigned long long)staged[i].thread,
   (unsigned long long)staged[i].next,(unsigned long long)staged[i].readOnly,
   (unsigned long long)staged[i].task,staged[i].state,(unsigned long long)staged[i].event,
   (unsigned long long)staged[i].waitq,(unsigned long long)staged[i].continuation,
   (unsigned long long)staged[i].parameter,(unsigned long long)staged[i].stackBase,
   (unsigned long long)task.stackBytes,(unsigned long long)staged[i].savedContextRaw,
   staged[i].threadTag,staged[i].readOnlyTag);
 if(known && rows) {
  VM27GuestThreadContextReadV65(&reader,slide,process,&task,&staged[0]);
  VM27GuestThreadUserStateReadV65(&reader,slide,process,&task,&staged[0]);
 }
 free(staged);errno=saved;
}
