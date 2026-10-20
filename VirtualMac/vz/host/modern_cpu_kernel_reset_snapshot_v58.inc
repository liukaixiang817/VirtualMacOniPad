// Only the first two actual RESET/RESET2 exits reach this observer. Each keeps
// the existing owner/post-return lease and a separate diagnostic receipt.
static _Atomic unsigned VM27ResetSnapshotsV58;
static bool VM27ResetSnapshotAddressV57(uint64_t address,size_t bytes,
 uint64_t sctlr,uint64_t tcr) {
 if(!bytes || address>UINT64_MAX-bytes || (sctlr&(UINT64_C(1)<<25)))return false;
 if(!(sctlr&1))return address+bytes<=(UINT64_C(1)<<36);
 if(tcr==UINT64_C(0x000800226511a511))
  return (address>>47)==UINT64_C(0x1ffff) && ((address+bytes-1)>>47)==UINT64_C(0x1ffff);
 return tcr==UINT64_C(0x001800616556a516) && address+bytes<=(UINT64_C(1)<<42);
}
static void VM27ResetSnapshotReadV57(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t address,size_t bytes,
 const uint64_t sys[6],VM27RunDiagnosticCodeV36 *out) {
 out->reason=2;out->virtualAddress=address;
 if(!VM27ResetSnapshotAddressV57(address,bytes,sys[2],sys[3]))return;
 if(sys[2]&1)VM27RunDiagnosticVirtualReadV37(a,q,address,sys[2],sys[3],
  sys[sys[3]==UINT64_C(0x000800226511a511)?5:4],bytes,false,out);
 else VM27RunDiagnosticRAMReadV37(a,q,address,bytes,out);
}
#include "modern_cpu_kernel_panic_prefix_v58.inc"

static void VM27ResetSnapshotV58(PendingRunAccessV14 *access,
 const VZKernelRunPendingRequestV14 *q,const VZKernelRunStepReceiptV7 *step,
 uint64_t x0,uint32_t cpsr) {
 if(x0!=UINT64_C(0x84000009) && x0!=UINT64_C(0xc4000009) &&
  x0!=UINT64_C(0x84000012) && x0!=UINT64_C(0xc4000012))return;
 const int saved=errno;
 unsigned ordinal=VM27RunDiagnosticReserveV29(&VM27ResetSnapshotsV58,2);
 if(!ordinal){errno=saved;return;}
 VZKernelLifecycleResult lifecycle=*access->init.lifecycle;
 RunPostAccessV7 post=*access->post;post.lifecycle=&lifecycle;
 PendingRunAccessV14 a=*access;a.init.lifecycle=&lifecycle;a.post=&post;
 bool owned=PendingRequestOwnedV14(a.init.cpu,q)==VZ_KERNEL_OK && PendingBoundaryV14(&a);
 uint64_t pc=0,fp=0,lr=0,callee[10]={0};unsigned known=0,calleeKnown=0;
 if(owned) {
  if(GICPostFieldV20(&a,0x108,false,&pc))known|=1;
  if(GICPostFieldV20(&a,0xf0,false,&fp))known|=2;
  if(GICPostFieldV20(&a,0xf8,false,&lr))known|=4;
  for(unsigned i=0;i<10;++i)
   if(GICPostFieldV20(&a,8+8*(19+i),false,&callee[i]))calleeKnown|=1u<<i;
 }
 dprintf(2,"[Independent27HV] reset-snapshot ordinal=%u id=%llu epoch=%llu generation=%llu owner=%llu token=%llu X0=0x%016llx CPSR=0x%08x ESR=0x%08x owned=%u known=0x%x PC=0x%016llx FP=0x%016llx rawLR=0x%016llx guestPACStripped=0 originalHVCResultPreserved=1\n",
  ordinal,(unsigned long long)q->expectedPublicIdentity,(unsigned long long)q->expectedVMEpoch,
  (unsigned long long)q->expectedCPUGeneration,(unsigned long long)q->expectedOwnerThread,
  (unsigned long long)post.token,(unsigned long long)x0,cpsr,step->nativeValues.syndrome32,
  owned,known,(unsigned long long)pc,(unsigned long long)fp,(unsigned long long)lr);
 for(unsigned group=0;group<2;++group) {
  unsigned i=group*5;
  dprintf(2,"[Independent27HV] reset-callee ordinal=%u known=0x%03x firstRegister=%u values=%016llx,%016llx,%016llx,%016llx,%016llx\n",
   ordinal,calleeKnown,19+i,(unsigned long long)callee[i],(unsigned long long)callee[i+1],
   (unsigned long long)callee[i+2],(unsigned long long)callee[i+3],(unsigned long long)callee[i+4]);
 }
 const uint32_t identifiers[]={0xc208,0xe208,0xc080,0xc102,0xc100,0xc101};
 uint64_t sys[6]={0};unsigned sysKnown=0;VZKernelStatus sysStatus[6];
 VM27RunDiagnosticSYSV36 sysAccess={.access=&a,.syncStatus=VZ_KERNEL_OK};
 VZKernelInitAccess sysPort={&sysAccess,VM27RunDiagnosticSYSReadV36,VM27RunDiagnosticSYSWriteV36};
 VZKernelSysFeatureCache featureCache={0};
 for(unsigned i=0;i<6;++i) {
  VZKernelSysRequest request={1,q->validatedKernelProfile,q->expectedOwnerThread,
   q->expectedCPUGeneration,q->expectedReturnedSlotWord,q->nativeHVISA,VZ_KERNEL_SYS_READ,identifiers[i],0};
  VZKernelSysReceipt receipt={0};sysStatus[i]=owned?PendingRequestOwnedV14(a.init.cpu,q):VZ_KERNEL_NOT_LIVE;
  if(sysStatus[i]==VZ_KERNEL_OK && PendingBoundaryV14(&a))
   sysStatus[i]=VZKernelSysApplyVerifiedRouteV3(&request,&sysPort,&featureCache,&sys[i],&receipt,VM27RunDiagnosticSYSSyncV36);
  else if(sysStatus[i]==VZ_KERNEL_OK)sysStatus[i]=a.init.boundaryStatus;
  if(sysStatus[i]==VZ_KERNEL_OK && !PendingBoundaryV14(&a))sysStatus[i]=a.init.boundaryStatus;
  if(sysStatus[i]==VZ_KERNEL_OK)sysKnown|=1u<<i;
 }
 // A failed actual lazy sync makes all SYS-derived walking unavailable. Its
 // real status remains only in the local receipt, never the original Run.
 if(sysAccess.syncAttempted && sysAccess.syncStatus!=VZ_KERNEL_OK)sysKnown=0;
 bool profile=!(sys[2]&1) || sys[3]==UINT64_C(0x000800226511a511) ||
  sys[3]==UINT64_C(0x001800616556a516);
 bool eligible=owned && sysKnown==0x3f && (cpsr&0xc)==4 && !(cpsr&0x10) &&
  !(sys[2]&(UINT64_C(1)<<25)) && profile && PendingBoundaryV14(&a);
 dprintf(2,"[Independent27HV] reset-sys ordinal=%u known=0x%x statuses=%u,%u,%u,%u,%u,%u SP0=%016llx SP1=%016llx SCTLR=%016llx TCR=%016llx TTBR0=%016llx TTBR1=%016llx syncAttempted=%u syncInvoked=%u syncStatus=%u syncNativeReturn=0x%08x walkEligible=%u maximumNewNative8Calls=1\n",
  ordinal,sysKnown,(unsigned)sysStatus[0],(unsigned)sysStatus[1],(unsigned)sysStatus[2],
  (unsigned)sysStatus[3],(unsigned)sysStatus[4],(unsigned)sysStatus[5],
  (unsigned long long)sys[0],(unsigned long long)sys[1],(unsigned long long)sys[2],
  (unsigned long long)sys[3],(unsigned long long)sys[4],(unsigned long long)sys[5],
  sysAccess.syncAttempted,sysAccess.syncInvoked,(unsigned)sysAccess.syncStatus,
  (unsigned)sysAccess.syncNativeReturn,eligible);
 unsigned attemptedPayload=0,completedPayload=0,frames=0,candidates=0;
 if(eligible && (known&2)) {
  uint64_t current=fp,seen[8]={0};
  for(unsigned frame=0;frame<8;++frame) {
   unsigned stop=0;
   if(!current)stop=1;
   else if((current&15) || !VM27ResetSnapshotAddressV57(current,16,sys[2],sys[3]))stop=2;
   for(unsigned j=0;j<frame && !stop;++j)if(current==seen[j])stop=3;
   if(stop) {
    dprintf(2,"[Independent27HV] reset-frame ordinal=%u index=%u known=0 stop=%u rawFP=0x%016llx\n",ordinal,frame,stop,(unsigned long long)current);break;
   }
   seen[frame]=current;VM27RunDiagnosticCodeV36 pair={.reason=2};attemptedPayload+=16;
   VM27ResetSnapshotReadV57(&a,q,current,16,sys,&pair);
   uint64_t next=0,returnAddress=0;
   if(!pair.reason){memcpy(&next,pair.bytes,8);memcpy(&returnAddress,pair.bytes+8,8);completedPayload+=16;++frames;}
   dprintf(2,"[Independent27HV] reset-frame ordinal=%u index=%u known=%u reason=%u rawFP=0x%016llx rawNextFP=0x%016llx rawSavedLR=0x%016llx bytes=%u ramGenerationKnown=%u ramGeneration=%llu softwareWalkOnly=1 guestPACStripped=0\n",
    ordinal,frame,!pair.reason,pair.reason,(unsigned long long)current,(unsigned long long)next,
    (unsigned long long)returnAddress,pair.reason?0u:pair.actualBytes,pair.ramGenerationKnown,(unsigned long long)pair.ramGeneration);
   if(pair.reason)break;
   if(next<=current) {
    dprintf(2,"[Independent27HV] reset-frame-stop ordinal=%u index=%u stop=nonforward rawNextFP=0x%016llx\n",ordinal,frame,(unsigned long long)next);break;
   }
   current=next;
  }
 }
 if(eligible) {
  uint64_t selected[2]={0};static const char hex[]="0123456789abcdef";
  for(unsigned i=0;i<10 && candidates<2;++i) {
   if(!(calleeKnown&(1u<<i)) || !callee[i] || !VM27ResetSnapshotAddressV57(callee[i],64,sys[2],sys[3]) ||
    (candidates && selected[0]==callee[i]))continue;
   selected[candidates++]=callee[i];VM27RunDiagnosticCodeV36 data={.reason=2};attemptedPayload+=64;
   VM27ResetSnapshotReadV57(&a,q,callee[i],64,sys,&data);
   char text[129]={0};unsigned nulAt=64,printablePrefix=0;
   if(!data.reason) {
    completedPayload+=64;
    for(unsigned j=0;j<64;++j) {
     unsigned value=data.bytes[j];text[2*j]=hex[value>>4];text[2*j+1]=hex[value&15];
     if(!value && nulAt==64)nulAt=j;
    }
    while(printablePrefix<64 && data.bytes[printablePrefix]>=32 && data.bytes[printablePrefix]<=126)++printablePrefix;
   }
   dprintf(2,"[Independent27HV] reset-data-candidate ordinal=%u register=%u known=%u reason=%u VA=0x%016llx bytes=%u firstNUL=%u printablePrefix=%u hex=%s possibleTextOnly=1 panicStringNotEstablished=1\n",
    ordinal,19+i,!data.reason,data.reason,(unsigned long long)callee[i],data.reason?0u:data.actualBytes,nulAt,printablePrefix,text);
   if(i==4 && !data.reason && data.actualBytes==64)
    VM27ResetPanicPrefixV58(&a,q,ordinal,callee[i],sys,&data,&attemptedPayload,&completedPayload);
  }
 }
 dprintf(2,"[Independent27HV] reset-snapshot-end ordinal=%u frames=%u dataCandidates=%u attemptedPayloadBytes=%u completedPayloadBytes=%u payloadLimit=768 pageTableDescriptorsExcluded=1 crossCPUAtomicSnapshotClaimed=0 originalRunReceiptPreserved=1\n",
  ordinal,frames,candidates,attemptedPayload,completedPayload);
 errno=saved;
}
