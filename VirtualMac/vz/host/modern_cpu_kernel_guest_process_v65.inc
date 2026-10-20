/* Exact 25G83 proc_find/proc_name data consumers, after the caller has matched
 * this boot's KC/UUID/anchor and derived slide. Read-only, bounded, non-atomic.
 * A private access/post/lifecycle copy prevents this optional observer from
 * replacing the original msgbuf diagnostic's generation, status or result. */
typedef struct {
 PendingRunAccessV14 *access;const VZKernelRunPendingRequestV14 *request;
 uint64_t sctlr,tcr,ttbr;VM27RunDiagnosticCodeV36 generation;
 unsigned reads;size_t bytes;bool budgetHit;
} VM27GuestProcessReaderV63;
typedef struct {
 uint64_t node,process,next,readOnly,tagAddress;uint32_t pid,bucket;
 uint16_t tag;uint8_t name[17];
} VM27GuestProcessRowV63;
static bool VM27GuestProcessPointerV63(uint64_t p,uint64_t alignment,size_t bytes) {
 return bytes && (p>>47)==UINT64_C(0x1ffff) && !(p&(alignment-1)) &&
  p<=UINT64_MAX-(uint64_t)bytes &&
  ((p+(uint64_t)bytes-1)>>47)==UINT64_C(0x1ffff);
}
static bool VM27GuestProcessPartV63(VM27GuestProcessReaderV63 *r,
 uint64_t va,size_t bytes,void *out) {
 if(!bytes || bytes>64 || !VM27GuestProcessPointerV63(va,1,bytes))return false;
 if(r->reads>=4096){r->budgetHit=true;return false;}
 ++r->reads;r->bytes+=bytes;
 VM27RunDiagnosticCodeV36 part={0};
 if(!VM27MsgbufVirtualV59(r->access,r->request,va,r->sctlr,r->tcr,r->ttbr,
  bytes,&r->generation,&part))return false;
 memcpy(out,part.bytes,bytes);return true;
}
static uint32_t VM27GuestProcessHashV63(uint32_t pid) {
 uint32_t h=pid^(pid>>16);h*=UINT32_C(0x7feb352d);
 h^=h>>15;h*=UINT32_C(0x846ca68b);return h^(h>>16);
}
static bool VM27GuestProcessRowReadV63(VM27GuestProcessReaderV63 *r,
 uint64_t node,uint32_t bucket,uint64_t mask,const uint64_t limits[2],
 uint64_t allocationBytes,uint64_t zoneMap,VM27GuestProcessRowV63 *out,
 bool *invalid) {
 *invalid=true;
 if(!VM27GuestProcessPointerV63(node,8,8) || node<0xa0)return false;
 uint64_t process=node-0xa0;
 if(!VM27GuestProcessPointerV63(process,8,0x5dd) ||
  process>UINT64_MAX-allocationBytes || process<limits[0] ||
  process+allocationBytes<limits[0] || process+allocationBytes>limits[1])return false;
 uint64_t tagOffset=(process>>10)&UINT64_C(0xffffffff0);
 if(zoneMap>UINT64_MAX-tagOffset)return false;
 uint64_t tagAddress=zoneMap+tagOffset;
 if(!VM27GuestProcessPointerV63(tagAddress,2,2))return false;
 out->node=node;out->process=process;out->bucket=bucket;out->tagAddress=tagAddress;
 *invalid=false;
 if(!VM27GuestProcessPartV63(r,tagAddress,2,&out->tag))return false;
 *invalid=true;if((out->tag&0x3ff)!=0x19)return false;
 *invalid=false;
 if(!VM27GuestProcessPartV63(r,process+0x18,8,&out->readOnly) ||
  !VM27GuestProcessPartV63(r,process+0x60,4,&out->pid) ||
  !VM27GuestProcessPartV63(r,node,8,&out->next))return false;
 *invalid=true;
 if(out->pid>0x3fffff ||
  (VM27GuestProcessHashV63(out->pid)&(uint32_t)mask)!=bucket ||
  !VM27GuestProcessPointerV63(out->readOnly,8,8) ||
  (out->next && !VM27GuestProcessPointerV63(out->next,8,8)))return false;
 uint64_t owner=0;*invalid=false;
 if(!VM27GuestProcessPartV63(r,out->readOnly,8,&owner))return false;
 *invalid=true;if(owner!=process)return false;
 *invalid=false;
 if(!VM27GuestProcessPartV63(r,process+0x5cc,17,out->name))return false;
 return true;
}
static bool VM27GuestProcessRowSameV63(const VM27GuestProcessRowV63 *a,
 const VM27GuestProcessRowV63 *b) {
 return a->node==b->node && a->process==b->process && a->next==b->next &&
  a->readOnly==b->readOnly && a->tagAddress==b->tagAddress && a->pid==b->pid &&
  a->bucket==b->bucket && a->tag==b->tag && !memcmp(a->name,b->name,17);
}
#include "modern_cpu_kernel_guest_thread_v65.inc"
static void VM27GuestProcessReadV65(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t slide,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,const VM27RunDiagnosticCodeV36 *parentGeneration) {
 const int saved=errno;unsigned reason=1,rows=0,traversedBuckets=0;
 bool known=false,complete=false,capped=false,invalid=false,footer=false;
 uint64_t word=0,afterWord=0,table=0,mask=0,buckets=0,limits[2]={0},
  allocationBytes=0,zoneMap=0;uint64_t *heads=NULL;
 VM27GuestProcessRowV63 *staged=NULL;
 VM27GuestProcessReaderV63 reader={0};
 PendingRunAccessV14 diagnostic={0};RunPostAccessV7 post={0};
 VZKernelLifecycleResult lifecycle={0};
 if(!a || !q || !a->post || !a->init.lifecycle || !parentGeneration ||
  parentGeneration->reason || !parentGeneration->ramGenerationKnown ||
  (parentGeneration->ramGeneration&1) || slide>UINT64_C(0x40000000) ||
  (slide&0x3fff) || tcr!=UINT64_C(0x000800226511a511))goto done;
 diagnostic=*a;post=*a->post;lifecycle=*a->init.lifecycle;
 diagnostic.init.lifecycle=&lifecycle;post.lifecycle=&lifecycle;diagnostic.post=&post;
 reader.access=&diagnostic;reader.request=q;reader.sctlr=sctlr;reader.tcr=tcr;reader.ttbr=ttbr;
 reader.generation.ramGeneration=parentGeneration->ramGeneration;
 reader.generation.ramGenerationKnown=true;
 reason=2;
 if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a9cb5d0)+slide,8,&word) ||
  !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe00077f6b50)+slide,16,limits) ||
  !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a966108)+slide,8,&allocationBytes) ||
  !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe00077f6c00)+slide,8,&zoneMap))goto done;
 reason=3;
 mask=UINT64_MAX>>((word>>48)&63);table=word|UINT64_C(0x00ff000000000000);
 if(mask>=8192)goto done;buckets=mask+1;
 if(!VM27GuestProcessPointerV63(table,8,(size_t)buckets*8))goto done;
 reason=4;
 if(!VM27GuestProcessPointerV63(limits[0],8,1) ||
  !VM27GuestProcessPointerV63(limits[1],8,1) || limits[0]>=limits[1] ||
  allocationBytes<0x5dd || allocationBytes>UINT64_C(1048576) ||
  !VM27GuestProcessPointerV63(zoneMap,2,2))goto done;
 reason=5;heads=calloc((size_t)buckets,sizeof(*heads));
 staged=calloc(128,sizeof(*staged));if(!heads || !staged)goto done;
 reason=6;
 for(uint64_t bucket=0;bucket<buckets;bucket+=8) {
  size_t count=(size_t)(buckets-bucket);if(count>8)count=8;
  if(!VM27GuestProcessPartV63(&reader,table+bucket*8,count*8,heads+bucket))goto done;
 }
 for(uint64_t bucket=0;bucket<buckets;++bucket) {
  uint64_t node=heads[bucket];unsigned chain=0;
  while(node) {
   reason=9;
   for(unsigned i=0;i<rows;++i)if(staged[i].node==node)goto done;
   if(rows==128 || chain==128){capped=true;goto guards;}
   VM27GuestProcessRowV63 row={0};reason=8;
   if(!VM27GuestProcessRowReadV63(&reader,node,(uint32_t)bucket,mask,limits,
    allocationBytes,zoneMap,&row,&invalid)){if(invalid)reason=7;goto done;}
   reason=9;
   for(unsigned i=0;i<rows;++i)
    if(staged[i].pid==row.pid || (row.next && staged[i].node==row.next))goto done;
   if(row.next==node)goto done;
   staged[rows++]=row;++chain;node=row.next;
  }
  ++traversedBuckets;
 }
 complete=true;
guards:
 reason=10;
 {
  uint64_t afterLimits[2]={0},afterAllocation=0,afterZoneMap=0;
  if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a9cb5d0)+slide,8,&afterWord) ||
   afterWord!=word ||
   !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe00077f6b50)+slide,16,afterLimits) ||
   memcmp(afterLimits,limits,16) ||
   !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a966108)+slide,8,&afterAllocation) ||
   afterAllocation!=allocationBytes ||
   !VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe00077f6c00)+slide,8,&afterZoneMap) ||
   afterZoneMap!=zoneMap)goto done;
 }
 reason=11;
 for(uint64_t bucket=0;bucket<buckets;bucket+=8) {
  uint64_t afterHeads[8]={0};size_t count=(size_t)(buckets-bucket);if(count>8)count=8;
  if(!VM27GuestProcessPartV63(&reader,table+bucket*8,count*8,afterHeads) ||
   memcmp(afterHeads,heads+bucket,count*8))goto done;
 }
 reason=12;
 for(unsigned i=0;i<rows;++i) {
  VM27GuestProcessRowV63 after={0};
  if(!VM27GuestProcessRowReadV63(&reader,staged[i].node,staged[i].bucket,mask,
   limits,allocationBytes,zoneMap,&after,&invalid) ||
   !VM27GuestProcessRowSameV63(&staged[i],&after))goto done;
 }
 reason=13;
 if(!VM27GuestProcessPartV63(&reader,UINT64_C(0xfffffe000a9cb5d0)+slide,8,&afterWord) ||
  afterWord!=word || !VM27RAMReadGenerationStableV54(&diagnostic,&reader.generation) ||
  !PendingBoundaryV14(&diagnostic))goto done;
 footer=true;known=true;reason=0;
done:
 if(reader.budgetHit)reason=14;
 dprintf(2,"[Independent27HV] guest-process known=%u complete=%u partial=%u reason=%u readerReason=%u footer=%u capped=%u packed=0x%016llx table=0x%016llx buckets=%llu traversedBuckets=%u stagedRows=%u rows=%u reads=%u bytes=%zu freshSlide=0x%llx ramGeneration=%llu nonAtomic=1 extraNativeCalls=0 guestWrites=0\n",
  known,known&&complete,known&&!complete,reason,reader.generation.reason,footer,capped,
  (unsigned long long)word,(unsigned long long)table,(unsigned long long)buckets,
  traversedBuckets,rows,known?rows:0,reader.reads,reader.bytes,
  (unsigned long long)slide,(unsigned long long)reader.generation.ramGeneration);
 if(known)for(unsigned i=0;i<rows;++i) {
  static const char hex[]="0123456789abcdef";char nameHex[35]={0},nameASCII[18]={0};
  bool ascii=true,terminated=false;
  for(unsigned j=0;j<17;++j) {
   uint8_t c=staged[i].name[j];nameHex[2*j]=hex[c>>4];nameHex[2*j+1]=hex[c&15];
   if(!terminated) {
    if(!c)terminated=true;
    else if(c>=0x21 && c<=0x7e && c!='"' && c!='\\')nameASCII[j]=(char)c;
    else ascii=false;
   }
  }
  dprintf(2,"[Independent27HV] guest-process-row ordinal=%u pid=%u nameASCII=%s nameHex=%s process=0x%016llx readOnly=0x%016llx node=0x%016llx next=0x%016llx bucket=%u zoneTag=0x%04x nonAtomic=1\n",
   i,staged[i].pid,ascii?nameASCII:"<hex>",nameHex,
   (unsigned long long)staged[i].process,(unsigned long long)staged[i].readOnly,
   (unsigned long long)staged[i].node,(unsigned long long)staged[i].next,
   staged[i].bucket,staged[i].tag);
 }
 if(known && complete)for(unsigned i=0;i<rows;++i)if(staged[i].pid==1) {
  VM27GuestThreadReadV65(a,q,slide,sctlr,tcr,ttbr,&staged[i],&reader.generation);break;
 }
 free(staged);free(heads);errno=saved;
}
