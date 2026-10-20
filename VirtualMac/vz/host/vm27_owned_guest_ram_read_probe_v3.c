/* Read-only diagnosis of one currently owned VMM, not a CPU implementation.
 * The current Root handoff and CPU-observed RAM mapping/TTBR/slide are pinned by the
 * host controller and again here. No remote calls, writes, suspend or signals.
 * Process offsets are from modern_cpu_kernel_guest_process_v65.inc (25G83).
 * Optional WindowServer/loginwindow task/thread fields reuse thread_v65; all
 * base process/msgbuf results remain independent and run first.
 */
#include <mach/mach.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static mach_port_t target;
static unsigned reads;
static size_t total;
static uint64_t bias;
static uint64_t root;
static uint64_t slide;
static bool physical(uint64_t gpa,size_t n,void *out) {
 if(!n || n>16384 || reads>=16384 || total+n>1048576 ||
    gpa<UINT64_C(0x70000000) || gpa>=UINT64_C(0x270a00000) ||
    n>UINT64_C(0x270a00000)-gpa)return false;
 ++reads;total+=n;
 vm_size_t got=0;
 kern_return_t k=vm_read_overwrite(target,(vm_address_t)(gpa+bias),n,(vm_address_t)out,&got);
 if(k || got!=n){fprintf(stderr,"RAM_READ_FAILED gpa=0x%llx size=%zu kr=%d got=%zu\n",gpa,n,k,(size_t)got);return false;}
 return true;
}
static bool translate(uint64_t va,uint64_t *gpa) {
 if((va>>47)!=UINT64_C(0x1ffff))return false;
 uint64_t table=root;
 for(unsigned level=1;level<=3;++level) {
  unsigned shift=14+11*(3-level);uint64_t d=0;
  if(!physical(table+8*((va>>shift)&2047),8,&d) || (d&0x3000))return false;
  unsigned type=(unsigned)(d&3);uint64_t base=d&UINT64_C(0x0000ffffffffc000);
  if(level<3 && type==3){table=base;continue;}
  if(!((level==2 && type==1)||(level==3 && type==3)) || !(d&(1ull<<10)))return false;
  uint64_t low=(1ull<<shift)-1;if(base&low)return false;
  *gpa=base|(va&low);return true;
 }
 return false;
}
static bool virtual_read(uint64_t va,size_t n,void *out) {
 if(!n || n>16384 || va>UINT64_MAX-n)return false;
 for(size_t at=0;at<n;) {
  uint64_t gpa=0;if(!translate(va+at,&gpa))return false;
  size_t count=0x4000-((va+at)&0x3fff);if(count>n-at)count=n-at;
  if(!physical(gpa,count,(char*)out+at))return false;at+=count;
 }
 return true;
}
static bool pointer(uint64_t p,size_t n){return n && (p>>47)==UINT64_C(0x1ffff) && !(p&7) && p<=UINT64_MAX-n;}
static uint32_t hash_pid(uint32_t pid){uint32_t h=pid^(pid>>16);h*=0x7feb352d;h^=h>>15;h*=0x846ca68b;return h^(h>>16);}
typedef struct {uint64_t node,process,next,ro;uint32_t pid,bucket;uint16_t tag;char name[18];} Row;
static bool row_read(uint64_t node,uint32_t bucket,uint64_t mask,uint64_t zone,
 uint64_t limits[2],uint64_t allocation,Row *r) {
 if(!pointer(node,8)||node<0xa0)return false;
 r->node=node;r->process=node-0xa0;r->bucket=bucket;
 if(r->process<limits[0] || r->process>UINT64_MAX-allocation || r->process+allocation>limits[1])return false;
 uint64_t tagAt=zone+((r->process>>10)&UINT64_C(0xffffffff0));uint64_t owner=0;
 if(!virtual_read(tagAt,2,&r->tag)||(r->tag&0x3ff)!=0x19 ||
    !virtual_read(r->process+0x18,8,&r->ro)||!pointer(r->ro,8)||
    !virtual_read(r->ro,8,&owner)||owner!=r->process||
    !virtual_read(r->process+0x60,4,&r->pid)||r->pid>0x3fffff||
    (hash_pid(r->pid)&mask)!=bucket||!virtual_read(node,8,&r->next)||
    (r->next&&!pointer(r->next,8))||!virtual_read(r->process+0x5cc,17,r->name))return false;
 return true;
}
typedef struct { Row row; uint64_t mask,zone,limits[2],allocation; unsigned matches; } SelectedProcess;
static SelectedProcess selected[2];
static int allowed_process(const char *name) {
 if(!memcmp(name,"WindowServer",13))return 0;
 if(!memcmp(name,"loginwindow",12))return 1;
 return -1;
}
static bool processes(void) {
 uint64_t word=0,limits[2]={0},allocation=0,zone=0;
 if(!virtual_read(UINT64_C(0xfffffe000a9cb5d0)+slide,8,&word)||
    !virtual_read(UINT64_C(0xfffffe00077f6b50)+slide,16,limits)||
    !virtual_read(UINT64_C(0xfffffe000a966108)+slide,8,&allocation)||
    !virtual_read(UINT64_C(0xfffffe00077f6c00)+slide,8,&zone))return false;
 uint64_t mask=UINT64_MAX>>((word>>48)&63),table=word|UINT64_C(0x00ff000000000000);
 if(mask>=8192||allocation<0x5dd||allocation>1048576||!pointer(table,(mask+1)*8)||!pointer(zone,2))return false;
 uint64_t *heads=calloc((size_t)mask+1,8);Row *rows=calloc(256,sizeof(*rows));
 if(!heads||!rows){free(heads);free(rows);return false;}
 bool ok=true,complete=true;unsigned count=0;
 for(uint64_t i=0;i<=mask && ok;i+=8){size_t n=mask+1-i;if(n>8)n=8;ok=virtual_read(table+8*i,n*8,heads+i);}
 for(uint64_t b=0;b<=mask && ok;++b) {
  uint64_t node=heads[b];unsigned chain=0;
  while(node && ok) {
   if(count==256||chain++==256){complete=false;break;}
   for(unsigned j=0;j<count;++j)if(rows[j].node==node)ok=false;
   if(!ok||!row_read(node,(uint32_t)b,mask,zone,limits,allocation,&rows[count])){ok=false;break;}
   node=rows[count++].next;
  }
  if(!complete)break;
 }
 uint64_t afterWord=0;
 if(!virtual_read(UINT64_C(0xfffffe000a9cb5d0)+slide,8,&afterWord)||word!=afterWord)ok=false;
 printf("GUEST_PROCESSES rows=%u structurallyChecked=%d complete=%d nonAtomic=1 noGuestWrites=1\n",count,ok,complete);
 if(ok)for(unsigned i=0;i<count;++i) {
  Row again={0};bool stable=row_read(rows[i].node,rows[i].bucket,mask,zone,limits,allocation,&again) &&
   again.pid==rows[i].pid && again.ro==rows[i].ro && !memcmp(again.name,rows[i].name,17);
  char printable[18]={0};for(unsigned j=0;j<17&&rows[i].name[j];++j){unsigned char c=rows[i].name[j];printable[j]=(c>=33&&c<=126)?c:'?';}
  printf("GUEST_PROCESS pid=%u name=%s identityRechecked=%d process=0x%llx\n",rows[i].pid,printable,stable,rows[i].process);
  int allow=allowed_process(rows[i].name);
  if(allow>=0 && stable && rows[i].pid>1) {
   SelectedProcess *s=&selected[allow];++s->matches;
   if(s->matches==1){s->row=rows[i];s->mask=mask;s->zone=zone;
    memcpy(s->limits,limits,16);s->allocation=allocation;}
  }
 }
 free(heads);free(rows);return ok;
}
static bool msgbuf(void) {
 uint64_t pointerVA=0;struct {uint32_t magic;int32_t size,writeIndex,readIndex;uint64_t buffer;} h={0},after={0};
 if(!virtual_read(UINT64_C(0xfffffe000a8f2848)+slide,8,&pointerVA)||!pointer(pointerVA,24)||
    !virtual_read(pointerVA,24,&h)||h.magic!=0x63061||h.size<=0||h.size>1048576||h.writeIndex<0||h.writeIndex>=h.size)return false;
 char text[16385]={0};size_t n=(size_t)h.size;if(n>16384)n=16384;
 size_t cursor=((size_t)h.writeIndex+h.size-n)%(size_t)h.size;
 for(size_t at=0;at<n;){size_t take=n-at;if(take>(size_t)h.size-cursor)take=h.size-cursor;
  if(!virtual_read(h.buffer+cursor,take,text+at))return false;at+=take;cursor=(cursor+take)%h.size;}
 if(!virtual_read(pointerVA,24,&after)||h.magic!=after.magic||h.size!=after.size||h.buffer!=after.buffer)return false;
 printf("GUEST_MSGBUF bytes=%zu writeBefore=%d writeAfter=%d nonAtomic=1\n",n,h.writeIndex,after.writeIndex);
 for(size_t i=0;i<n;++i){unsigned char c=text[i];if(c)putchar((c=='\n'||c=='\t'||(c>=32&&c<=126))?c:'.');}
 printf("\nGUEST_MSGBUF_END\n");return true;
}
/* Optional user-service threads reuse exact25G83 v65 structural fields.
 * Reader state is external-only; no original CPU/lifecycle code runs here. */
typedef Row VM27GuestProcessRowV63;
typedef struct { unsigned reads; size_t bytes; bool budgetHit; } VM27GuestProcessReaderV63;
static bool VM27GuestProcessPointerV63(uint64_t p,uint64_t alignment,size_t bytes) {
 return alignment && !(alignment&(alignment-1)) && bytes &&
  (p>>47)==UINT64_C(0x1ffff) && !(p&(alignment-1)) &&
  p<=UINT64_MAX-(uint64_t)bytes &&
  ((p+(uint64_t)bytes-1)>>47)==UINT64_C(0x1ffff);
}
static bool VM27GuestProcessPartV63(VM27GuestProcessReaderV63 *r,
 uint64_t va,size_t bytes,void *out) {
 if(!bytes || bytes>64 || !VM27GuestProcessPointerV63(va,1,bytes))return false;
 if(r->reads>=4096 || reads>=16384 || total+bytes>1048576){r->budgetHit=true;return false;}
 ++r->reads;r->bytes+=bytes;return virtual_read(va,bytes,out);
}
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
 if(out->pid!=process->pid || process->pid<=1 || allowed_process(process->name)<0 ||
  out->readOnly!=process->ro || memcmp(out->name,process->name,17) ||
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

static bool selected_same(const SelectedProcess *s) {
 Row after={0};
 return s->matches==1 && row_read(s->row.node,s->row.bucket,s->mask,s->zone,
  (uint64_t *)s->limits,s->allocation,&after) && after.process==s->row.process &&
  after.pid==s->row.pid && after.ro==s->row.ro && !memcmp(after.name,s->row.name,17);
}
static bool thread_identity(VM27GuestProcessReaderV63 *r,const SelectedProcess *s,
 const VM27GuestThreadTaskV65 *task,const VM27GuestThreadRowV65 *row) {
 VM27GuestThreadTaskV65 t={0};VM27GuestThreadRowV65 q={0};bool invalid=false;
 return selected_same(s) && VM27GuestThreadTaskReadV65(r,slide,&s->row,&t,&invalid) &&
  VM27GuestThreadTaskSameV65(task,&t) && VM27GuestThreadRowReadV65(r,&t,row->thread,&q,&invalid) &&
  VM27GuestThreadRowSameV65(row,&q);
}
static bool thread_bytes(VM27GuestProcessReaderV63 *r,uint64_t at,size_t n,uint8_t *out) {
 for(size_t done=0;done<n;done+=64){size_t take=n-done;if(take>64)take=64;
  if(!VM27GuestProcessPartV63(r,at+done,take,out+done))return false;}
 return true;
}
static void thread_context(const SelectedProcess *s,const VM27GuestThreadTaskV65 *task,
 const VM27GuestThreadRowV65 *row) {
 VM27GuestProcessReaderV63 r={0};unsigned reason=1,frames=0,frameReason=0;
 bool known=false,complete=false;uint64_t context=0,fp=0,lr=0,sp=0;
 uint8_t before[208]={0},after[208]={0};
 struct {uint64_t address,previous,returnRaw;} staged[8]={0};
 if(task->stackBytes<208 || task->stackBytes>1048576 || (task->stackBytes&15) ||
  !VM27GuestProcessPointerV63(row->stackBase,16,(size_t)task->stackBytes))goto done;
 context=row->stackBase+task->stackBytes-208;reason=2;
 if(!thread_bytes(&r,context,208,before))goto done;
 memcpy(&fp,before+0x50,8);memcpy(&lr,before+0x58,8);memcpy(&sp,before+0x60,8);
 uint64_t frame=fp;
 for(;;){
  if(!frame){complete=true;break;}
  if(frames==8){frameReason=1;break;}
  if(!VM27GuestProcessPointerV63(frame,16,16) || frame<row->stackBase ||
   frame>context || context-frame<16){frameReason=2;break;}
  if(frames && frame<=staged[frames-1].address){frameReason=3;break;}
  uint64_t pair[2]={0};reason=3;
  if(!VM27GuestProcessPartV63(&r,frame,16,pair))goto done;
  staged[frames].address=frame;staged[frames].previous=pair[0];
  staged[frames++].returnRaw=pair[1];frame=pair[0];
 }
 reason=4;
 for(unsigned i=0;i<frames;++i){uint64_t pair[2]={0};
  if(!VM27GuestProcessPartV63(&r,staged[i].address,16,pair) ||
   pair[0]!=staged[i].previous || pair[1]!=staged[i].returnRaw)goto done;}
 reason=5;if(!thread_identity(&r,s,task,row))goto done;
 reason=6;
 if(!thread_bytes(&r,context,208,after) || memcmp(before,after,208))goto done;
 known=true;reason=0;
done:
 printf("GUEST_THREAD_CONTEXT pid=%u name=%s tid=%llu known=%d reason=%u context=0x%llx savedContextRaw=0x%llx lastSavedFPRaw=0x%llx lastSavedLRRaw=0x%llx lastSavedSPRaw=0x%llx frames=%u framesComplete=%d frameReason=%u lastSavedContextNotCurrentExecution=1 pointerAuthenticationKnown=0 ownStackOnly=1 nonAtomic=1 noGuestWrites=1\n",
  s->row.pid,s->row.name,row->tid,known,reason,context,row->savedContextRaw,
  known?fp:0,known?lr:0,known?sp:0,known?frames:0,known&&complete,frameReason);
 if(known)for(unsigned i=0;i<frames;++i)
  printf("GUEST_THREAD_FRAME pid=%u tid=%llu ordinal=%u frameAddress=0x%llx previousFPRaw=0x%llx returnAddressRaw=0x%llx ownStackOnly=1 pointerAuthenticationKnown=0 nonAtomic=1\n",
   s->row.pid,row->tid,i,staged[i].address,staged[i].previous,staged[i].returnRaw);
}
static void thread_user_state(const SelectedProcess *s,const VM27GuestThreadTaskV65 *task,
 const VM27GuestThreadRowV65 *row) {
 VM27GuestProcessReaderV63 r={0};bool known=false;unsigned reason=1;
 uint64_t zone=0,afterZone=0,pc=0,fp=0;uint32_t flavor=0,count=0,pstate=0;
 uint16_t tag=0,element=0,afterTag=0,afterElement=0;uint8_t before[304]={0},after[304]={0};
 if((task->taskFlags&3)!=3 || !VM27GuestProcessPointerV63(row->userAllocationBase,16,304) ||
  row->userAllocationBase<task->limits[0] || row->userAllocationBase+304>task->limits[1])goto done;
 reason=2;
 if(!VM27GuestProcessPartV63(&r,UINT64_C(0xfffffe0007889780)+slide,8,&zone) ||
  !VM27GuestThreadTagV65(&r,task->zoneMap,row->userAllocationBase,&tag))goto done;
 reason=3;
 if(!VM27GuestProcessPointerV63(zone,8,0x36) ||
  zone!=UINT64_C(0xfffffe000a927b80)+slide+UINT64_C(0xc0)*(tag&0x3ff))goto done;
 reason=4;if(!VM27GuestProcessPartV63(&r,zone+0x34,2,&element))goto done;
 reason=5;
 if(element<304 || element>16384 || row->userAllocationBase>UINT64_MAX-element ||
  row->userAllocationBase+element>task->limits[1])goto done;
 reason=6;if(!thread_bytes(&r,row->userAllocationBase,304,before))goto done;
 memcpy(&flavor,before,4);memcpy(&count,before+4,4);
 reason=7;if(flavor!=21 || count!=74)goto done;
 memcpy(&fp,before+0xf0,8);memcpy(&pc,before+0x108,8);memcpy(&pstate,before+0x110,4);
 reason=8;if(!thread_identity(&r,s,task,row))goto done;
 reason=9;
 if(!VM27GuestProcessPartV63(&r,UINT64_C(0xfffffe0007889780)+slide,8,&afterZone) || afterZone!=zone ||
  !VM27GuestThreadTagV65(&r,task->zoneMap,row->userAllocationBase,&afterTag) || afterTag!=tag ||
  !VM27GuestProcessPartV63(&r,zone+0x34,2,&afterElement) || afterElement!=element ||
  !thread_bytes(&r,row->userAllocationBase,304,after) || memcmp(before,after,304))goto done;
 known=true;reason=0;
done:
 printf("GUEST_THREAD_USER_STATE pid=%u name=%s tid=%llu known=%d reason=%u unsignedAllocationBase=0x%llx rawSignedStatePointer=0x%llx flavor=%u count=%u userPCRaw=0x%llx userFPRaw=0x%llx pstateRaw=0x%x allocationAddressOnly=1 rawSignedPointerNotFollowed=1 userPCVerified=0 pointerAuthenticationKnown=0 nonAtomic=1 noGuestWrites=1\n",
  s->row.pid,s->row.name,row->tid,known,reason,row->userAllocationBase,row->userStateRaw,
  known?flavor:0,known?count:0,known?pc:0,known?fp:0,known?pstate:0);
}
typedef struct {VM27GuestThreadTaskV65 task;VM27GuestThreadRowV65 rows[16];bool stable[16];unsigned count,reason;bool known,capped,complete;} ThreadSnapshot;
static void threads_optional(void) {
 /* Base process and16KiB msgbuf diagnostics already ran before this optional work. */
 ThreadSnapshot snapshots[2]={0};
 for(unsigned a=0;a<2;++a){
  SelectedProcess *s=&selected[a];ThreadSnapshot *snap=&snapshots[a];VM27GuestProcessReaderV63 r={0};bool invalid=false;
  snap->reason=1;if(s->matches!=1 || !selected_same(s))goto summary;
  snap->reason=2;if(!VM27GuestThreadTaskReadV65(&r,slide,&s->row,&snap->task,&invalid))goto summary;
  uint64_t node=snap->task.head,sentinel=snap->task.task+0x50;
  while(node!=sentinel){
   if(snap->count==16){snap->capped=true;break;}
   snap->reason=3;
   for(unsigned i=0;i<snap->count;++i)if(snap->rows[i].thread==node)goto summary;
   VM27GuestThreadRowV65 row={0};snap->reason=4;
   if(!VM27GuestThreadRowReadV65(&r,&snap->task,node,&row,&invalid) || row.next==node)goto summary;
   for(unsigned i=0;i<snap->count;++i)
    if((row.tid && row.tid==snap->rows[i].tid) || row.next==snap->rows[i].thread)goto summary;
   snap->rows[snap->count++]=row;node=row.next;
  }
  snap->complete=!snap->capped;snap->reason=5;
  VM27GuestThreadTaskV65 after={0};
  if(!selected_same(s) || !VM27GuestThreadTaskReadV65(&r,slide,&s->row,&after,&invalid) ||
   !VM27GuestThreadTaskSameV65(&snap->task,&after))goto summary;
  for(unsigned i=0;i<snap->count;++i){VM27GuestThreadRowV65 row={0};
   snap->stable[i]=VM27GuestThreadRowReadV65(&r,&snap->task,snap->rows[i].thread,&row,&invalid) &&
    VM27GuestThreadRowSameV65(&snap->rows[i],&row);}
  snap->reason=6;
  if(!selected_same(s) || !VM27GuestThreadTaskReadV65(&r,slide,&s->row,&after,&invalid) ||
   !VM27GuestThreadTaskSameV65(&snap->task,&after))goto summary;
  snap->known=true;snap->reason=0;
summary:
  printf("GUEST_THREADS pid=%u name=%s uniqueStableProcessMatches=%u known=%d reason=%u stagedRows=%u capped=%d complete=%d maxThreads=16 contextsFirstStableThreadOnly=1 nonAtomic=1 noGuestWrites=1\n",
   s->row.pid,s->row.name,s->matches,snap->known,snap->reason,snap->count,snap->capped,snap->known&&snap->complete);
  if(snap->known)for(unsigned i=0;i<snap->count;++i){VM27GuestThreadRowV65 *q=&snap->rows[i];
   printf("GUEST_THREAD_ROW pid=%u name=%s ordinal=%u identityRechecked=%d tid=%llu thread=0x%llx stateRaw=0x%x waitEventRaw=0x%llx waitqRaw=0x%llx continuationRaw=0x%llx parameterRaw=0x%llx kernelStackBaseRaw=0x%llx savedContextRaw=0x%llx nonAtomic=1\n",
    s->row.pid,s->row.name,i,snap->stable[i],q->tid,q->thread,
    snap->stable[i]?q->state:0,snap->stable[i]?q->event:0,snap->stable[i]?q->waitq:0,
    snap->stable[i]?q->continuation:0,snap->stable[i]?q->parameter:0,
    snap->stable[i]?q->stackBase:0,snap->stable[i]?q->savedContextRaw:0);}
 }
 for(unsigned a=0;a<2;++a){ThreadSnapshot *snap=&snapshots[a];if(!snap->known)continue;
  for(unsigned i=0;i<snap->count;++i)if(snap->stable[i]){
   thread_context(&selected[a],&snap->task,&snap->rows[i]);
   thread_user_state(&selected[a],&snap->task,&snap->rows[i]);break;}}
}

static bool argument(const char *text,uint64_t *value) {
 char *end=NULL;errno=0;unsigned long long n=strtoull(text,&end,0);
 if(errno || !text[0] || text[0]=='-' || !end || *end)return false;
 *value=(uint64_t)n;return true;
}
int main(int argc,char **argv) {
 uint64_t pid=0,headerGPA=0;
 if(geteuid()!=0 || argc!=6 || !argument(argv[1],&pid) || pid<=1 || pid>INT32_MAX ||
    !argument(argv[2],&bias) || bias>UINT64_C(0x10000000000) || (bias&0x3fff) ||
    !argument(argv[3],&root) || root<UINT64_C(0x70000000) || root>=UINT64_C(0x270a00000) || (root&0x3fff) ||
    !argument(argv[4],&slide) || slide>UINT64_C(0x40000000) || (slide&0x3fff) ||
    !argument(argv[5],&headerGPA) || headerGPA<UINT64_C(0x70000000) || headerGPA>=UINT64_C(0x270a00000) || (headerGPA&0x3fff))return 2;
 alarm(18);setbuf(stdout,NULL);
 kern_return_t k=task_for_pid(mach_task_self(),(pid_t)pid,&target);
 printf("OWNED_VMM_TASK_PORT pid=%llu kr=%d valid=%d\n",(unsigned long long)pid,k,MACH_PORT_VALID(target));if(k)return 3;
 static const uint8_t root32[32]={0xcf,0xfa,0xed,0xfe,0x0c,0,0,1,2,0,0,0xc0,0x0c,0,0,0,0xe6,0,0,0,0x20,0x40,0,0,0,0,0,0,0,0,0,0};
 static const uint8_t kernelUUID[24]={0x1b,0,0,0,0x18,0,0,0,0xb2,0x45,0x5c,0x4b,0x78,0x1c,0x3f,0x38,0x8c,0xa0,0xdd,0x11,0xcf,0x31,0x7c,0x15};
 uint8_t actual[32]={0};uint64_t rootGPA=0;
 bool identity=physical(headerGPA,32,actual)&&!memcmp(actual,root32,32)&&
  physical(headerGPA+0x9490,24,actual)&&!memcmp(actual,kernelUUID,24)&&
  translate(UINT64_C(0xfffffe0007004000)+slide,&rootGPA)&&rootGPA==headerGPA;
 printf("GUEST_RAM_IDENTITY exactKernelUUID=%d actualRootGPA=0x%llx bias=0x%llx slide=0x%llx externalNonAtomicRead=1\n",identity,rootGPA,bias,slide);
 bool procs=false,msg=false;if(identity){procs=processes();msg=msgbuf();}
 if(identity && procs)threads_optional();
 mach_port_deallocate(mach_task_self(),target);
 printf("OWNED_GUEST_RAM_READ_END processRead=%d msgbufRead=%d reads=%u bytes=%zu noGuestWrites=1 noTaskSuspend=1 noRemoteCalls=1\n",procs,msg,reads,total);
 return identity&&(procs||msg)?0:4;
}
