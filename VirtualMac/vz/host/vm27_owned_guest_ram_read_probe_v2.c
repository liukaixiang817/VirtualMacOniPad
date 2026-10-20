/* Read-only diagnosis of one currently owned VMM, not a CPU implementation.
 * The current Root handoff and CPU-observed RAM mapping/TTBR/slide are pinned by the
 * host controller and again here. No remote calls, writes, suspend or signals.
 * Process offsets are from modern_cpu_kernel_guest_process_v65.inc (25G83).
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
 mach_port_deallocate(mach_task_self(),target);
 printf("OWNED_GUEST_RAM_READ_END processRead=%d msgbufRead=%d reads=%u bytes=%zu noGuestWrites=1 noTaskSuspend=1 noRemoteCalls=1\n",procs,msg,reads,total);
 return identity&&(procs||msg)?0:4;
}
