/* One read at the existing diagnostic wake. Exact 25G83 KC identity and
 * original instructions bind the data layout; never reuse another boot's slide.
 * All memory is borrowed guest RAM through the existing owner/ledger readers. */
typedef struct {
 uint32_t magic;int32_t size,writeIndex,readIndex;uint64_t buffer;
} VM27GuestMsgbufHeaderV59;
_Static_assert(sizeof(VM27GuestMsgbufHeaderV59)==24,"actual ARM64 msgbuf prefix");
static bool VM27MsgbufPartV59(VM27RunDiagnosticCodeV36 *generation,
 const VM27RunDiagnosticCodeV36 *part) {
 if(part->reason){generation->reason=part->reason;return false;}
 return VM27RAMReadGenerationV54(generation,part);
}
static bool VM27MsgbufVirtualV59(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t va,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,size_t bytes,VM27RunDiagnosticCodeV36 *generation,
 VM27RunDiagnosticCodeV36 *part) {
 VM27RunDiagnosticVirtualReadV37(a,q,va,sctlr,tcr,ttbr,bytes,false,part);
 return VM27MsgbufPartV59(generation,part);
}
static bool VM27MsgbufHeaderValidV59(const VM27GuestMsgbufHeaderV59 *h) {
 return h->magic==0x063061 && h->size>0 && h->size<=1048576 &&
  h->writeIndex>=0 && h->writeIndex<h->size && h->readIndex>=0 &&
  h->readIndex<h->size && (h->buffer>>47)==UINT64_C(0x1ffff) &&
  h->buffer<=UINT64_MAX-(uint64_t)h->size;
}
static void VM27GuestMsgbufReadV59(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,uint64_t pc,uint64_t sctlr,uint64_t tcr,
 uint64_t ttbr,const VM27RunDiagnosticCodeV36 *code) {
 static const uint8_t root32[32]={0xcf,0xfa,0xed,0xfe,0x0c,0x00,0x00,0x01,0x02,0x00,0x00,0xc0,0x0c,0x00,0x00,0x00,0xe6,0x00,0x00,0x00,0x20,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 static const uint8_t uuid24[24]={0x1b,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x11,0x56,0x86,0x0d,0x0e,0xc5,0xed,0x95,0x48,0x13,0x26,0x77,0xa8,0x10,0x9a,0xd7};
 static const uint8_t text64[64]={0x19,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x5f,0x5f,0x54,0x45,0x58,0x54,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x07,0x00,0xfe,0xff,0xff,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
 static const uint8_t anchor64[64]={0xf4,0x4f,0xbe,0xa9,0xfd,0x7b,0x01,0xa9,0xfd,0x43,0x00,0x91,0x28,0xe3,0x3b,0xd5,0x08,0x7d,0x01,0x53,0x01,0x01,0x1f,0x12,0x75,0xff,0xff,0x97,0x14,0xc8,0x38,0xd5,0x93,0xd0,0x38,0xd5,0x68,0xce,0x40,0xf9,0x09,0x00,0x80,0x12,0x09,0x71,0x00,0xb9,0x16,0x23,0x00,0x94,0x9f,0xfe,0x0f,0xf1,0x60,0x00,0x00,0x54,0x34,0xc8,0x18,0xd5};
 static const uint8_t kernelUUID24[24]={0x1b,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0xb2,0x45,0x5c,0x4b,0x78,0x1c,0x3f,0x38,0x8c,0xa0,0xdd,0x11,0xcf,0x31,0x7c,0x15};
 const int saved=errno;unsigned reason=1,pages=0,candidates=0,chunks=0;
 uint64_t headerGPA=0,headerVA=0,slide=0,pointer=0,afterPointer=0,textVA=0;
 bool rootUUIDMatched=false,kernelUUIDMatched=false;
 char actualRootUUID[49]={0},actualKernelUUID[49]={0},actualText[129]={0};
 static const char hex[]="0123456789abcdef";
 VM27RunDiagnosticCodeV36 generation={0};uint8_t *payload=NULL;
 VM27GuestMsgbufHeaderV59 before={0},after={0};size_t bytes=0;
 if(code->reason || !code->translated || code->tableNumber!=1 ||
  !code->ramGenerationKnown || (code->regionFlags&5)!=5 ||
  !code->regionBytes || code->regionBytes>UINT64_C(67108864) ||
  (code->regionGuestAddress&0x3fff) || (code->regionBytes&0x3fff) ||
  code->regionGuestAddress>UINT64_MAX-code->regionBytes ||
  code->guestAddress<code->regionGuestAddress ||
  code->guestAddress-code->regionGuestAddress>=code->regionBytes)goto done;
 generation.ramGeneration=code->ramGeneration;generation.ramGenerationKnown=true;
 reason=2;
 for(uint64_t offset=0;offset<code->regionBytes;offset+=0x4000) {
  VM27RunDiagnosticCodeV36 part={0};++pages;
  VM27RunDiagnosticRAMReadV37(a,q,code->regionGuestAddress+offset,32,&part);
  if(!VM27MsgbufPartV59(&generation,&part))goto done;
  if(!memcmp(part.bytes,root32,32)) {
   headerGPA=code->regionGuestAddress+offset;
   if(++candidates>1){reason=3;goto done;}
  }
 }
 if(candidates!=1)goto done;
 reason=5;
 if(headerGPA>code->guestAddress || pc<code->guestAddress-headerGPA)goto done;
 headerVA=pc-(code->guestAddress-headerGPA);
 if(headerVA<UINT64_C(0xfffffe0007004000))goto done;
 slide=headerVA-UINT64_C(0xfffffe0007004000);
 if(slide>UINT64_C(0x40000000) || (slide&0x3fff))goto done;
 {
  VM27RunDiagnosticCodeV36 u={0},t={0},kernel={0};reason=4;
  VM27RunDiagnosticRAMReadV37(a,q,headerGPA+0x20,24,&u);
  if(!VM27MsgbufPartV59(&generation,&u))goto done;
  for(unsigned i=0;i<24;++i){actualRootUUID[2*i]=hex[u.bytes[i]>>4];actualRootUUID[2*i+1]=hex[u.bytes[i]&15];}
  rootUUIDMatched=!memcmp(u.bytes,uuid24,24);
  if(memcmp(u.bytes,uuid24,8))goto done;
  VM27RunDiagnosticRAMReadV37(a,q,headerGPA+0x9490,24,&kernel);
  if(!VM27MsgbufPartV59(&generation,&kernel))goto done;
  for(unsigned i=0;i<24;++i){actualKernelUUID[2*i]=hex[kernel.bytes[i]>>4];actualKernelUUID[2*i+1]=hex[kernel.bytes[i]&15];}
  kernelUUIDMatched=!memcmp(kernel.bytes,kernelUUID24,24);
  if(!kernelUUIDMatched)goto done;
  VM27RunDiagnosticRAMReadV37(a,q,headerGPA+0x180,64,&t);
  if(!VM27MsgbufPartV59(&generation,&t))goto done;
  for(unsigned i=0;i<64;++i){actualText[2*i]=hex[t.bytes[i]>>4];actualText[2*i+1]=hex[t.bytes[i]&15];}
  memcpy(&textVA,t.bytes+24,8);
  // iBoot may slide LC_SEGMENT_64 vmaddr in the loaded Mach-O header.
  // Accept only the exact offline VA or the independently derived live VA.
  if(textVA!=UINT64_C(0xfffffe0007004000) && textVA!=headerVA)goto done;
  memcpy(t.bytes+24,text64+24,8);
  if(memcmp(t.bytes,text64,64))goto done;
 }
 {
  VM27RunDiagnosticCodeV36 h={0},anchor={0};reason=6;
  if(!VM27MsgbufVirtualV59(a,q,headerVA,sctlr,tcr,ttbr,32,&generation,&h) ||
   h.guestAddress!=headerGPA || memcmp(h.bytes,root32,32))goto done;
  if(!VM27MsgbufVirtualV59(a,q,UINT64_C(0xfffffe0009ddd5c4)+slide,
   sctlr,tcr,ttbr,64,&generation,&anchor) || memcmp(anchor.bytes,anchor64,64))goto done;
 }
 {
  VM27RunDiagnosticCodeV36 p={0},h={0};reason=7;
  if(!VM27MsgbufVirtualV59(a,q,UINT64_C(0xfffffe000a8f2848)+slide,
   sctlr,tcr,ttbr,8,&generation,&p))goto done;
  memcpy(&pointer,p.bytes,8);
  if((pointer>>47)!=UINT64_C(0x1ffff) || (pointer&7) || pointer>UINT64_MAX-24)goto done;
  if(!VM27MsgbufVirtualV59(a,q,pointer,sctlr,tcr,ttbr,24,&generation,&h))goto done;
  memcpy(&before,h.bytes,24);
  if(!VM27MsgbufHeaderValidV59(&before))goto done;
 }
 bytes=(size_t)before.size;if(bytes>16384)bytes=16384;
 payload=calloc(1,bytes);reason=8;if(!payload)goto done;
 {
  size_t cursor=((size_t)before.writeIndex+(size_t)before.size-bytes)%(size_t)before.size;
  for(size_t offset=0;offset<bytes;) {
   VM27RunDiagnosticCodeV36 part={0};size_t count=bytes-offset;
   if(count>64)count=64;
   if(count>(size_t)before.size-cursor)count=(size_t)before.size-cursor;
   if(++chunks>257)goto done;
   if(!VM27MsgbufVirtualV59(a,q,before.buffer+cursor,sctlr,tcr,ttbr,count,&generation,&part))goto done;
   memcpy(payload+offset,part.bytes,count);offset+=count;cursor+=count;
   if(cursor==(size_t)before.size)cursor=0;
  }
 }
 {
  VM27RunDiagnosticCodeV36 p={0},h={0};reason=9;
  if(!VM27MsgbufVirtualV59(a,q,UINT64_C(0xfffffe000a8f2848)+slide,
   sctlr,tcr,ttbr,8,&generation,&p))goto done;
  memcpy(&afterPointer,p.bytes,8);
  if(afterPointer!=pointer ||
   !VM27MsgbufVirtualV59(a,q,pointer,sctlr,tcr,ttbr,24,&generation,&h))goto done;
  memcpy(&after,h.bytes,24);
  if(!VM27MsgbufHeaderValidV59(&after) || after.magic!=before.magic ||
   after.size!=before.size || after.buffer!=before.buffer ||
   !VM27RAMReadGenerationStableV54(a,&generation))goto done;
 }
 reason=0;
done:
 if(candidates==1)dprintf(2,"[Independent27HV] guest-msgbuf-header rootUUIDHex=%s kernelUUIDHex=%s textHex=%s\n",actualRootUUID,actualKernelUUID,actualText);
 dprintf(2,"[Independent27HV] guest-msgbuf known=%u reason=%u readerReason=%u scanPages=%u candidates=%u headerGPA=0x%016llx headerVA=0x%016llx freshSlide=0x%llx pointer=0x%016llx textVA=0x%016llx rootUUIDMatched=%u kernelUUIDMatched=%u magic=0x%x size=%d writeBefore=%d writeAfter=%d readBefore=%d readAfter=%d bytes=%zu chunks=%u ramGeneration=%llu nonAtomic=1 extraNativeCalls=0 guestWrites=0\n",
  reason==0,reason,generation.reason,pages,candidates,(unsigned long long)headerGPA,
  (unsigned long long)headerVA,(unsigned long long)slide,(unsigned long long)pointer,
  (unsigned long long)textVA,rootUUIDMatched,kernelUUIDMatched,
  before.magic,before.size,before.writeIndex,after.writeIndex,before.readIndex,
  after.readIndex,reason?0:bytes,chunks,(unsigned long long)generation.ramGeneration);
 if(!reason) {
  static const char digits[]="0123456789abcdef";
  for(size_t offset=0;offset<bytes;offset+=64) {
   size_t count=bytes-offset;if(count>64)count=64;char text[129]={0};
   for(size_t i=0;i<count;++i){text[2*i]=digits[payload[offset+i]>>4];text[2*i+1]=digits[payload[offset+i]&15];}
   dprintf(2,"[Independent27HV] guest-msgbuf-data offset=%zu bytes=%zu hex=%s\n",offset,count,text);
  }
 }
 free(payload);errno=saved;
}
