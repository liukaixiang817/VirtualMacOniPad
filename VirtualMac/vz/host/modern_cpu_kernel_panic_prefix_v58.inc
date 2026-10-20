// The public packed FUNK prefix preserves existing fields across versions.
// Only the actual version8/offset0x321 observed twice is admitted here; this
// is not validation of the complete version8 header or its CRC.
static void VM27ResetPanicPrefixV58(PendingRunAccessV14 *a,
 const VZKernelRunPendingRequestV14 *q,unsigned ordinal,uint64_t address,
 const uint64_t sys[6],const VM27RunDiagnosticCodeV36 *header,
 unsigned *attemptedPayload,unsigned *completedPayload) {
 if(header->reason || header->actualBytes!=64 || !(sys[2]&1) ||
  sys[3]!=UINT64_C(0x000800226511a511))return;
 uint32_t magic=0,crc=0,version=0,offset=0,length=0;uint64_t flags=0;
 memcpy(&magic,header->bytes,4);memcpy(&crc,header->bytes+4,4);
 memcpy(&version,header->bytes+8,4);memcpy(&flags,header->bytes+12,8);
 memcpy(&offset,header->bytes+20,4);memcpy(&length,header->bytes+24,4);
 bool valid=magic==UINT32_C(0x46554e4b) && version==8 && offset==UINT32_C(0x321) &&
  offset>=sizeof(header->bytes) && length>=512 && length<=65536 && offset<=65536-length &&
  address<=UINT64_MAX-offset && address+offset<=UINT64_MAX-length &&
  header->ramGenerationKnown &&
  VM27ResetSnapshotAddressV57(address+offset,length,sys[2],sys[3]);
 dprintf(2,"[Independent27HV] reset-panic-header ordinal=%u register=23 known=1 admitted=%u VA=0x%016llx magic=0x%08x version=%u flags=0x%016llx storedCRC=0x%08x logOffset=%u logLength=%u prefixLayoutDerivedFromStablePublicPrefix=1 headerCRCValidated=0 completeVersion8LayoutValidated=0 nonAtomic=1 maximumPrefixBytes=512\n",
  ordinal,valid,(unsigned long long)address,magic,version,(unsigned long long)flags,crc,offset,length);
 if(!valid)return;
 static const char hex[]="0123456789abcdef";
 for(unsigned index=0;index<8;++index) {
  uint64_t at=address+offset+64u*index;VM27RunDiagnosticCodeV36 data={.reason=2};
  *attemptedPayload+=64;
  VM27ResetSnapshotReadV57(a,q,at,64,sys,&data);
  if(!data.reason && (!data.ramGenerationKnown || data.ramGeneration!=header->ramGeneration))data.reason=12;
  char text[129]={0};
  if(!data.reason) {
   *completedPayload+=64;
   for(unsigned j=0;j<64;++j){text[2*j]=hex[data.bytes[j]>>4];text[2*j+1]=hex[data.bytes[j]&15];}
  }
  dprintf(2,"[Independent27HV] reset-panic-prefix ordinal=%u chunk=%u prefixOffset=%u known=%u reason=%u VA=0x%016llx bytes=%u hex=%s headerCRCValidated=0 nonAtomic=1 headerRAMGenerationMatched=%u\n",
   ordinal,index,index*64,!data.reason,data.reason,(unsigned long long)at,
   data.reason?0u:data.actualBytes,text,!data.reason);
  if(data.reason)break;
 }
}
