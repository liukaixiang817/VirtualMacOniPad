"""Bind inert binary, finite host faults, and exact old reset/value provenance."""
from pathlib import Path
import hashlib,json,re,struct
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-owned-brk-device-unsigned-local-v3'
H=N/'cpu-owned-brk-device-host-faults-v3'
def pin(path):
 p=Path(path).absolute();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(path,value):
 with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
def main():
 if (D/'source-finalization.json').exists():raise ValueError('already finalized')
 candidate=json.loads((D/'candidate.json').read_bytes());host=json.loads((H/'host-results.json').read_bytes())
 for receipt in [candidate,host]:
  for row in receipt['inputs']:
   if pin(row['path'])!=row:raise ValueError('source changed '+row['path'])
 if pin(candidate['binary']['path'])!=candidate['binary']:raise ValueError('binary changed')
 if not host['finiteMockScopePassed'] or host['normalModes']!=12 or host['sanitizedModes']!=12:raise ValueError('fault receipt')
 original=N/'native-cpu-initialization-v1/audit/contract.json'
 if pin(original)['sha256']!='a289bdfb24c0e9ae7f0c1c8e301925c5b9a79cc241dc47d567231e2075cfb849':raise ValueError('old reset source')
 old=json.loads(original.read_bytes())
 for key in ['oldHV','oldVMM']:
  identity=old['inputs'][key]
  if pin(identity['path'])['sha256']!=identity['sha256']:raise ValueError('old image identity')
 vm=Path(old['inputs']['oldVMM']['path']).read_bytes();hv=Path(old['inputs']['oldHV']['path']).read_bytes()
 words=[]
 for owner,data,rva,word,meaning in [
  ('oldVMM',vm,0xb59ac,0xf9400021,'reset109 PC value is incoming frame+0, not a literal reset constant'),
  ('oldVMM',vm,0xb5910,0x528003e1,'true PC leaf uses logical scalar31'),
  ('oldVMM',vm,0xb5b7c,0xf9419a81,'reset109 PSTATE path receives frame+330'),
  ('oldVMM',vm,0xb5000,0x52800441,'ordinary PSTATE path uses scalar34'),
  ('oldVMM',vm,0xb5004,0xaa1403e2,'PSTATE value is actual caller x20, not an invented zero'),
  ('oldVMM',vm,0xb7060,0xf942f281,'reset109 SCTLR path receives frame+5e0'),
  ('oldVMM',vm,0x10869c,0x52981001,'ordinary SCTLR path uses genuine SYSc080'),
  ('oldHV',hv,0x5ab8,0xf9008502,'scalar31 actual native write is8B at108'),
  ('oldHV',hv,0x5b18,0xb9011102,'scalar34 actual native write is4B at110')]:
  if struct.unpack_from('<I',data,rva)[0]!=word:raise ValueError('exact original word '+hex(rva))
  words.append(dict(image=owner,rva=hex(rva),machineWord=f'{word:08x}',meaning=meaning))
 prod=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-hv-first-run-observer-v2-actual-prelogin-v1/hv-first-run-61006-832137-584404000.log'
 if pin(prod)['sha256']!='adf8d1b52b7bf26e89b7109c9543775c6afcb6badc47687f11c859624c698275':raise ValueError('saved production log')
 lines=prod.read_text().splitlines();selected=[]
 for pattern in ['originalVMCreate rc=00000000','raw id=0 owner=6394248 offset=108 bytes=8',
  'raw id=0 owner=6394248 offset=110 bytes=8','raw id=0 owner=6394248 offset=400 bytes=8']:
  chosen=[(i+1,line) for i,line in enumerate(lines) if pattern in line]
  if len(chosen)!=1:raise ValueError('exact production row '+pattern)
  selected.append(dict(line=chosen[0][0],text=chosen[0][1]))
 if 'configRaw18=0000000000000002' not in selected[0]['text'] or 'value=00000000000003c5' not in selected[2]['text'] or 'value=0000000030800180' not in selected[3]['text']:raise ValueError('actual diagnostic values')
 binary=Path(candidate['binary']['path']).read_bytes();uuid=None;offset=32;textRange=None
 for _ in range(struct.unpack_from('<I',binary,16)[0]):
  command,size=struct.unpack_from('<II',binary,offset)
  if command==0x1b:uuid=binary[offset+8:offset+24].hex()
  if command==0x19 and binary[offset+8:offset+24].rstrip(b'\0')==b'__TEXT':
   textRange=struct.unpack_from('<QQQQ',binary,offset+24)
  offset+=size
 if not uuid or not textRange:raise ValueError('Mach-O image identity')
 base,_,fileoff,_=textRange
 symbols=(D/'symbols.stdout').read_text();traps=[]
 for name in ['_VM27OwnedBRKNativeTrapV1','_VM27CPUConfigCapabilityKernelQueryV1']:
  match=re.search(r'^([0-9a-f]{16}) .* '+re.escape(name)+r'$',symbols,re.M)
  if not match:raise ValueError('actual private trap symbol')
  address=int(match.group(1),16);at=fileoff+address-base;raw=binary[at:at+12]
  if raw.hex()!='90008092011000d4c0035fd6':raise ValueError('actual exact12B trampoline')
  traps.append(dict(name=name,address=hex(address),fileOffset=at,bytes=raw.hex()))
 provenance=dict(originalReset=pin(original),savedProduction=pin(prod),originalMachineWords=words,
  productionRows=selected,PCDiagnosticOverride='0x40000000 is the new owned BRK mapping; saved production ROM PC is0x100000',
  PSTATEAndSCTLRSource='cached saved actual production observations, not complete reset constants',
  completeResetReproduced=False,actualNativeISA2PacketSupported=True,
  architecturalNamesOfNumericISASelectorsEstablished=False)
 save(D/'provenance.json',provenance)
 save(D/'scope.json',dict(schema='Owned BRK complete execution proposal scope v3',
  unsignedCandidate=pin(D/'candidate.json'),binary=candidate['binary'],
  native0CapabilityQueryMaximum=1,native0CapabilityQuery='private AcqV2 pthread_once kernel query; no guest control0 submission',
  nativeCallbackSequence=[1,3,6,8,9,7,4,2],native8ConditionalMaximum=1,native9Maximum=1,
  nativeCallbackRetries=0,guestControl0SubmissionCount=0,initialCancelCount=0,
  ownSingleCPU=True,callerOwned16KiBBRKPage=True,nativeISA=2,
  externalProcessTimeoutSeconds=20,killGraceSeconds=1,cpuLimitInfinity=True,coreLimitBytes=0,
  requiresRootExactSourceReview=True,requiresNewExactSignedProductReview=True,
  requiresExplicitNewTrustCacheApproval=True,originalProductionFilesModified=False,
  nativeCallsExecuted=0,deviceOperations=0,staleNative8BRKRejectedBeforeNative9=True,
  freshSyndromeRecheckedAtFinalNative9Boundary=True,completeReset=False,guestBooted=False,full27Backend=False))
 save(D/'source-finalization.json',dict(schema='Owned BRK diagnostic source final binding v3',
  candidate=pin(D/'candidate.json'),binary=candidate['binary'],hostFaultReceipts=pin(H/'host-results.json'),
  provenance=pin(D/'provenance.json'),completeScope=pin(D/'scope.json'),
  native0CapabilityQueryMaximum=1,UUID=uuid,exactPrivateTrampolines=traps,
  finiteIOSAndHostMockScopePassed=True,externalWatchdogImplementedInExistingControllerOnly=True,
  requiresNewExactProductControllerReview=True,requiresSeparateNewSigningAndTrustCacheReview=True,
  nativeExecutionAuthorizedHere=False,nativeCallsExecuted=0,deviceOperations=0,providerSigned=False,
  staleNative8BRKCounterexample=pin(N/'cpu-owned-brk-helper-source-independent-review-v1/stale-sync-finding.json'),
  staleNative8BRKRejectedInNormalAndSAN=True,freshSyndromeRecheckedAtFinalNative9Boundary=True,
  instructionOracleActual=False,guestBooted=False,full27Backend=False))
 print(json.dumps(dict(sourceFinalization=pin(D/'source-finalization.json'),provenance=pin(D/'provenance.json'),scope=pin(D/'scope.json'),finalFreezePendingRoot53CurrentDefinitions=True,nativeCallsExecuted=0)))
if __name__=='__main__':main()
