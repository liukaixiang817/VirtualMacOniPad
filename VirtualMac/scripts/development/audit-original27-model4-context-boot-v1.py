#!/usr/bin/env python3
"""Bounded true model4 frame CFG and current residual context call grouping.

Reads original and frozen candidates. No binary mutation, signing or device I/O.
"""
from pathlib import Path
import argparse,collections,hashlib,json,re,runpy,struct,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S=R/'VirtualMac/vz/host'

def pin(path):
 p=Path(path).resolve();data=p.read_bytes()
 return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def require(ok,message):
 if not ok:raise ValueError(message)

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);out=p.parse_args().out.resolve()
 require(out.parent==N.resolve() and not out.exists(),'fresh diagnostic output')
 parserPath=N/'vmm-public-adapter-gap-design-v1/audit.py'
 parser=runpy.run_path(str(parserPath))
 flowPath=R/'VirtualMac/scripts/development/audit-original27-cpu-restore-v1.py'
 flow=runpy.run_path(str(flowPath))
 oldPath=parser['VM'];old=parser['MachO'](oldPath.read_bytes())
 currentPath=N/'original27-routed-mandatory-fields-data-v2-attempt2/candidate.json'
 candidate=json.loads(currentPath.read_bytes());current=Path(candidate['candidate']['path'])
 require(pin(current)==candidate['candidate'],'actual frozen current VMM')
 image=parser['MachO'](current.read_bytes())
 require(pin(oldPath)['sha256']=='c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422','actual original image')
 def word(at,expected):
  before=struct.unpack('<I',old.raw(at,4))[0];after=struct.unpack('<I',image.raw(at,4))[0]
  require(before==after==expected,'unchanged exact original word '+hex(at))
  return dict(rva=hex(at),word=hex(expected),originalAndCurrentSame=True)
 checks=[word(0xb2438,0x52800088),word(0xb243c,0xb9003008)]
 gates=[]
 for name,start,end,at,target,nextAt,join,remaining in [
  ('SAVE',0x2875a8,0x28a258,0x289274,0x289be0,0x289be0,0x289dd0,[0x289288,0x289adc,0x289be8,0x289db4]),
  ('RESTORE',0x28a508,0x28cc24,0x28bd3c,0x28c908,0x28c908,0x28cb08,[0x28bd70,0x28c7cc,0x28c914,0x28caf0])]:
  require(old.bounds(at)==image.bounds(at)==(start,end),'actual complete LC_FUNCTION_STARTS frame')
  words=[word(at,0xb9403288),word(at+4,0x51000509),word(at+8,0x71000d3f)]
  branch=struct.unpack('<I',old.raw(at+12,4))[0]
  words.append(word(at+12,branch));require(branch&0xff00001f==0x54000002,'actual unsigned B.HS')
  require(flow['edges'](branch,at+12)==[at+16,target],'exact unsigned model branch target')
  second=struct.unpack('<I',old.raw(nextAt,4))[0]
  words.append(word(nextAt,second));require(second&0xff00001f==0x35000008,'actual CBNZ W8')
  require(flow['edges'](second,nextAt)==[nextAt+4,join],'exact nonzero branch target')
  graph={}
  for pc in range(start,end,4):
   insn=struct.unpack('<I',image.raw(pc,4))[0]
   successors=flow['edges'](insn,pc)
   graph[pc]=successors
  # Both outcomes remain possible everywhere else. Only these two branches
  # use the actual CPU model freshly loaded by the original instruction.
  graph[at+12]=[target];graph[nextAt]=[join]
  reachable=flow['closure'](start,graph)
  require(all(start<=to<end for to in reachable),'closed reachable complete frame CFG')
  require(not set(remaining)&reachable,'model4 must skip every remaining context call')
  for pc in remaining:
   require(parser['branch'](struct.unpack('<I',image.raw(pc,4))[0],pc)==0x4125b4,'true remaining GetContext call')
  cases=[]
  for model in [0,1,2,3,4,5,0xffffffff]:
   sub=(model-1)&0xffffffff;bulk=sub<3;tail=bulk or model==0
   cases.append(dict(actualModel=model,unsignedSubResult=sub,
    ca8Bc0ModelEligible=bulk,raw390Af8ModelEligible=tail,
    ca8RestoreStillSubjectToOriginalCapability9Gate=name=='RESTORE' and bulk))
  gates.append(dict(function=name,completeFunctionStartRVA=hex(start),completeFunctionEndRVA=hex(end),
   exactUnchangedWords=words,model4InstructionPath=[hex(at),hex(at+4),hex(at+8),hex(at+12),hex(target),hex(join)],
   actualCPUModelSource='original LDR W8,[X20,#0x30]',actualModel4RemainingContextCallsReachable=[],
   reachableInstructionsWithOtherBranchesConservative=len(reachable),trueRemainingContextCallRVAs=list(map(hex,remaining)),
   actualModelCases=cases,opaqueCalleesAssumedOrdinaryAAPCSReturn=True,
   exceptionalUnwindExecutionProven=False,archiveModelsOutside4Supported=False))
 summaryPath=N/'context-consumer-adapter-v1/audit/summary.json'
 censusPath=N/'context-consumer-adapter-v1/audit/context-cfg-consumers.json'
 census=json.loads(censusPath.read_bytes());require(json.loads(summaryPath.read_bytes())['image']==pin(oldPath),'genuine census image pin')
 fieldsPath=S/'modern_vmm_physical_save53_fields_v1.inc'
 known={int(m[2],16):int(m[1],16) for m in re.finditer(r'\{0x[0-9a-f]+,0x([0-9a-f]+),0x([0-9a-f]+),',fieldsPath.read_text())}
 require(len(known)==53,'actual 53 mapper-compatible modern physical fields')
 text=next(s for s in image.sections if s['name']=='__text');calls=[]
 incoming=collections.defaultdict(list)
 for k in range(0,text['bytes'],4):
  pc=text['va']-image.base+k;insn=struct.unpack_from('<I',image.b,text['offset']+k)[0]
  to=parser['branch'](insn,pc)
  if to is not None:incoming[to].append(pc)
  if insn&0xfc000000==0x94000000 and to==0x4125b4:calls.append(pc)
 remaining=set(calls)-{int(pc,16) for g in gates for pc in g['trueRemainingContextCallRVAs']}
 require(len(calls)==147 and len(remaining)==139,'actual current 147/139 context calls')
 rows=[];groups=collections.Counter()
 for row in census:
  pc=int(row['callRVA'],16)
  if pc not in remaining:continue
  begin,end=image.bounds(pc)
  require((begin,end)==(int(row['functionBegin'],16),int(row['functionEnd'],16)),'actual residual function bounds')
  require(image.raw(begin,end-begin)==old.raw(begin,end-begin),'actual residual complete function bytes unchanged')
  offsets={int(a['offset'],16) for a in row['accesses']}-{0xa08,0x4110,0x4116,0x4117}
  if offsets and offsets<=set(known):tag='53ExistingPublicSYSFieldsGetterSetter'
  elif offsets=={0x6a0}:tag='ExistingPrivateDBGCLAIMFieldAdapter'
  elif offsets=={0x410}:tag='ExistingPrivateACTLRFieldAdapter'
  elif offsets&{0x390,0xca8,0xbc0,0xaf8}:tag='FourUnidentifiedFieldsVirtualMethods'
  elif offsets=={0x350}:tag='OriginalConditionalDebugFlags'
  elif offsets<={0x690,0x698}:tag='PrivateDebugControlReadModifyWrite'
  elif offsets and offsets<={0x11b8,0x11c0,0x11c8,0x11d0,0x11d8}:tag='FiveOtherPhysicalSYSFieldPairs'
  elif offsets=={0xa00}:tag='InternalContextWordReadModifyWrite'
  else:raise ValueError('unclassified true context consumer '+hex(pc))
  groups[tag]+=1
  rows.append(dict(callRVA=hex(pc),functionBegin=hex(begin),functionEnd=hex(end),group=tag,
   physicalFields=list(map(hex,sorted(offsets))),existingPublicSYSSelectors={hex(v):hex(known[v]) for v in offsets if v in known},
   genuineOriginalAccesses=row['accesses'],actualFunctionBodySHA256=hashlib.sha256(image.raw(begin,end-begin)).hexdigest(),
   actualDirectIncomingToFunction=list(map(hex,incoming[begin])),
   genuineGuestBootMandatoryProven=False,genuineVirtualMethodDispatchCallerStillNeeded=True,
   rawNativeContextProjectionPermitted=False))
 require(len(rows)==139 and groups['53ExistingPublicSYSFieldsGetterSetter']==106,'actual function grouping')
 root=N/'vm-hv-public-bootstrap-integration-local-v11-attempt2/candidate.json'
 rootCandidate=json.loads(root.read_bytes());exactExports={'_'+n for n in rootCandidate['exactExports']}
 hvImports=[r for r in image.imports if r['ordinal']==21]
 require(len(hvImports)==75 and all(not r['weak'] for r in hvImports),'current actual strong HV imports')
 missing=[r for r in hvImports if r['name'] not in exactExports]
 installPath=S/'vm27_hv_public_vm_bootstrap_v4.m'
 result=dict(schema='genuine fresh model4 frame skip and actual residual caller groups v1',
  originalImage=pin(oldPath),actualVMMCandidate=pin(current),inheritedVMMCandidateReceipt=pin(currentPath),
  constructorInitializesActualCPUModel4=checks,model4ActualBoundedFrameCFG=gates,
  currentGetContextCalls=147,remainingFrameCalls8AllSkippedForActualModel4=True,
  actualResidualCalls=139,residualFunctions=len({r['functionBegin'] for r in rows}),actualFunctionalGroups=dict(groups),residualCallers=rows,
  actualRoot11=pin(root),actualRoot11Provider=rootCandidate['provider'],actualStrongHypervisorImportCount=75,
  namesNotDirectlyDefinedByRoot11=missing,otherIndependentProviderGraphClosureProven=False,
  actualNativeOpsInstallSource=pin(installPath),actualNativeOpsInstallEntry='VM27HVVMInstallNativeOpsV1',
  nativeOpsInstallRequirements=['true NativeTrap plus current native thread plus own checked read/write callbacks',
   'schema1 and exact old kernel profile; writer context equals ops context',
   'install before original VM creation on that VM owner; actual CPU creation may use a distinct worker owner',
   'normal VM/RAM/config teardown on original VM owner; CPU/borrow access on that actual CPU owner'],
  actualAppVMMNativeOpsInstalled=False,priorHypervisor14FacadeIndependent=False,
  nextMinimalPort='106 actual private SYS getter/setter methods plus 6 DBGCLAIM/ACTLR calls through their true incoming CPU identity and reviewed owner APIs',
  unsupportedGetContextViewOrShadowNativeStateAllowed=False,
  nativeCallsExecuted=0,deviceOperations=0,signed=False,loaded=False,fullIndependent27GuestBoot=False)
 out.mkdir(mode=0o700)
 (out/'closure.json').write_text(json.dumps(result,indent=2)+'\n')
 paths=[Path(__file__),parserPath,flowPath,oldPath,current,currentPath,summaryPath,censusPath,fieldsPath,root,Path(rootCandidate['provider']['path']),installPath,
  S/'modern_cpu_native_public_factory_v8.c',S/'modern_cpu_kernel_lifecycle_v11.c',S/'hypervisor14_compat.c']
 (out/'freeze.json').write_text(json.dumps(dict(schema='bounded model4 original caller proof freeze v1',files=[pin(p) for p in paths+[out/'closure.json']],nativeCallsExecuted=0,deviceOperations=0),indent=2)+'\n')
 print(json.dumps(dict(closure=pin(out/'closure.json'),freeze=pin(out/'freeze.json'),groups=dict(groups),directRoot11Missing=len(missing))))

if __name__=='__main__':main()
