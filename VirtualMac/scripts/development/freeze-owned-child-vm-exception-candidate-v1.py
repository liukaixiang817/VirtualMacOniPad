#!/usr/bin/env python3
"""Freeze the completed HOST-only MD initializer catch/rethrow build; no execution/signing."""
from pathlib import Path
import copy,hashlib,json,runpy
R=Path('/Users/liukaixiang/Documents/VirtualMacOniPad');N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
o=N/'owned-child-vm-exception-diagnostic-source-local-v4-attempt1';old=N/'owned-child-vm-result-diagnostic-source-port-v3-attempt1';bp=N/'independent27-signed-runtime-vm-result-product-v29-attempt1/candidate.json'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
ns=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'));M=ns['MachO'];base=json.loads(bp.read_bytes());rel='child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS';root=Path(base['runtimeRoot']);original=root/rel/'com.apple.Virtualization.VirtualMachine';child=M(original.read_bytes());md=M((o/'MD').read_bytes());oldMD=M((root/rel/'MD').read_bytes());og=json.loads((old/'incremental-native-closure.json').read_bytes());oc=json.loads((old/'candidate.json').read_bytes());nd=json.loads(Path(og['nativeIndex']['path']).read_bytes())['images']
assert len(md.exports)==len(oldMD.exports)==8 and set(md.exports)==set(oldMD.exports)
assert all(md.exports[k]['flags']==oldMD.exports[k]['flags']for k in md.exports)
assert [(x['cmd'],x['path'])for x in md.loads if x['path']!='/usr/lib/libc++.1.dylib']==[(x['cmd'],x['path'])for x in oldMD.loads]
def resolve(path,name,seen=()):
 if (path,name)in seen or path not in nd:return []
 im=nd[path];q=im['definitions'].get(name);seen=seen+((path,name),)
 if q:
  if q['flags']&8:
   dep=next(v for v in im['dependencies']if v['ordinal']==q['ordinal']);alias=q.get('alias')or q.get('importedName')or name
   return [([dict(path=path,symbol=name,reexportOrdinal=q['ordinal'],alias=alias)]+steps,leaf)for steps,leaf in resolve(dep['path'],alias,seen)]
  return [([dict(path=path,symbol=name)],dict(path=path,symbol=name,UUID=im['UUID'],offset=q['offset'],VA=im['base']+q['offset'],actualCompleteCommands=im['actualCompleteCommands'],actualCompleteExportSource=im['actualCompleteExportSource']['rangePin']))]
 out=[]
 for dep in im['dependencies']:
  if dep['command']==0x8000001f:out += [([dict(path=path,symbol=name,reexportOrdinal=dep['ordinal'])]+steps,leaf)for steps,leaf in resolve(dep['path'],name,seen)]
 return out
rows=[];new=[];nativePins=[];trieCache={}
for actual in md.imports:
 load=md.loads[actual['ordinal']-1]['path'];p=next((v for v in og['actualProviderNativeRows']if v['requiredLoad']==load and all(v['actualImport'][k]==actual[k]for k in ('name','weak','addend'))),None)
 if p:
  v=copy.deepcopy(p);v['actualImport']=actual;rows.append(v);continue
 routes=resolve(load,actual['name']);assert len({(v['path'],v['symbol'],v['offset'])for _,v in routes})==1,(load,actual)
 steps,leaf=routes[0]
 for step in steps:
  im=nd[step['path']];fp=im['actualCompleteExportSource']['rangePin'];cp=im['actualCompleteCommands']
  assert pin(fp['path'])==fp and pin(cp['path'])==cp
  if fp['path']not in trieCache:trieCache[fp['path']]=ns['trie'](Path(fp['path']).read_bytes())[0]
  q=trieCache[fp['path']].get(step['symbol'])
  if 'alias'in step:assert q and q['flags']&8 and q['ordinal']==step['reexportOrdinal']and(q['importedName']or step['symbol'])==step['alias']
  elif step is steps[-1]:assert q and not(q['flags']&8)and q['address']==leaf['offset']
  nativePins += [fp,cp]
 v=dict(actualImport=actual,requiredLoad=load,actualDefinition=leaf,actualResolutionPath=steps);new.append(v);rows.append(v)
assert len(rows)==49 and len(new)==7
assert {v['actualImport']['name']for v in new}=={'__ZSt9terminatev','___cxa_begin_catch','___cxa_current_exception_type','___cxa_end_catch','___cxa_rethrow','__ZTISt9exception','_OBJC_EHTYPE_$_NSException'}
pg=M((root/rel/'ParavirtualizedGraphics27.dylib').read_bytes());pgrows=[]
for actual in pg.imports[261:]:
 assert actual['ordinal']==10 and not actual['weak']and actual['name']in md.exports
 pgrows.append(dict(actualImport=actual,requiredLoad='@loader_path/MD',target=pin(o/'MD'),targetUUID=md.uuid,definition=md.exports[actual['name']]))
cr=[]
for i in [1203,1204]:
 actual=child.imports[i];assert actual['ordinal']==3 and not actual['weak']and actual['name']in md.exports
 cr.append(dict(actualImport=actual,requiredLoad='@loader_path/MD',target=pin(o/'MD'),targetUUID=md.uuid,definition=md.exports[actual['name']]))
assert len(pgrows)==5 and len(child.imports)==1205
closure=dict(schema='MD initializer exception observation: 42 namespace-preserved native rows plus seven real EH native exports',nativeIndex=og['nativeIndex'],actualProvider=pin(o/'MD'),actualProviderNativeRows=rows,strongRows=49,unresolved=[],newActualNativeRows=new,inheritedNativeRowsProof=pin(old/'incremental-native-closure.json'),inheritedNativeRequiredNamespacesAndNameWeakAddendUnchanged=True,oldOrdinalChangesDueOnlyNewLibCxxLoad=True,selectedPGImportsNewStrongDefinitions=pgrows,inheritedSelectedChildDefinitions=cr,oldFullRuntimeNotRecomputed=True)
dump(o/'incremental-native-closure.json',closure)
contract=dict(symbol='_VM27OwnedChildInitializeVMResultDiagnosticV1',existingRequiredOrdinal=3,existingImportIndex=1204,originalInitializerRVA=0x2e9b24,selectedCallerReturnRVA=0x24a78,actualArguments=['x0 explicit native Result destination','x1 original VM object','x2 original config'],originalFunctionCalledOnce=True,noHiddenResultX8=True,allThreePointersPassedUnchanged=True,catchOnlyForObservationAndOriginalRethrow=True,cppStandardExceptionActualTypeNameAndWhat=True,whatCalledOnceOnlyOnCaughtStdException=True,unknownExceptionOnlyNativeCurrentTypeNoUnknownWhat=True,objectiveCOnlyOriginalNameAndReason=True,cppRethrowUsesBareThrow=True,objectiveCRethrowUsesBareAtThrow=True,loggingSideExceptionsContainedAndOriginalPreserved=True,diagnosticReadFailureOnlyUnavailable=True,maximumBoundaryInvocationsLogged=8,maximumTextBytesPerNameAndReason=256,maximumEscapedTextBytes=1024,boundedPrefixNotClaimedCompleteLongText=True,objectiveCMayHaveBothCppUnknownAndObjCObservation=True,incomingErrnoRestoredBeforeOriginalAndNativeErrnoRestoredAfterObservation=True,resultAndGuestStructuresNeverModified=True,normalReturnUsesInheritedActualResultReader=True,entryDoesNotClaimNormalReturnOrException=True,exceptionObservationDoesNotClaimGuestStarted=True,originalUUIDAndCodePrefixAndActualCallerGatesRetained=True,UIDAndEffectiveUID=501,CSValidPlatformMask=0x04000001,parentMDAndPGCPUAndVMMAndShaderAndChildEntitlementsUnchangedRequired=True)
for f in ['compile-metal.json','compile-bridge.json','link.json','md-validate.json']:assert json.loads((o/f).read_bytes())['exit']==0
c=dict(schema='HOST-only MD V10 genuine initializer exception observation and original rethrow; no new Child port',baselineRuntimeCandidate=pin(bp),providerKey='MD',roles=['child'],newProvider=pin(o/'MD'),actualProviderPin=pin(o/'MD'),originalProvider=pin(root/rel/'MD'),originalChildMain=pin(original),source=pin(S/'modern_metal_device_array_v10.m'),exceptionBridgeSource=pin(S/'vm27_owned_child_exception_bridge_v1.mm'),header=pin(S/'vm27_owned_child_exception_bridge_v1.h'),inheritedFrozenV9Source=pin(S/'modern_metal_device_array_v9.m'),inheritedV9SourceCandidate=pin(old/'candidate.json'),builder=pin(__file__),graph=pin(o/'incremental-native-closure.json'),verification=pin(o/'incremental-native-closure.json'),exceptionBoundaryContract=contract,historicalInitializationResultContract=oc['initializationResultContract'],historicalNoCatchContractIsNotCurrentBehavior=True,actualIOSObjects=[pin(o/'modern_metal_device_array_v10.o'),pin(o/'vm27_owned_child_exception_bridge_v1.o')],actualIOSCompile=[pin(o/'compile-metal.json'),pin(o/'compile-bridge.json')],actualIOSLink=pin(o/'link.json'),actualMDValidate=pin(o/'md-validate.json'),compileLinkAndMDValidateExit=[0,0,0,0],providerUUID=md.uuid,actualProviderExportCount=8,actualProviderNativeImportCount=49,actualNativeImportsAdded=7,actualChildImportsOrCodeChanged=False,actualChildRequiredLoadsChanged=False,actualCurrentChildConsumerDefinitionsUpdated=2,inheritedPGOwnedImportDefinitionCount=5,parentMDWholeUnchangedRequired=True,PGWholeByteUnchangedRequired=True,CPUAndVMMProvidersAndChild14EntitlementsAndShaderUnchangedRequired=True,actualNormal30Start=pin(N/'independent27-app40-normal-guest-lifecycle-v30-attempt1/device-receipts/start/stdout'),actualNormal30USB=pin(N/'actual-normal30-child-breadcrumb-live-usb-syslog-v2/stdout'),observedInitializerEntryWithoutObservedNormalReturn=True,actualExceptionNotYetObserved=True,actualDeviceOperations=0,actualExceptionObservationExecuted=False,actualGuestStarted=False,codeSignedByProductSigner=False)
dump(o/'candidate.json',c)
files=[pin(o/'candidate.json')]+nativePins
for k in ['baselineRuntimeCandidate','newProvider','originalProvider','originalChildMain','source','exceptionBridgeSource','header','inheritedFrozenV9Source','inheritedV9SourceCandidate','builder','graph','actualIOSLink','actualMDValidate','actualNormal30Start','actualNormal30USB']:files.append(c[k])
files+=c['actualIOSObjects']+c['actualIOSCompile']
for f in ['compile-metal.stdout','compile-metal.stderr','compile-bridge.stdout','compile-bridge.stderr','link.stdout','link.stderr','md-validate.stdout','md-validate.stderr','exports.txt']:files.append(pin(o/f))
for f in ['modern_metal_device_array_v8.m','modern_metal_device_array_v6.m','modern_metal_device_array_v5.m','modern_metal_device_array.m','vm27_owned_child_vm_result_diagnostic_v1.h','vm27_owned_child_error_reason_diagnostic_v1.h','vm27_owned_pvg_unified_storage_v1.h','vm27_owned_pvg_address_range_capability_v3.h','vm27_owned_pvg_address_range_capability_v2.h','vm27_owned_pvg_buffer_capability_v1.h']:files.append(pin(S/f))
dump(o/'freeze.json',dict(schema='Completed HOST actual compile/link/native EH closure freeze; source immutable',candidate=pin(o/'candidate.json'),files=list({v['path']:v for v in files}.values()),noModelsOrFullRuntimeGraphRepeated=True,actualDeviceOperations=0))
print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),MD=pin(o/'MD'),UUID=md.uuid,exports=8,imports=49,newNative=7,initializeDefinition=md.exports['_VM27OwnedChildInitializeVMResultDiagnosticV1']),indent=2))
