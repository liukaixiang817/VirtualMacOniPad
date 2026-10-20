#!/usr/bin/env python3
"""Freeze exact native nullable-queue USBH V3; no device/signing."""
from pathlib import Path
import json,hashlib,runpy,copy
R=Path('/Users/liukaixiang/Documents/VirtualMacOniPad');N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host';O=N/'owned-usbh-avp-nullable-queue-source-local-v3-attempt1';bp=N/'independent27-signed-runtime-child-usbh-offline-product-v31-attempt1/candidate.json';ni=N/'current-native-header-export-index-v3/index.json'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
ns=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'));M=ns['MachO'];base=json.loads(bp.read_bytes());rel='child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS';root=Path(base['runtimeRoot']);old=root/rel/'VM27USBUnavailable.dylib';childPath=root/rel/'com.apple.Virtualization.VirtualMachine';child=M(childPath.read_bytes());image=M((O/'VM27USBUnavailable.dylib').read_bytes());oldM=M(old.read_bytes());nd=json.loads(ni.read_bytes())['images']
assert len(image.exports)==19 and set(image.exports)==set(oldM.exports)and len(image.imports)==45
assert [(v['cmd'],v['path'])for v in image.loads]==[(v['cmd'],v['path'])for v in oldM.loads]
def resolve(path,name,seen=()):
 if (path,name)in seen or path not in nd:return []
 im=nd[path];q=im['definitions'].get(name);seen=seen+((path,name),)
 if q:
  if q['flags']&8:
   dep=next(x for x in im['dependencies']if x['ordinal']==q['ordinal']);alias=q.get('alias')or q.get('importedName')or name
   return [([dict(path=path,symbol=name,reexportOrdinal=q['ordinal'],alias=alias)]+steps,leaf)for steps,leaf in resolve(dep['path'],alias,seen)]
  return [([dict(path=path,symbol=name)],dict(path=path,symbol=name,UUID=im['UUID'],offset=q['offset'],VA=im['base']+q['offset'],actualCompleteCommands=im['actualCompleteCommands'],actualCompleteExportSource=im['actualCompleteExportSource']['rangePin']))]
 out=[]
 for dep in im['dependencies']:
  if dep['command']==0x8000001f:out += [([dict(path=path,symbol=name,reexportOrdinal=dep['ordinal'])]+steps,leaf)for steps,leaf in resolve(dep['path'],name,seen)]
 return out
rows=[];nativePins=[];tries={}
for a in image.imports:
 load=image.loads[a['ordinal']-1]['path'];routes=resolve(load,a['name']);assert len({(v['path'],v['symbol'],v['offset'])for _,v in routes})==1,(load,a)
 steps,leaf=routes[0]
 for step in steps:
  im=nd[step['path']];fp=im['actualCompleteExportSource']['rangePin'];cp=im['actualCompleteCommands']
  if fp['path']not in tries:
   assert pin(fp['path'])==fp and pin(cp['path'])==cp;tries[fp['path']]=ns['trie'](Path(fp['path']).read_bytes())[0];nativePins.extend([fp,cp])
  q=tries[fp['path']].get(step['symbol'])
  if 'alias'in step:assert q and q['flags']&8 and q['ordinal']==step['reexportOrdinal']and(q['importedName']or step['symbol'])==step['alias']
  elif step is steps[-1]:assert q and not(q['flags']&8)and q['address']==leaf['offset']
 rows.append(dict(actualImport=a,requiredLoad=load,actualDefinition=leaf,actualResolutionPath=steps))
selected=[]
for a in child.imports:
 if a['ordinal']>0 and child.loads[a['ordinal']-1]['path']=='@loader_path/VM27USBUnavailable.dylib':
  assert a['ordinal']==24 and not a['weak']and a['name']in image.exports
  selected.append(dict(actualImport=a,requiredLoad='@loader_path/VM27USBUnavailable.dylib',target=pin(O/'VM27USBUnavailable.dylib'),targetUUID=image.uuid,definition=image.exports[a['name']]))
assert selected
closure=dict(schema='Exact new child USBH native45 and unchanged required Child24 consumers; no whole runtime graph repeated',nativeIndex=pin(ni),actualProvider=pin(O/'VM27USBUnavailable.dylib'),actualProviderNativeRows=rows,actualChildConsumerDefinitions=selected,strongRows=45,unresolved=[],oldFullRuntimeNotRecomputed=True)
dump(O/'incremental-native-closure.json',closure)
source=S/'modern_usbh_owned_avp_offline_v3.m';frozen=S/'modern_usbh_host_unavailable_compat.m';text=source.read_text();original=frozen.read_text();assert original[original.index('static CFMutableDictionaryRef ClosedMatchingDictionary'):original.index('@implementation IOUSBHostControllerInterface')]in text;assert original[original.index('@implementation IOUSBHostCIDeviceStateMachine'):]in text
for label in ['compile','link','validate']:assert json.loads((O/(label+'.json')).read_bytes())['exit']==0
contract=dict(mode='owned-normal-boot-AVP-external-host-mediation-offline',actualSubclass='VZIOUSBHostControllerInterface',actualCallerReturnRVA=0x2449e8,ChildUUID=child.uuid,UIDAndEffectiveUID=501,CSValidPlatformMask=0x04000001,actualChildPath='/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/'+rel+'/com.apple.Virtualization.VirtualMachine',nativeSuperclassBytes=320,subclassRawInstanceStart=8,subclassRawInstanceSize=16,actualSuperclassAdjustment=312,runtimeSubclassInstanceSize=328,actualIvarOffset=0x140,originalInitializerPrefix32BytesGuard=True,realNSObjectInitialization=True,actualCapabilitiesCopied=True,originalCapabilityOrderUnchanged=True,ownedSerialQueueRetained=True,originalCommandAndDoorbellBlocksCopied=True,originalInterestFunctionRetainedAsPointerOnly=True,controllerState='Off',externalHostPortState='disconnected-no-port-power-command',noHostCICommandsGenerated=True,noDoorbellsGenerated=True,noInterruptResponseFabricated=True,kernelUserClientCreated=False,physicalPassthroughUnavailable=True,externalControllerPortDeviceEndpointOperationsExplicitUnsupported=True,guestAVPNodeRetained=True,standardGuestUSBKeyboardPointingAndXHCIUnchanged=True,DFUOnlyNotClaimed=True,guestDisconnectedSemanticsNotYetDeviceObserved=True,actualDeviceBootRequiredToDetermineNormalBootEffect=True,destroyReleasesCallbacksQueueCapabilityAndWeakOwner=True,noNewAsyncWorkOrTimers=True,actualDestroyCallEvidence=dict(guestImplDestructorRVA=0x244be8,cleanupQueueBlockRVA=0x248ddc,destroyCallRVA=0x248e0c,destroySelectorStubRVA=0x414500,followingOriginalReleaseRVA=0x248e24),headerABIUnchanged=True,parentUSBHWholeUnchangedRequired=True)
contract.update(nativeCallerQueueNil=True,nativeCallerInterruptRateHz=0,nullableQueueNativeSemanticsRestored=True,realDefaultSerialQueueCreatedWhenNil=True,nonNilCallerQueueRetained=True,allocationFailureReturnsNilAndARCReleasesPartialState=True,zeroInterruptRateUnchanged=True)
c=dict(schema='HOST-only USBH V3 exact native nullable-queue fix; physical host CI deferred honestly',baselineRuntimeCandidate=pin(bp),providerKey='USBH',roles=['child'],runtimeProviderBasename='VM27USBUnavailable.dylib',runtimeProviderIdentity='child:VM27USBUnavailable.dylib',newProvider=pin(O/'VM27USBUnavailable.dylib'),actualProviderPin=pin(O/'VM27USBUnavailable.dylib'),originalProvider=pin(old),originalChildMain=pin(childPath),source=pin(source),header=pin(S/'modern_usbh_host_unavailable_compat.h'),inheritedFrozenUnavailableSource=pin(frozen),builder=pin(__file__),graph=pin(O/'incremental-native-closure.json'),verification=pin(O/'incremental-native-closure.json'),offlineAVPSuperclassContract=contract,actualIOSObject=pin(O/'USBH.o'),actualIOSCompile=pin(O/'compile.json'),actualIOSLink=pin(O/'link.json'),actualProviderValidate=pin(O/'validate.json'),compileLinkValidateExit=[0,0,0],providerUUID=image.uuid,actualProviderExportCount=19,actualProviderNativeImportCount=44,actualRequiredChildLoadOrdinal=24,actualChildCodeImportsLoadsUnchanged=True,parentMDPGAndHVAndShaderAnd14ChildEntitlementsUnchangedRequired=True,actualFailureCrash=pin(N/'independent27-normal33-child2726-crash-readonly-v1-attempt1/captured-child2726-crash.json'),actualNativeResourceAbsentReceipt=pin(N/'ipad-native-usbh-resources-ioreg-readonly-v1-attempt1/receipt.json'),actualDeviceOperations=0,codeSignedByProductSigner=False,actualOwnedOfflineInitializationExecuted=False,actualUSBInputVerified=False,actualGuestStarted=False)
c['nullableQueueSourceReview']=pin(N/'owned-usbh-avp-nullable-queue-source-v3-attempt1/source-review.json')
c['baselineUSBHSourceV2']=pin(S/'modern_usbh_owned_avp_offline_v2.m')
dump(O/'candidate.json',c);files=[pin(O/'candidate.json')]+nativePins
for k in ['baselineRuntimeCandidate','newProvider','originalProvider','originalChildMain','source','header','inheritedFrozenUnavailableSource','builder','graph','actualIOSObject','actualIOSCompile','actualIOSLink','actualProviderValidate','actualFailureCrash','actualNativeResourceAbsentReceipt','nullableQueueSourceReview','baselineUSBHSourceV2']:files.append(c[k])
for f in ['exports.txt','compile.stdout','compile.stderr','link.stdout','link.stderr','validate.stdout','validate.stderr']:files.append(pin(O/f))
dump(O/'freeze.json',dict(schema='Actual HOST-only owned USBH AVP offline source/product/route freeze',candidate=pin(O/'candidate.json'),files=list({v['path']:v for v in files}.values()),noModelsOrFullGraphRepeated=True,actualDeviceOperations=0))
print(json.dumps(dict(candidate=pin(O/'candidate.json'),freeze=pin(O/'freeze.json'),provider=pin(O/'VM27USBUnavailable.dylib'),UUID=image.uuid,imports=45,exports=19,actualChildConsumers=len(selected)),indent=2))
