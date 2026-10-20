#!/usr/bin/env python3
"""Finite App8 source/IR delta and actual signed-main/anchor inspection."""
from pathlib import Path
import argparse,ast,difflib,hashlib,importlib.util,json,plistlib,re,struct,sys
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';S=R/'VirtualMac/vz/host'
checks=0
def need(value,message):
 global checks;checks+=1
 if not value:raise ValueError(message)
def pin(path):
 p=Path(path).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def check_pin(row):need(pin(row['path'])==row,'actual frozen pin: '+row['path'])
def frozen(path):
 rows=json.loads(Path(path).read_bytes())['files']
 for row in rows:check_pin(row)
 return len(rows)
def import_module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def der_items(data):
 at=0;items=[]
 while at<len(data):
  need(at+2<=len(data),'complete DER tag/length');tag,first=data[at],data[at+1];at+=2
  if first&128:
   count=first&127;need(0<count<=4 and at+count<=len(data) and data[at]!=0,'finite minimally encoded DER length')
   length=int.from_bytes(data[at:at+count],'big');at+=count;need(length>=128,'canonical DER long length')
  else:length=first
  need(at+length<=len(data),'complete DER value');value=data[at:at+length];at+=length
  items.append((tag,value))
 need(at==len(data),'exact DER container');return items
def der_value(tag,value):
 if tag==1:
  need(value in (b'\0',b'\xff'),'canonical DER Boolean');return value==b'\xff'
 if tag==12:return value.decode('utf-8')
 if tag==0x30:return [der_value(t,v)for t,v in der_items(value)]
 raise ValueError('unsupported actual DER entitlement type')
def der_entitlements(blob):
 need(struct.unpack_from('>I',blob)[0]==0xfade7172,'actual DER entitlement blob magic')
 top=der_items(blob[8:]);need(len(top)==1 and top[0][0]==0x70,'actual Apple application-container entitlement schema')
 envelope=der_items(top[0][1]);need(len(envelope)==2 and envelope[0]==(2,b'\1') and envelope[1][0]==0xb0,'actual version1 dictionary container')
 result={}
 for tag,value in der_items(envelope[1][1]):
  need(tag==0x30,'actual dictionary pair sequence');pair=der_items(value)
  need(len(pair)==2 and pair[0][0]==12,'actual string entitlement key and one value')
  key=pair[0][1].decode('utf-8');need(key not in result,'unique DER entitlement key');result[key]=der_value(*pair[1])
 return result
def signature_slots(data):
 at=32;extent=None
 for _ in range(struct.unpack_from('<I',data,16)[0]):
  cmd,size=struct.unpack_from('<II',data,at)
  if cmd==0x1d:extent=struct.unpack_from('<II',data,at+8)
  at+=size
 need(extent is not None,'actual signed-main signature command');start,size=extent;blob=data[start:start+size]
 result={}
 for i in range(struct.unpack_from('>I',blob,8)[0]):
  key,offset=struct.unpack_from('>II',blob,12+8*i);length=struct.unpack_from('>I',blob,offset+4)[0];result[key]=blob[offset:offset+length]
 return result
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);out=ap.parse_args().out.resolve()
 need(out.parent==N and not out.exists(),'fresh finite independent review')
 folder=N/'independent27-app-isolated-log-source-v8-attempt1';candidate=folder/'candidate.json';freeze=folder/'freeze.json'
 signed_folder=N/'independent27-signed-app-product-v1-attempt1';signed_path=signed_folder/'candidate.json';signed_freeze=signed_folder/'freeze.json'
 linked_path=N/'independent27-actual-app-linked-v8-attempt1/candidate.json'
 need(pin(candidate)['sha256']=='ca65732b060ec3f473a311e73af075dff0b18be0c7c9099bf826e7c63d2418dc','exact App8 source candidate')
 need(pin(signed_path)['sha256']=='1c47f9e95260769ef5902a0b0a6a5f6acb01523cc4335ee8bb5d429bb22779d0','exact actual signed App product')
 j=json.loads(candidate.read_bytes());signed=json.loads(signed_path.read_bytes());linked=json.loads(linked_path.read_bytes())
 frozen_counts={str(path):frozen(path)for path in [freeze,signed_freeze]}
 source=Path(j['source']['path']);text=source.read_text();prior_path=Path(j['prior']['path']);prior=json.loads(prior_path.read_bytes());before_path=Path(prior['source']['path']);before=before_path.read_text()
 check_pin(j['prior']);check_pin(prior['source'])
 expected=''.join(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile=str(before_path),tofile=str(source)))
 need(expected==Path(j['sourceDiff']['path']).read_text(),'exact full App7 to App8 source diff')
 builder=Path(j['builder']['path']);tree=ast.parse(builder.read_text());owner_main=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='main')
 rebuilt=before;replacements=0
 for node in owner_main.body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='source'for t in node.targets) and isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Name)and node.value.func.id=='replace_once':
   old,new=map(ast.literal_eval,node.value.args[1:]);need(rebuilt.count(old)==1,'finite unique source replacement');rebuilt=rebuilt.replace(old,new,1);replacements+=1
 need(replacements==7 and rebuilt==text,'only actual atomic accesses/comment/log/legacy-unlink delta')
 need(text.count('__atomic_load_n(&gIndependent27ExplicitRuntimeStartupPending, __ATOMIC_RELAXED)')==2 and text.count('__atomic_store_n(&gIndependent27ExplicitRuntimeStartupPending,')==2,'exact source two atomic loads and two stores')
 uses=[line for line in text.splitlines()if 'gIndependent27ExplicitRuntimeStartupPending' in line]
 need(len(uses)==5 and all('__atomic_' in line or 'static BOOL ' in line for line in uses),'no ordinary concurrent pending access')
 ir_path=folder/'app.ll';ir=ir_path.read_text();memory_lines=[line for line in ir.splitlines()if '@gIndependent27ExplicitRuntimeStartupPending' in line and ('load 'in line or 'store 'in line)]
 need(len(memory_lines)==4 and sum('load atomic i8' in line for line in memory_lines)==2 and sum('store atomic i8' in line for line in memory_lines)==2 and all('monotonic' in line for line in memory_lines),'actual optimized arm64e IR four monotonic atomic accesses')
 need('store atomic i8 1, ptr @gIndependent27ExplicitRuntimeStartupPending' in ir and 'store atomic i8 0, ptr @gIndependent27ExplicitRuntimeStartupPending' in ir,'real admission true/maincompletion false publication')
 control_term='void (^actualRuntimeControl)(void)=^{' 
 control=text[text.index(control_term):text.index('typedef struct {\n    UIView *container;',text.index(control_term))]
 old_control=before[before.index(control_term):before.index('typedef struct {\n    UIView *container;',before.index(control_term))]
 need(control==old_control,'actual construction/bind/input/display/start main-queue control unchanged')
 need('dispatch_async(gIndependent27ExplicitRuntimeStartupQueue' in text and 'VM27IndependentAppRuntimeLoadV1(startupRoot, &runtimeError)' in text and 'dispatch_async_f(' in text,'genuine background bootstrap and worker retained')
 need('dispatch_sync(dispatch_get_main_queue(),actualRuntimeControl);' in text,'true main VM control identity retained')
 need('const char *applicationLog = VZIndependent27SourceRouteSelected()\n        ? "/tmp/VirtualMacIndependent27.log" : "/tmp/VirtualMac.log";' in text and text.count('freopen(applicationLog, "a",')==2,'true independent App stdout/stderr isolated')
 need('if (!VZIndependent27SourceRouteSelected()) {\n        unlink("/tmp/vzxpchook.log");\n        unlink("/tmp/vmmhook.log");\n        unlink("/tmp/vmm.stderr.log");\n    }' in text,'independent worker does not erase real legacy logs')
 backend=Path(j['backendSource']['path']).read_text();need('return @"27";'in backend,'real standalone profile selects new log even before inherited input-route initialization')
 check_pin(signed['sourceCandidate']);check_pin(linked['sourceCandidate']);need(signed['sourceCandidate']==pin(linked_path)and linked['sourceCandidate']==pin(candidate),'actual signed main links this App8 source')
 need(len(linked['sourceFiles'])==30 and len(linked['objects'])==30,'actual thirty strong linked units including true anchor')
 for row in linked['sourceFiles']+linked['actualIncludeClosure']+linked['objects']+linked['appFiles']:check_pin(row)
 need(sum(Path(row['path']).name=='vm27_independent_app_runtime_v3.m'for row in linked['sourceFiles'])==1 and not any(Path(row['path']).name in ['vm27_independent_app_runtime_v1.m','vm27_independent_app_runtime_v2.m']for row in linked['sourceFiles']),'one actual Runtime3 compiled translation unit')
 commands=json.loads(linked_path.parent.joinpath('commands.json').read_bytes());need(all(row['exit']==0 for row in commands),'actual app compile/link/resources/validate completed')
 link=next(row['argv']for row in commands if row['label']=='link-app');need('-Wl,-no_adhoc_codesign'in link and '-Wl,-export_dynamic'in link,'actual strong unsigned-link product with visible anchor')
 check_pin(signed['runtimeCandidate']);runtime_path=Path(signed['runtimeCandidate']['path']);runtime=json.loads(runtime_path.read_bytes())
 need(runtime_path.parent.name=='independent27-signed-runtime-product-v1-attempt3','fresh genuine Root18 signed runtime, not stale anchor')
 check_pin(runtime['anchorSource']);check_pin(runtime['manifest']);need(runtime['anchorSource']==signed['realCompiledManifestAnchor'] and runtime['anchorSource']in linked['sourceFiles'],'matching actual final manifest anchor compiled')
 manifest_bytes=Path(runtime['manifest']['path']).read_bytes();manifest=plistlib.loads(manifest_bytes)
 need(linked['runtimeRoot']==runtime['canonicalDeviceRoot']==signed['runtimeRoot'],'actual configured canonical runtime root joins signed manifest')
 parent_cpu=next(row for row in manifest['files']if row['id']=='parent:VM27HVVMProduction.dylib')
 need(parent_cpu['bytes']>328600 and parent_cpu['kind']=='mach-o','actual signed production Root18 included')
 parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py';reader=import_module('actual_app8_macho',parser)
 unsigned=reader.MachO(Path(linked['binary']['path']).read_bytes());actual=reader.MachO(Path(signed['binary']['path']).read_bytes())
 need(actual.uuid==unsigned.uuid and actual.sections==unsigned.sections and actual.imports==unsigned.imports and actual.exports==unsigned.exports and actual.binds==unsigned.binds,'signing preserves actual UUID/sections/imports/exports/entire PAC binding metadata')
 for section in unsigned.sections:
  at,size=section['fileoff'],section['size']
  if at and size and section['flags']&255 not in (1,12,18):need(unsigned.data[at:at+size]==actual.data[at:at+size],'actual compiled section bytes unchanged by signing')
 digest_rva=actual.exports['_VM27IndependentRuntimeManifestSHA256V1']['address'];size_rva=actual.exports['_VM27IndependentRuntimeManifestBytesV1']['address']
 digest_at=actual.file(actual.base+digest_rva);size_at=actual.file(actual.base+size_rva)
 need(actual.data[digest_at:digest_at+32]==hashlib.sha256(manifest_bytes).digest()and struct.unpack_from('<Q',actual.data,size_at)[0]==len(manifest_bytes),'actual signed main memory contains exact fresh manifest digest and extent')
 for symbol in ['_VM27IndependentAppRuntimePreflightV1','_VM27IndependentAppRuntimeLoadV1','_VM27IndependentAppRuntimeBindGuestV1','_VM27IndependentAppRuntimeGuestStartedV1']:
  need(actual.exports[symbol]['flags']==0,'actual genuine runtime C API strong definition')
 need(not any('VZHostCompat'in row['path']or 'ModernCPURuntimeCompat'in row['path']for row in actual.loads),'no old Ventura backend direct App load')
 signed_reader_path=R/'VirtualMac/scripts/development/review-independent27-signed-runtime-product-v1.py';signature_reader=import_module('actual_app8_signature',signed_reader_path)
 app=Path(signed['app']);binary=Path(signed['binary']['path']);info=(app/'Info.plist').read_bytes();resources=(app/'_CodeSignature/CodeResources').read_bytes()
 actual_signature=signature_reader.signed_image(binary,signed['actualSignature'],{1:info,3:resources})
 need(json.loads(json.dumps(actual_signature))==signed['actualSignature'],'independent primary53pages/realInfoResources specialslot parse equals actual signed receipt')
 slots=signature_slots(binary.read_bytes());xml=plistlib.loads(slots[5][8:]);der=der_entitlements(slots[7]);desired=plistlib.loads((S/'VirtualMac.entitlements').read_bytes())
 need(xml==der==desired==actual_signature['embeddedEntitlements'],'actual DER and XML entitlements exactly match real signed App permission source')
 need(all(xml[key]is True for key in ['platform-application','com.apple.private.hypervisor','com.apple.private.virtualization']),'native Boolean rights required by Acquisition3 present in actual signed main')
 signed_info=plistlib.loads(info);need(signed_info['CFBundleIdentifier']=='com.mac.virtual.independent27'and signed_info['CFBundleExecutable']=='VirtualMacIndependent27'and signed_info['CFBundleURLTypes'][0]['CFBundleURLSchemes']==['virtualmac27'],'actual own App identity and explicit URL scheme signed')
 need(signed_info['VirtualMacIndependent27ActualNICCount']==0 and signed_info['VirtualMacIndependent27ActualAudioDeviceCount']==0 and signed_info['VirtualMacIndependent27ExplicitLaunchOnly']is True,'true signed first-visible profile stays NIC0/audio0/explicitlaunch')
 need(signed['signedMainBytes']==binary.stat().st_size==869696 and binary.stat().st_size<=2097152,'actual signed main fits genuine Runtime3 self inspection')
 need(signed['actualSignature']['cdhash']=='001f8728486dba76a6a852519643a0c97f9ea225','exact signed App CodeDirectory identity')
 need(not signed['actualAppLaunched'] and not signed['actualGuestBoot'] and signed['deviceOperations']==0 and signed['trustCacheOperations']==0,'host signing is not actual device/native admission')
 out.mkdir(mode=0o700)
 review=dict(schema='App8 actual atomic/background/isolation and signed main finite independent review v1',finiteLocalScopePassed=True,findings=[],checks=checks,
  sourceCandidate=pin(candidate),sourceFreeze=pin(freeze),actualSource=pin(source),actualIR=pin(ir_path),sourceDiff=j['sourceDiff'],
  linkedCandidate=pin(linked_path),signedCandidate=pin(signed_path),signedFreeze=pin(signed_freeze),verifiedFrozenPinCounts=frozen_counts,
  exactSevenSourceChangesVerified=True,actualTwoAtomicReadsTwoAtomicWritesVerified=True,
  allRuntimePendingAccessesActuallyAtomic=True,backgroundAndMainVMOwnershipUnchanged=True,
  independentLogPath='/tmp/VirtualMacIndependent27.log',legacyLogUnlinksExcludedFromIndependentWorker=True,
  actualLinkedUnits=30,actualSignedMain=pin(binary),actualSignature=actual_signature,
  actualDERAndXMLEntitlementsAgree=True,realSignedMainAnchorDigestAndSizeVerified=True,
  runtimeCandidate=pin(runtime_path),realFinalManifest=runtime['manifest'],actualMainCodeSectionsPACAndImportsPreserved=True,
  readyForExactControllerPeerReview=True,actualDeviceLaunchReadyWithoutAdditionalReviewOrAuthorization=False,
  actualAppLaunched=False,actualNativeVMCreated=False,deviceOperations=0,nativeOperations=0,trustCacheOperations=0,actualGuestBoot=False,
  limitations=['This proves host source/IR/link/signature/anchor composition only. Real UIApplication launch, original child construction, native mobile kernel admission, VMM boot, framebuffer delivery and guest SSH remain unexecuted.',
  'The actual signed experimental configuration deliberately has no NIC and no audio device. Final real networking/SSH22222 remains required.',
  'Atomic relaxed accesses remove the App7 compiler speculative-load race boundary. The VM control/input/display ownership profile remains actual main serial queue; this does not authorize arbitrary cross-thread VM control.',
  'The isolated log is selected by the independent27 backend profile. It does not establish actual device file permissions or actual log delivery before device execution.'])
 (out/'review.json').write_text(json.dumps(review,indent=2)+'\n')
 files=[candidate,freeze,source,ir_path,Path(j['sourceDiff']['path']),prior_path,before_path,builder,Path(j['packageBuilder']['path']),linked_path,
  signed_path,signed_freeze,binary,app/'Info.plist',app/'_CodeSignature/CodeResources',Path(linked['binary']['path']),runtime_path,
  Path(runtime['anchorSource']['path']),Path(runtime['manifest']['path']),S/'VirtualMac.entitlements',parser,signed_reader_path,
  N/'app7-background-startup-independent-review-v1-attempt1/review.json',N/'root18-mobile-capability-independent-review-v1-attempt1/review.json',
  Path(__file__).resolve(),out/'review.json']
 (out/'freeze.json').write_text(json.dumps(dict(files=[pin(p)for p in files],deviceOperations=0,nativeOperations=0,trustCacheOperations=0),indent=2)+'\n')
 print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=checks,findings=[])))
if __name__=='__main__':main()
