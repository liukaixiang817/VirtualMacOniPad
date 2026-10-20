#!/usr/bin/env python3
"""Freeze a new native-identity capability admission object; no device/sign."""
import argparse,difflib,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.parent==N and not o.exists();o.mkdir();commands=[];includes={}
 old=N/'cpu-dtr-factory-local-v21-attempt2/candidate.json';j=json.loads(old.read_bytes())
 freeze=old.parent/'freeze.json'
 for row in json.loads(freeze.read_bytes())['files']:assert pin(row['path'])==row,row['path']
 acq=S/'modern_cpu_config_capability_acquisition_v3.c';previous=S/'modern_cpu_config_capability_acquisition_v2.c'
 fixture=S/'test-modern-cpu-capability-admission-v3.c'
 sources=[acq,fixture,S/'modern_cpu_native_capability_seed.c',S/'modern_cpu_tlbi_capability_values_v1.c',S/'modern_cpu_config_capability_query_v1.S']
 initial=[pin(p)for p in sources]
 def run(label,args,expect=0):
  args=list(map(str,args));cp=subprocess.run(args,capture_output=True,timeout=60)
  (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(label=label,argv=args,exit=cp.returncode,expectedExit=expect));save(o/'commands.json',commands)
  assert (cp.returncode==0 if expect==0 else cp.returncode!=0),(label,cp.stderr.decode(errors='replace'))
  return cp.stdout
 mac=['xcrun','clang','-O2','-std=c11','-Wall','-Wextra','-Werror','-I',S]
 models={}
 for mode in ('normal','san'):
  flags=mac+(['-fsanitize=address,undefined','-fno-omit-frame-pointer']if mode=='san'else[])
  run(mode+'-compile',flags+[fixture,sources[2],sources[3],'-framework','CoreFoundation','-o',o/mode])
  models[mode]=json.loads(run(mode+'-run',[o/mode]));assert models[mode]['checks']==373 and models[mode]['actualNativeOperations']==0
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-O2','-std=c11','-Wall','-Wextra','-Werror','-fvisibility=hidden','-I',S]
 objects=[]
 for p in (acq,sources[2],sources[3],sources[4]):
  obj=o/(p.stem+'.ios.o');run('ios-'+p.stem,ios+['-c',p,'-o',obj]);objects.append(obj)
  dep=run('deps-'+p.stem,ios+['-MM',p]).decode().replace('\\\n',' ').split(':',1)[1]
  for item in shlex.split(dep):
   q=pathlib.Path(item).resolve()
   if q.is_file():includes[str(q)]=pin(q)
 typed=o/'typed-caller.cpp';typed.write_text('extern "C" {\n#include "modern_cpu_config_capability_acquisition_v2.h"\n}\nextern "C" void typed_capability_v3(VM27CPUCapabilitiesV2 *c,VM27CPURawIPAPairV2 *p,VM27CPUTLBICapabilityValueV1 *t){VM27CPUConfigAcquireCapabilitiesV2(c);VM27CPUConfigAcquireRawIPAPairV2(p);VM27CPUConfigAcquireTLBICapabilityV1(t);}\n')
 typedObj=o/'typed-caller.ios.o'
 run('typed-cpp-ios',['xcrun','--sdk','iphoneos','clang++','-arch','arm64e','-miphoneos-version-min=16.1','-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',typed,'-o',typedObj])
 run('typed-native-strong-link',ios+['-dynamiclib',typedObj]+objects+['-framework','CoreFoundation','-framework','Security','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',o/'TypedCapabilityAdmissionV3.unsigned.dylib'])
 run('typed-native-validate',['xcrun','dyld_info','-validate_only',o/'TypedCapabilityAdmissionV3.unsigned.dylib'])
 run('fixture-ios-refused',ios+['-DVM27_CPU_CAPABILITY_ADMISSION_TESTING=1','-c',acq,'-o',o/'forbidden-fixture.ios.o'],expect=1)
 assert 'fixture hooks are forbidden on iOS' in (o/'fixture-ios-refused.stderr').read_text()
 run('ios-symbols',['xcrun','nm','-m',objects[0]])
 undefined=run('ios-undefined',['xcrun','nm','-u',objects[0]]).decode().splitlines()
 imports=sorted(x.strip() for x in undefined if x.strip())
 parser=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec=importlib.util.spec_from_file_location('capmacho',parser);lib=importlib.util.module_from_spec(spec);spec.loader.exec_module(lib)
 whole=lib.MachO(pathlib.Path(j['provider']['path']).read_bytes());oldImports={x['name'] for x in whole.imports}
 additions=sorted(x for x in set(imports)-oldImports if not x.startswith(('_VM27','_VZKernel')))
 diff=o/'acquisition-v2-to-v3.diff';diff.write_text(''.join(difflib.unified_diff(previous.read_text().splitlines(True),acq.read_text().splitlines(True),fromfile=str(previous),tofile=str(acq))))
 assert initial==[pin(p)for p in sources]
 expectedObject=next(row for row in j['reusedObjectPins']if row['path'].endswith('vm-hv-public-bootstrap-integration-local-v12-attempt2/modern_cpu_config_capability_acquisition_v2.o'))
 record=dict(schema='Authenticated own UID0/mobile501 native0 acquisition V3 source and object',builder=pin(__file__),source=pin(acq),fixture=pin(fixture),
  inheritedF21=pin(old),inheritedF21Freeze=pin(freeze),actualF21ReplacedObject=expectedObject,productionObject=pin(objects[0]),
  hiddenABI=['_VM27CPUConfigAcquireCapabilitiesV2','_VM27CPUConfigAcquireRawIPAPairV2','_VM27CPUConfigAcquireTLBICapabilityV1'],
  actualObjectUndefined=imports,currentF21StrongImports=len(whole.imports),possibleWholeNewNativeImports=additions,
  sourceFiles=initial,actualIncludeClosure=list(includes.values()),sourceDiff=pin(diff),models=models,
  allowedUIDs=[0,501],realAndEffectiveUIDMustAgree=True,actualAuditPIDAndVersionAndUIDRequired=True,
  actualKernelCSValidAndCDHashCheckedBeforeAndAfterEntitlements=True,
  actualBooleanPlatformHypervisorVirtualizationEntitlementsRequired=True,CSPlatformBinaryRequired=False,
  securityEntitlementsValidatedIsNotForged=True,actualKernelPermissionStillRequired=True,
  originalOneNative0Guarded352ByteAcquisitionPreserved=True,native0PostIdentityRechecked=True,
  sourceTestingHooksForbiddenOnIOS=True,actualIOSObjectCompiled=True,actualTypedCPPAndNativeStrongLinkPassed=True,
  originalF21AndV2Modified=False,wholeCPUProviderLinked=False,singleCPURegistryCompositionByPeerStillRequired=True,
  codeSigned=False,deviceOperations=0,nativeOperations=0,guestBoot=False)
 save(o/'candidate.json',record)
 files={str(p):pin(p)for p in o.iterdir()if p.is_file()}
 for row in list(includes.values())+initial+[pin(__file__),pin(previous),pin(old),pin(freeze),expectedObject,pin(parser)]:files[row['path']]=row
 save(o/'freeze.json',dict(schema='CapabilityAdmissionV3 source object typed models freeze',files=sorted(files.values(),key=lambda row:row['path']),deviceOperations=0,nativeOperations=0))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),object=pin(objects[0]),models=models,possibleWholeNewNativeImports=additions)))
if __name__=='__main__':main()
