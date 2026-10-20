#!/usr/bin/env python3
"""Strictly link the actual UIKit/serial-VM-queue source path, without running VZ."""
import argparse,hashlib,importlib.util,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir();cmds=[]
 own=[S/'vm27_input_queue_v3.h',S/'vm27_input_queue_v3.m',pathlib.Path(__file__).resolve()]
 initial=[pin(f)for f in own]
 inherited=[]
 for name in ('own-uikit-genuine-input-ingress-source-build-v1','uikit-own-input-surface-data-build-v6','uikit-genuine-display-source-finalization-v1'):
  directory=N/name;freeze=directory/'freeze.json';j=json.loads(freeze.read_bytes())
  for row in j['files']:
   assert pin(pathlib.Path(row['path']))==row,row['path']
  inherited.append(dict(freeze=pin(freeze),files=len(j['files'])))
 def run(label,args):
  argv=list(map(str,args));cp=subprocess.run(argv,capture_output=True,timeout=60)
  (o/(label+'.stdout')).write_bytes(cp.stdout);(o/(label+'.stderr')).write_bytes(cp.stderr)
  cmds.append(dict(label=label,argv=argv,exit=cp.returncode));save(o/'commands.json',cmds)
  assert cp.returncode==0,(label,cp.stderr.decode(errors='replace'));return cp
 sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
 mac=run('mac-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
 stateHeader=pathlib.Path(mac)/'System/Library/Frameworks/Virtualization.framework/Headers/VZVirtualMachine.h'
 header=stateHeader.read_text();assert 'VZVirtualMachineStateRunning' in header
 names=['modern_input_packet_v2.c','vm27_own_uikit_ingress_values_v1.c','modern_vz_scroll_normalization_v1.c',
  'modern_processed_scroll_native_v1.c','modern_input_packet_lease_v2.m','modern_uikit_input_adapter_v2.m',
  'modern_uikit_input_surface_v2.m','modern_processed_scroll_sink_v1.m','modern_vz_processed_scroll_receiver_v1.m',
  'vm27_own_uikit_ingress_profile_v1.m','vm27_genuine_display_observer_v1.mm','vm27_uikit_guest_display_v1.mm',
  'vm27_input_queue_v3.m']
 unitPins=[pin(S/name)for name in names];objects=[];closure={}
 common=['-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-Wall','-Wextra','-Werror','-fblocks','-I',S]
 for i,name in enumerate(names):
  f=S/name;compiler='clang++'if f.suffix=='.mm'else'clang'
  options=['xcrun',compiler]+common+(['-std=c++17']if f.suffix=='.mm'else['-std=c11'])
  if f.suffix in('.m','.mm'):options+=['-fobjc-arc']
  obj=o/(str(i)+'-'+f.stem+'.o');run('compile-'+str(i),options+['-c',f,'-o',obj]);objects.append(obj)
  cp=run('deps-'+str(i),options+['-MM',f]);tail=cp.stdout.decode().replace('\\\n',' ').split(':',1)[1]
  for item in shlex.split(tail):
   q=pathlib.Path(item).resolve()
   if q.is_file():closure[str(q)]=pin(q)
 provider=o/'VM27ActualUIKitInputQueueV3.unsigned.inert.dylib'
 options=['xcrun','clang++']+common+['-dynamiclib']+objects
 for framework in ('Foundation','CoreFoundation','CoreGraphics','IOKit','UIKit','IOSurface','Metal','QuartzCore'):
  options+=['-framework',framework]
 run('link',options+['-Wl,-undefined,error','-Wl,-no_adhoc_codesign',
  '-Wl,-install_name,@loader_path/VM27ActualUIKitInputQueueV3.dylib','-o',provider])
 run('validate',['xcrun','dyld_info','-validate_only',provider])
 run('exports',['xcrun','dyld_info','-exports',provider]);run('imports',['xcrun','dyld_info','-imports',provider])
 spec=importlib.util.spec_from_file_location('queue_macho',N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);image=m.MachO(provider.read_bytes())
 required=['_VM27ConnectGenuineInputQueueV3','_OBJC_CLASS_$_VM27InputQueueV3','_VM27GenuineDisplayProfileAvailableV1',
  '_OBJC_CLASS_$_VM27OwnUIKitIngressProfileV1','_OBJC_CLASS_$_VM27UIKitInputSurfaceV2']
 assert all(name in image.exports and image.exports[name]['flags']==0 for name in required)
 assert not any(row['name'].startswith(('_hv_','__hv_','_SLEvent','_OBJC_CLASS_$_VZ','_OBJC_CLASS_$__VZ'))for row in image.imports)
 assert not any(any(s in row['path']for s in ('Virtualization','Hypervisor','UniversalHID'))for row in image.loads)
 save(o/'actual-link.json',dict(uuid=image.uuid,requiredActualDefinitions={name:image.exports[name]for name in required},
  exports=image.exports,imports=image.imports,loads=image.loads))
 assert unitPins==[pin(S/name)for name in names] and initial==[pin(f)for f in own]
 candidate=dict(schema='Actual VZ27 main serial queue UIKit input source v3',sourceFiles=initial,
  inheritedFrozenSources=inherited,compiledSources=unitPins,actualIncludeClosure=list(closure.values()),
  currentSDKVMStateHeader=pin(stateHeader),provider=pin(provider),actualLink=pin(o/'actual-link.json'),
  actualVMQueueIdentitySourceConnected=True,genuineKeyboardPointingAndScrollSourceConnected=True,
  boundedCopiedPacketAdmissionCapacity=128,actualSerialSourceCancelDrainImplemented=True,
  originalSenderCleanupFailureReportedAndVMRetained=True,sourceLinkedWithRealDisplayProfile=True,
  fixtureClassOrGenuineRuntimeMockUsed=False,actualVZValueObjectsExecuted=False,actualUIKitRuntimeValidated=False,
  productionSourceModified=False,providerLoaded=False,codeSigned=False,deviceOperations=0,nativeHVCalls=0,full27Backend=False)
 save(o/'candidate.json',candidate)
 pins=initial+[pin(f)for f in o.iterdir()if f.is_file()]
 save(o/'freeze.json',dict(files=pins,deviceOperations=0,sharedFrozenSourceReceipts=inherited))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),provider=pin(provider),exports=len(image.exports),imports=len(image.imports))))
if __name__=='__main__':main()
