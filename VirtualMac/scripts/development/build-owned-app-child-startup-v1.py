#!/usr/bin/env python3
"""Compile true parent/child startup sources; no signing, spawn or device calls."""
import argparse,hashlib,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir();commands=[]
 def run(label,args):
  args=list(map(str,args));c=subprocess.run(args,capture_output=True,timeout=60)
  (o/(label+'.stdout')).write_bytes(c.stdout);(o/(label+'.stderr')).write_bytes(c.stderr)
  commands.append(dict(label=label,argv=args,exit=c.returncode));save(o/'commands.json',commands)
  assert c.returncode==0,(label,c.stderr.decode(errors='replace'));return c.stdout
 parent=N/'owned-vmm-xpc-v10-provider-build-v2';provider=json.loads((parent/'candidate.json').read_bytes())
 for row in json.loads((parent/'freeze.json').read_bytes())['files']:assert pin(pathlib.Path(row['path']))==row,row['path']
 libraries={row['name']:row for row in provider['libraries']}
 names=['VM27OwnedStartupV3.dylib','VM27LargeConsumerV2.dylib','VM27LargeRegistry.dylib','VM27PrivateEndpoint.dylib','VM27OriginalV10Transport.dylib','VM27LWCRPolicy.dylib']
 selected=[libraries[name]for name in names]
 for row in selected:assert pin(pathlib.Path(row['path']))=={k:row[k]for k in ['path','bytes','sha256']}
 sdk=run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 flags=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-std=c11','-Wall','-Wextra','-Werror','-I',S]
 inputs=[S/'vm27_owned_app_child_startup_v1.c',S/'vm27_owned_app_parent_identity_v1.c',S/'vm27_owned_app_child_premain_v1.c']
 closure={};objects=[]
 for i,source in enumerate(inputs):
  obj=o/(source.stem+'.o');run('compile-'+str(i),flags+['-c',source,'-o',obj]);objects.append(obj)
  deps=run('deps-'+str(i),flags+['-MM',source]).decode().replace('\\\n',' ')
  for name in shlex.split(deps.split(':',1)[1]):
   p=pathlib.Path(name).resolve();assert p.is_file();closure[str(p)]=pin(p)
 adapter=o/'VM27OwnedAppStartupV1.unsigned.dylib'
 run('link-adapter',flags+['-dynamiclib']+objects[:2]+[pathlib.Path(row['path'])for row in selected]+[
  '-framework','CoreFoundation','-framework','Security','-Wl,-install_name,@loader_path/VM27OwnedAppStartupV1.dylib','-Wl,-no_adhoc_codesign','-o',adapter])
 child=o/'VM27OwnedAppChildPreMainV1.unsigned.dylib'
 run('link-child-only-premain',flags+['-dynamiclib',objects[2],adapter,'-Wl,-install_name,@loader_path/VM27OwnedAppChildPreMainV1.dylib','-Wl,-no_adhoc_codesign','-o',child])
 for label,p in [('adapter',adapter),('child-only-premain',child)]:
  for what in ['validate_only','imports','exports','dependents']:run(label+'-'+what,['xcrun','dyld_info','-'+what,p])
 fixture=S/'test-vm27-owned-app-child-startup-v1.c';policy=S/'modern_xpc_lwcr_policy.c';models=[]
 for san in [False,True]:
  name='san'if san else'normal';binary=o/('host-'+name)
  args=['xcrun','clang','-std=c11','-fblocks','-Wall','-Wextra','-Werror','-O1','-g','-I',S,fixture,policy,'-framework','CoreFoundation','-framework','Security','-o',binary]
  if san:args+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
  run('host-'+name+'-compile',args);raw=run('host-'+name,[binary]);model=json.loads(raw);assert model['passed'] and model['processesSpawned']==0 and model['nativeVMOperations']==0;models.append(model)
 assert all(pin(pathlib.Path(row['path']))==row for row in closure.values())
 record=dict(schema='Actual app-owned startup source finite candidate v1',finiteLocalSourceScopePassed=True,findings=[],
  sourcePins=[pin(p)for p in inputs]+[pin(fixture),pin(pathlib.Path(__file__))],actualIncludeClosure=list(closure.values()),
  parentProviderCandidate=pin(parent/'candidate.json'),parentProviderFreeze=pin(parent/'freeze.json'),actualLinkedParentLibraries=selected,
  adapter=pin(adapter),childOnlyPreMain=pin(child),objects=[pin(p)for p in objects],models=models,
  parentCreateAndSpawnSourceIntegrated=True,childActualPreMainConstructorSourceIntegrated=True,
  childConstructorBelongsOnlyInChildDependencyGraph=True,childConstructorAddedToOriginalVMMCandidate=False,
  actualNativeParentGatesBeforeConfiguration=True,messageBodyHashDoesNotGrantPermission=True,
  actualReceivedHelloRequiredForFactory=True,installedFactoryOwnershipRetained=True,
  originalVZPrivateConnectionFinalInvalidObserverImplemented=False,
  productRuntimeAnchorGenerated=False,actualAppRuntimeStartupCallIntegrated=False,
  originalVZExecuted=False,originalVMMExecuted=False,actualXPCHandshakeExecuted=False,
  productionNativeOpsInstalled=False,deviceOperations=0,signingCalls=0,nativeVMOperations=0,guestBoot=False,
  limitations=['Installed original factory/consumer is retained for process lifetime until true original privateconnection drain is observed.','Product must add child-only preMain DSO to original child and ParentStart to actual RuntimeLoad; source linking alone is not execution.','Mocked finite native trust/registry models do not prove actual entitlement authorization or a child handshake.'])
 save(o/'candidate.json',record)
 files={str(p.resolve()):pin(p)for p in o.rglob('*')if p.is_file() and p.name!='freeze.json'}
 for row in record['sourcePins']+record['actualIncludeClosure']:files[row['path']]=row
 for p in [parent/'candidate.json',parent/'freeze.json']:files[str(p.resolve())]=pin(p)
 save(o/'freeze.json',dict(schema='actual startup source include closure and output freeze v1',files=list(files.values())))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),adapter=pin(adapter),childOnlyPreMain=pin(child),models=models)))
if __name__=='__main__':main()
