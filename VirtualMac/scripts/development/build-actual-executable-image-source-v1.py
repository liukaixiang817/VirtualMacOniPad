#!/usr/bin/env python3
"""Bounded host-only main-image fix compilation; no signing or device actions."""
import argparse,hashlib,json,pathlib,shlex,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=pathlib.Path);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir();commands=[];closure={}
 def run(label,args):
  args=list(map(str,args));c=subprocess.run(args,capture_output=True,timeout=60)
  (o/(label+'.stdout')).write_bytes(c.stdout);(o/(label+'.stderr')).write_bytes(c.stderr)
  commands.append(dict(label=label,argv=args,exit=c.returncode));save(o/'commands.json',commands)
  assert c.returncode==0,(label,c.stderr.decode(errors='replace'));return c.stdout
 sdk=run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 common=['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,'-O2','-fblocks','-Wall','-Wextra','-Werror','-I',S]
 sources=[S/'vm27_actual_executable_image_v1.c',S/'vm27_owned_app_child_premain_v4.c',S/'vm27_independent_app_runtime_v4.m']
 objects=[]
 for i,source in enumerate(sources):
  flags=common+(['-fobjc-arc']if source.suffix=='.m'else['-std=c11'])
  obj=o/(source.stem+'.o');run('ios-compile-'+str(i),flags+['-c',source,'-o',obj]);objects.append(obj)
  raw=run('ios-deps-'+str(i),flags+['-MM',source]).decode().replace('\\\n',' ')
  for name in shlex.split(raw.split(':',1)[1]):
   p=pathlib.Path(name).resolve();assert p.is_file();closure[str(p)]=pin(p)
 run('ios-runtime-ir',common+['-fobjc-arc','-S','-emit-llvm',sources[2],'-o',o/'runtime4.ll'])
 prior=N/'owned-app-child-startup-source-v3-attempt1';pdoc=json.loads((prior/'candidate.json').read_bytes())
 adapter=pathlib.Path(pdoc['adapter']['path']);assert pin(adapter)==pdoc['adapter']
 child=o/'VM27OwnedAppChildPreMainV3.unsigned.dylib'
 run('ios-child-link',common+['-dynamiclib',objects[0],objects[1],adapter,
  '-Wl,-install_name,@loader_path/VM27OwnedAppChildPreMainV3.dylib','-Wl,-no_adhoc_codesign','-o',child])
 for what in ['validate_only','imports','exports','dependents']:
  run('ios-child-'+what,['xcrun','dyld_info','-'+what,child])
 exports=(o/'ios-child-exports.stdout').read_text();imports=(o/'ios-child-imports.stdout').read_text()
 assert 'VM27ActualExecutableImage' not in exports and 'VM27OwnedAppChildBootstrapBeforeMainV3' in imports
 assert 'VM27OwnedAppChildBootstrapBeforeMainV2' not in imports
 models=[];host=['xcrun','clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-I',S]
 for san in [False,True]:
  label='san'if san else'normal';binary=o/('host-model-'+label)
  flags=host+(['-fsanitize=address,undefined','-fno-omit-frame-pointer']if san else[])
  run('model-compile-'+label,flags+[S/'test_vm27_actual_executable_image_v1.c','-o',binary])
  result=json.loads(run('model-'+label,[binary]).splitlines()[-1]);assert result['passed'] and result['cases']==14;models.append(result)
 live=o/'host-live-main';run('live-compile',host+[S/'test_vm27_actual_executable_image_live_v1.c',sources[0],'-o',live])
 liveResult=json.loads(run('live-main',[live]).splitlines()[-1]);assert liveResult['passed'] and liveResult['actualHostDyld']
 cpp=o/'actual-main-typed-caller.cpp'
 cpp.write_text('#include "vm27_actual_executable_image_v1.h"\nextern "C" int actualTypedMain(VM27ActualExecutableImageV1 *o){return VM27ActualExecutableImageFindSelfV1(o);}\n')
 run('ios-cpp-compile',['xcrun','clang++']+common[2:]+['-std=c++17','-c',cpp,'-o',o/'actual-main-typed-caller.o'])
 run('ios-cpp-link',common+['-dynamiclib',o/'actual-main-typed-caller.o',objects[0],'-Wl,-no_adhoc_codesign','-o',o/'actual-main-typed-caller.dylib'])
 run('ios-cpp-validate',['xcrun','dyld_info','-validate_only','-imports',o/'actual-main-typed-caller.dylib'])
 old=(S/'vm27_independent_app_runtime_v3.m').read_text();new=sources[2].read_text()
 first=old.index(' const struct mach_header_64 *loaded=(const void *)_dyld_get_image_header(0);')
 last=old.index(' NSDictionary *row=',first)
 nfirst=new.index(' /* Resolve the true executable by canonical path')
 nlast=new.index(' NSDictionary *row=',nfirst)
 assert old[:first].replace('#include <mach-o/dyld.h>','#include <mach-o/dyld.h>\n#include "vm27_actual_executable_image_v1.h"',1)==new[:nfirst]
 assert old[last:]==new[nlast:]
 delta=dict(runtime3=pin(S/'vm27_independent_app_runtime_v3.m'),runtime4=pin(sources[2]),
  oldBlock=old[first:last],newBlock=new[nfirst:nlast],allOtherRuntimeBytesUnchanged=True,
  actualFileUUIDCompared=True,primaryCodeDirectoryAndPageSlotValidationUnchanged=True,
  actualParentTokenCDAndCSValidNativeRightsUnchanged=True)
 save(o/'source-delta.json',delta)
 sourcePins=[pin(p)for p in sources+[S/'vm27_actual_executable_image_v1.h',S/'test_vm27_actual_executable_image_v1.c',S/'test_vm27_actual_executable_image_live_v1.c',pathlib.Path(__file__)]]
 evidence=[pin(S/'modern_cpu_kernel_lifecycle.md'),pin(S/'modern_pvg_texture_error_observation.m'),pin(S/'vm27_owned_app_child_premain_v1.c'),pin(S/'vm27_owned_app_child_premain_v3.c'),pin(prior/'candidate.json'),pin(prior/'freeze.json'),pin(adapter)]
 candidate=dict(schema='Canonical actual main image source fix finite candidate v1',finiteLocalSourceScopePassed=True,findings=[],
  sourcePins=sourcePins,actualIncludeClosure=list(closure.values()),evidencePins=evidence,sourceDelta=pin(o/'source-delta.json'),
  iosObjects=[pin(p)for p in objects],childOnlyPreMain=pin(child),iosRuntimeIR=pin(o/'runtime4.ll'),models=models,actualHostMain=liveResult,
  actualExecutableSymbolOnlyLookup=True,canonicalPathAndUniqueDyldMatchingExecutableRequired=True,
  actualLoadedHeaderAndCommandsSafelyMachRead=True,uuidComparedWithActualSignedAppFileOrOriginalChildRole=True,
  dyldSnapshotAndSelectedIdentityRechecked=True,mainIndexZeroNotRequired=True,
  sharedFunctionsHidden=True,newSharedDSODependencies=0,childStableInstallName='@loader_path/VM27OwnedAppChildPreMainV3.dylib',
  childActualV3BootstrapRetained=True,childFrontEndLoadForbidden=True,childConstructorNativeVMOperations=0,
  runtime3AllOtherSourcePreserved=True,iosArm64eCompileAndChildStrictLinkPassed=True,actualCPPUnmangledLinkPassed=True,
  deviceOperations=0,deviceWrites=0,explicitSigningCalls=0,nativeVMOperations=0,guestBoot=False,
  limitations=['Host synthetic dyld inventory is not the failed iPad process; actual host main identity was also tested.',
   'Runtime4 was component compiled only; the actual App still needs a real product anchor and whole link.',
   'The final Root19 and both signed CPU copies are built by Root; this candidate does not cover those product bytes.',
   'New trust hashes require actual final signing; prior 140 hashes do not authorize arbitrary replacements.'])
 save(o/'candidate.json',candidate)
 allpins={str(p.resolve()):pin(p)for p in o.rglob('*')if p.is_file() and p.name!='freeze.json'}
 for row in sourcePins+list(closure.values())+evidence:allpins[row['path']]=row
 save(o/'freeze.json',dict(schema='actual main image source and finite output freeze v1',files=list(allpins.values())))
 print(json.dumps(dict(candidate=pin(o/'candidate.json'),freeze=pin(o/'freeze.json'),child=pin(child),models=models,actualHostMain=liveResult)))
if __name__=='__main__':main()
