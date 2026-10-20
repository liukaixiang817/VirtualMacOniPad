#!/usr/bin/env python3
"""Compile the real Runtime3 source; fixture cannot authorize or spawn a child."""
import argparse,hashlib,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
S=pathlib.Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();data=p.read_bytes();return dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=pathlib.Path,required=True);out=ap.parse_args().out.resolve()
 if out.parent!=N:raise ValueError('Fresh diagnostic root required')
 out.mkdir(exist_ok=False);commands=[];frozen=[]
 for relative in ['independent27-runtime-source-local-v2-attempt1/freeze.json','owned-app-child-startup-source-v2-attempt1/freeze.json']:
  path=N/relative
  for row in json.loads(path.read_bytes())['files']:
   if pin(row['path'])!=row:raise ValueError('Frozen runtime/startup source changed')
  frozen.append(pin(path))
 def run(label,args,expected=0):
  result=subprocess.run(list(map(str,args)),capture_output=True,timeout=45)
  (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
  commands.append(dict(label=label,argv=list(map(str,args)),returncode=result.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
  (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if (expected==0 and result.returncode) or (expected!=0 and not result.returncode):raise RuntimeError(label+': '+result.stderr.decode(errors='replace'))
  return result
 previous=N/'independent27-runtime-source-local-v2-attempt1';fixture=previous/'fixture';anchor=previous/'fixture-only-anchor.c'
 models={}
 for mode,flags in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  executable=out/('runtime-'+mode)
  run(mode+'-compile',['xcrun','--sdk','macosx','clang','-fobjc-arc','-Wall','-Wextra','-Werror',*flags,'-I',S,
   S/'test-vm27-independent-runtime-v3.m',anchor,'-framework','Foundation','-o',executable])
  models[mode]=json.loads(run(mode+'-run',[executable,fixture]).stdout.splitlines()[-1])
 if models['normal']!=models['san']:raise ValueError('Scoped fixture models differ')
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-fobjc-arc','-Wall','-Wextra','-Werror','-I',S]
 obj=out/'vm27_independent_app_runtime_v3.o'
 run('ios-production-compile',[*ios,'-c',S/'vm27_independent_app_runtime_v3.m','-o',obj])
 rejected=run('ios-fixture-rejected',[*ios,'-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-c',S/'vm27_independent_app_runtime_v3.m','-o',out/'forbidden.o'],expected=1)
 if b'Runtime fixture admission is forbidden on iOS' not in rejected.stderr:raise ValueError('Wrong fixture refusal')
 files=[S/name for name in ['vm27_independent_app_runtime_v3.m','vm27_independent_app_runtime_v2.m','vm27_independent_app_runtime_v1.m',
  'vm27_independent_app_runtime_v1.h','vm27_independent_app_runtime_anchor_v1.h','test-vm27-independent-runtime-v3.m',
  'vm27_owned_app_child_startup_v2.h','vm27_owned_app_child_startup_v1.h']]+[pathlib.Path(__file__).resolve()]
 report=dict(schema='independent27 runtime true parent bootstrap source v3',sourcePins=[pin(p) for p in files],inheritedFreezePins=frozen,
  models=models,productionIOSObject=pin(obj),actualFrontendLoadCallsTypedParentStart=True,
  originalParentSelfPathMainUUIDCodeDirectoryPagesAndExternalSlotsRequired=True,
  productManifestAppSelfHashCycleAvoided=True,bootstrapUsesLiveNonce=True,environmentEmptyNoDYLDMutation=True,
  originalChildAndScopedNativeGatesUnchanged=True,failedOwnershipRetainedAndProcessPoisoned=True,
  actualRuntimeProductAnchorGenerated=False,fixtureAnchorIOSLinked=False,actualChildSpawnExecuted=False,
  actualStrong27GraphFinalized=False,productionNativeOpsInstalled=False,deviceOperations=0,guestBoot=False)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 files+=[p for p in out.rglob('*') if p.is_file() and not p.is_symlink()]
 (out/'freeze.json').write_text(json.dumps(dict(schema='independent runtime3 source compile and scoped fixtures freeze v1',files=[pin(p) for p in sorted(set(files))]),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),models=models)))
if __name__=='__main__':main()
