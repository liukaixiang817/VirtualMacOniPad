#!/usr/bin/env python3
"""Actual signed inert local fixtures, and production iOS compile without a fixture anchor."""
import argparse,hashlib,json,pathlib,plistlib,struct,subprocess,sys
sys.dont_write_bytecode=True
S=pathlib.Path(__file__).resolve().parent
N=S.parents[2]/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=pathlib.Path,required=True);out=ap.parse_args().out.resolve()
 if out.parent!=N:raise ValueError('Fresh diagnostics root required')
 out.mkdir(exist_ok=False);commands=[]
 for row in json.loads((N/'independent27-runtime-source-local-v1-attempt1/freeze.json').read_bytes())['files']:
  if pin(row['path'])!=row:raise ValueError('Frozen Runtime v1 changed')
 def run(label,args,expected=0):
  r=subprocess.run(list(map(str,args)),capture_output=True,timeout=45)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append(dict(label=label,argv=list(map(str,args)),returncode=r.returncode,stdout=pin(out/(label+'.stdout')),stderr=pin(out/(label+'.stderr'))))
  (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if (expected==0 and r.returncode) or (expected!=0 and not r.returncode):raise RuntimeError(label+': '+r.stderr.decode(errors='replace'))
  return r
 fixture=out/'fixture';fixture.mkdir();(fixture/'directory').mkdir()
 source=out/'inert.c';source.write_text('const unsigned ActualFixtureBLV1=0x9404a45a;\nint hv_vm_config_create(void){return 17;}\n')
 rows=[]
 for key,role in [('provider','frontend'),('child','child')]:
  p=fixture/('fixture-'+key+'.dylib')
  run(key+'-compile',['xcrun','--sdk','macosx','clang','-dynamiclib',source,'-Wl,-install_name,@rpath/'+p.name,'-o',p])
  run(key+'-sign',['codesign','--force','--sign','-','--timestamp=none',p]);run(key+'-verify',['codesign','--verify','--strict',p])
  data=p.read_bytes();at=32;n,total=struct.unpack_from('<II',data,16);uuid=None;cs=None
  for _ in range(n):
   cmd,size=struct.unpack_from('<II',data,at)
   if cmd==0x1b:uuid=data[at+8:at+24].hex()
   if cmd==0x1d:cs=struct.unpack_from('<II',data,at+8)
   at+=size
  if not uuid or not cs:raise ValueError('Actual fixture UUID/signature')
  start,length=cs;magic,size,count=struct.unpack_from('>III',data,start)
  if magic!=0xfade0cc0:raise ValueError('Actual signature')
  cd=None
  for i in range(count):
   t,o=struct.unpack_from('>II',data,start+12+8*i)
   if t==0:l=struct.unpack_from('>I',data,start+o+4)[0];cd=data[start+o:start+o+l]
  if cd is None:raise ValueError('Actual CodeDirectory')
  rows.append(dict(id=key,path=p.name,kind='mach-o',role=role,uuid=uuid,cdhash=hashlib.sha256(cd).hexdigest()[:40],bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
 nm=run('actual-export-offset',['xcrun','nm','-gU',fixture/'fixture-provider.dylib']).stdout.decode();line=next(x for x in nm.splitlines() if x.endswith(' _hv_vm_config_create'));rva=int(line.split()[0],16)
 proof=fixture/'fixture-scope.json';proof.write_text(json.dumps(dict(scope='inert local runtime admission fixture only',fullStrong27Graph=False,nativeCPUCalls=0))+'\n')
 rows.append(dict(id='fixture-proof',path=proof.name,kind='resource',role='proof',bytes=proof.stat().st_size,sha256=pin(proof)['sha256']))
 child=(fixture/'fixture-child.dylib').read_bytes();word=struct.pack('<I',0x9404a45a)
 if child.count(word)!=1:raise ValueError('Unique inert fixture BL word')
 manifest=dict(schema=1,runtimeVersion=27,files=rows,loadOrder=['provider'],dependencyProofID='fixture-proof',
  entries=[dict(fileID='provider',symbol='hv_vm_config_create',rva=rva)],
  childEntryContract=dict(providerID='provider',childID='child',mainUUID=rows[1]['uuid'],symbol='hv_vm_config_create',
   setupBLFileOffset=child.index(word),setupBLWord=0x9404a45a,providerEntryRVA=rva))
 raw=plistlib.dumps(manifest,fmt=plistlib.FMT_BINARY,sort_keys=True);(fixture/'VM27IndependentRuntimeManifestV1.plist').write_bytes(raw)
 anchor=out/'fixture-only-anchor.c';anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\nconst uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={'+','.join(str(x) for x in hashlib.sha256(raw).digest())+'};\nconst size_t VM27IndependentRuntimeManifestBytesV1='+str(len(raw))+';\n')
 (fixture/'symlink-provider').symlink_to(fixture/'fixture-provider.dylib')
 models={}
 for mode,flags in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  exe=out/('runtime-'+mode)
  run(mode+'-compile',['xcrun','--sdk','macosx','clang','-fobjc-arc','-Wall','-Wextra','-Werror',*flags,'-I',S,
   S/'test-vm27-independent-runtime-v2.m',anchor,'-framework','Foundation','-o',exe])
  models[mode]=json.loads(run(mode+'-run',[exe,fixture]).stdout.splitlines()[-1])
 if models['normal']!=models['san']:raise ValueError('Fixture model disagreement')
 obj=out/'vm27_independent_app_runtime_v1.o'
 ios=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1','-fobjc-arc','-Wall','-Wextra','-Werror','-I',S]
 run('ios-production-compile',[*ios,'-c',S/'vm27_independent_app_runtime_v2.m','-o',obj])
 reject=run('ios-fixture-rejected',[*ios,'-DVM27_INDEPENDENT_RUNTIME_TESTING=1','-c',S/'vm27_independent_app_runtime_v2.m','-o',out/'forbidden.o'],expected=1)
 if b'Runtime fixture admission is forbidden on iOS' not in reject.stderr:raise ValueError('Wrong fixture rejection')
 files=[S/x for x in ['vm27_independent_app_runtime_v2.m','vm27_independent_app_runtime_v1.m','vm27_independent_app_runtime_v1.h','vm27_independent_app_runtime_anchor_v1.h','test-vm27-independent-runtime-v2.m']]+[pathlib.Path(__file__).resolve()]
 report=dict(schema='independent27 runtime class identity actual file signature load source local v2',sourcePins=[pin(x) for x in files],models=models,
  productionIOSObject=pin(obj),actualRuntimeProductAnchorGenerated=False,fixtureAnchorIOSLinked=False,
  productionNativeOpsInstalled=False,actualChildSpawnAdapterIntegrated=False,actualStrong27GraphFinalized=False,
  codeDirectoryAndPagesActuallyChecked=True,actualInertFixtureDlopen=True,guestStateCannotBeClaimedWithoutOriginalBoundVM=True,
  actualVZClassImageAndStrongExportIdentityRequired=True,originalClassUUID='418efc4809d93606918eb6f95baeffdc',targetProfile='iPad14,6/22.1.0/20B101',deviceOperations=0,guestBoot=False)
 (out/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
 files+=[p for p in out.rglob('*') if p.is_file() and not p.is_symlink()]
 (out/'freeze.json').write_text(json.dumps(dict(schema='independent runtime source and scoped fixture freeze v1',files=[pin(x) for x in sorted(set(files))]),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),models=models)))
if __name__=='__main__':main()
