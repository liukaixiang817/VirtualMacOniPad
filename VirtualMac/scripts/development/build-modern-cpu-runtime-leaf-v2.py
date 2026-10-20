#!/usr/bin/env python3
"""Prepare a bounded ordinary C++ leaf fixture. No device dispatch or VM APIs."""
from pathlib import Path
import hashlib,json,re,shutil,struct,subprocess,sys

R=Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE=R/'VirtualMac/scripts/tests/test-modern-cpu-runtime-leaf-v2.cpp'
GOLDEN=R/'VirtualMac/scripts/tests/capture-modern-cpu-runtime-hash-goldens-v1.cpp'
RUNTIME_SOURCE=R/'VirtualMac/vz/host/modern_cpu_runtime_compat.cpp'
SYMBOLS=['__ZTINSt3__119bad_expected_accessIvEE','__ZNKSt3__119bad_expected_accessIvE4whatEv',
 '__ZNSt3__113__hash_memoryEPKvm','__ZNSt3__123__atomic_monitor_globalEPKv',
 '__ZNSt3__126__atomic_wait_global_tableEPKvx','__ZNSt3__132__atomic_notify_all_global_tableEPKv']
H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def commands(b):
 assert struct.unpack_from('<I',b)[0]==0xfeedfacf
 at=32;end=32+struct.unpack_from('<I',b,20)[0]
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,size=struct.unpack_from('<II',b,at);assert size>=8 and size%8==0 and at+size<=end
  yield cmd,at,size;at+=size
 assert at==end
def uuid(p):
 rows=[p.read_bytes()[a+8:a+24].hex() for c,a,s in commands(p.read_bytes()) if c==0x1b]
 assert len(rows)==1;return rows[0]
def row(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':H(p)}
def main(output):
 out=Path(output).resolve();out.mkdir(mode=0o700,exist_ok=False)
 inputs=[SOURCE,GOLDEN,RUNTIME_SOURCE,Path(__file__),N/'vz-cxx-six-strong-data-v2/candidate.json',
  N/'current-stock-cxx-leaves-independent-review-v1/review.json']
 original={str(p):H(p) for p in inputs}
 def run(label,args,timeout=30):
  z=subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout)
  (out/(label+'.command.json')).write_text(json.dumps(list(map(str,args)),indent=2)+'\n')
  (out/(label+'.stdout')).write_bytes(z.stdout);(out/(label+'.stderr')).write_bytes(z.stderr)
  if z.returncode:raise RuntimeError(label+': '+z.stderr.decode(errors='replace')[-2000:])
  return z
 flags=['-std=c++23','-O2','-fno-typed-cxx-new-delete','-D_LIBCPP_DISABLE_AVAILABILITY',
  '-fptrauth-abi-version=0','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-Wl,-no_adhoc_codesign']
 run('native-golden-compile',['xcrun','--sdk','macosx','clang++','-target','arm64e-apple-macos13.0',
  *flags,'-Wl,-no_mac_public_arm64e',GOLDEN,'-o',out/'native-goldens'])
 run('native-golden-sign',['codesign','--force','--sign','-','--timestamp=none',out/'native-goldens'])
 g=json.loads(run('native-golden-execute',[out/'native-goldens']).stdout);assert len(g['hashes'])==54
 (out/'native-goldens.json').write_text(json.dumps(g,indent=2)+'\n')
 candidate=json.loads((N/'vz-cxx-six-strong-data-v2/candidate.json').read_bytes())
 libraries={x['alias']:x['source'] for x in candidate['unchangedRuntimeProviders']}
 review=json.loads((N/'current-stock-cxx-leaves-independent-review-v1/review.json').read_bytes())
 # Find the actual -3 lookup row, retaining its explicit unproven-runtime flag.
 def search(value):
  if isinstance(value,dict):
   if value.get('symbol')=='__ZdlPv' and value.get('ordinal')==-3:return value
   for v in value.values():
    if (found:=search(v)) is not None:return found
  if isinstance(value,list):
   for v in value:
    if (found:=search(v)) is not None:return found
  return None
 deletion=search(review);assert deletion['proof']['status']=='specialLookupRuntimeNotProven'
 nested=deletion['proof']['nativeSameNameDefinition']['nested']
 assert nested['owner']=='/usr/lib/libc++abi.dylib' and nested['entry']['address']==80212
 all_products=[]
 for role in ('ios','macos'):
  d=out/role;d.mkdir(mode=0o700)
  runtime=d/'ModernCPURuntimeCompat.dylib';cp=d/'VM27CxxProvider.dylib'
  if role=='ios':
   for alias,dest in [('CP',cp),('ModernCPURuntimeCompat.dylib',runtime)]:
    pin=libraries[alias];p=Path(pin['path']);assert p.is_file() and not p.is_symlink()
    assert p.stat().st_size==pin['bytes'] and H(p)==pin['sha256'];inputs.append(p);original[str(p)]=H(p)
    shutil.copyfile(p,dest)
   native={'nativeDeletePath':nested['owner'],'nativeDeleteUUID':nested['UUID'],'nativeDeleteRVA':nested['entry']['address']}
  else:
   run('mac-runtime-compile',['xcrun','--sdk','macosx','clang++','-target','arm64e-apple-macos13.0',
    *flags,'-D_LIBCPP_BUILDING_LIBRARY','-Wl,-no_mac_public_arm64e','-dynamiclib',
    '-install_name','@rpath/ModernCPURuntimeCompat.dylib',RUNTIME_SOURCE,'-o',runtime])
   exports=SYMBOLS+['__ZNSt13exception_ptr31__from_native_exception_pointerEPv']
   (d/'reexports.txt').write_text('\n'.join(exports)+'\n')
   (d/'native-identity.tbd').write_text('--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64e-macos ]\ninstall-name: /usr/lib/libc++.1.dylib\n...\n')
   (d/'empty.c').write_text('/* Genuine reexports only. */\n')
   run('mac-cp-compile',['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0',
    '-fptrauth-abi-version=0','-Wl,-no_mac_public_arm64e','-Wl,-no_adhoc_codesign','-dynamiclib',
    '-Wl,-reexport_library,'+str(d/'native-identity.tbd'),runtime,
    '-Wl,-reexported_symbols_list,'+str(d/'reexports.txt'),'-Wl,-rpath,@loader_path',
    '-install_name','@rpath/VM27CxxProvider.dylib',d/'empty.c','-o',cp])
   for name,p in [('runtime',runtime),('cp',cp)]:run('mac-'+name+'-sign',['codesign','--force','--sign','-','--timestamp=none',p])
   native=g
  for name,p in [('runtime',runtime),('cp',cp)]:
   run(role+'-'+name+'-strict',['codesign','--verify','--strict',p]);run(role+'-'+name+'-dyld',['xcrun','dyld_info','-validate_only',p])
   assert not run(role+'-'+name+'-entitlements',['codesign','-d','--entitlements',':-',p]).stdout
  exports=run(role+'-runtime-exports',['xcrun','dyld_info','-exports',runtime]).stdout.decode()
  offsets={m[2]:int(m[1],16) for m in re.finditer(r'^\s*0x([0-9A-Fa-f]+)\s+(\S+)\s*$',exports,re.M)}
  assert all(s in offsets for s in SYMBOLS)
  fixups=run(role+'-runtime-fixups',['xcrun','dyld_info','-fixups',runtime]).stdout.decode()
  matches=re.findall(r'^\s*__DATA_CONST\s+__auth_got\s+0x([0-9A-Fa-f]+)\s+auth-bind\s+<weak-def-coalesce>/__ZdlPv.*$',fixups,re.M)
  assert len(matches)==1;delete_got=int(matches[0],16)
  device='/var/root/VirtualMac2/diagnostics/cxx-runtime-leaf-v1'
  paths=[device+'/'+cp.name,device+'/'+runtime.name] if role=='ios' else [str(cp),str(runtime)]
  header='#pragma once\n#include <cstddef>\n#include <cstdint>\n'
  header+='struct FilePin {const char *path,*sha;size_t bytes;};\nstatic const FilePin FilePins[]={\n'
  for p,path in zip((cp,runtime),paths):header+='{'+json.dumps(path)+','+json.dumps(H(p))+','+str(p.stat().st_size)+'},\n'
  header+='};\n'
  for key,pin in [('RuntimeUUID',uuid(runtime)),('CPUUID',uuid(cp)),('NativeDeleteUUID',native['nativeDeleteUUID'])]:
   header+='static const unsigned char '+key+'[]={'+','.join('0x'+pin[i:i+2] for i in range(0,32,2))+'};\n'
  header+='static const uintptr_t RuntimeRVAs[]={'+','.join(str(offsets[s]) for s in SYMBOLS)+'};\n'
  header+='static const uintptr_t DeleteGOTRVA='+str(delete_got)+';\n'
  header+='static const uintptr_t NativeDeleteRVA='+str(native['nativeDeleteRVA'])+';\n'
  header+='static const char NativeDeletePath[]='+json.dumps(native['nativeDeletePath'])+';\n'
  header+='struct HashPin {unsigned offset,length;uint64_t value;};\nstatic const HashPin HashPins[]={\n'
  for pin in g['hashes']:header+='{'+str(pin['offset'])+','+str(pin['length'])+','+str(pin['value'])+'ULL},\n'
  header+='};\nstatic const unsigned HashCount=sizeof(HashPins)/sizeof(HashPins[0]);\n'
  (d/'cpu-runtime-leaf-pins.h').write_text(header)
  sdk='iphoneos' if role=='ios' else 'macosx';target='arm64e-apple-ios16.1' if role=='ios' else 'arm64e-apple-macos13.0'
  binary=d/'cpu-runtime-leaf-v1'
  run(role+'-fixture-compile',['xcrun','--sdk',sdk,'clang++','-target',target,*flags,
   *([] if role=='ios' else ['-Wl,-no_mac_public_arm64e']),'-I',d,SOURCE,cp,runtime,
   '-Wl,-rpath,@executable_path','-o',binary])
  if role=='ios':
   b=bytearray(binary.read_bytes());build=[a for c,a,s in commands(b) if c==0x32];assert len(build)==1
   assert struct.unpack_from('<I',b,build[0]+8)[0]==2
   struct.pack_into('<3I',b,build[0]+8,2,0x100100,0x100100);binary.write_bytes(b)
  run(role+'-fixture-sign',['codesign','--force','--sign','-','--timestamp=none','--identifier','local.VirtualMac.cxx-leaf.'+role,binary])
  for name,p in [('runtime',runtime),('cp',cp),('fixture',binary)]:
   run(role+'-'+name+'-final-strict',['codesign','--verify','--strict',p])
   sig=run(role+'-'+name+'-signature',['codesign','-dvvv',p]).stderr
   run(role+'-'+name+'-validate',['xcrun','dyld_info','-validate_only',p])
   assert not run(role+'-'+name+'-final-entitlements',['codesign','-d','--entitlements',':-',p]).stdout
   all_products.append({**row(p),'role':role,'kind':name,'UUID':uuid(p),
    'CDHash':re.search(rb'CDHash=([0-9a-f]{40})',sig)[1].decode(),'emptyEntitlements':True})
  binds=run(role+'-fixture-binds',['xcrun','dyld_info','-imports','-dependents',binary]).stdout.decode()
  assert not any(s in binds for s in ['Hypervisor.framework','Virtualization.framework','VirtualMachine','ParavirtualizedGraphics','IOKit.framework'])
  for s in SYMBOLS:
   lines=[line for line in binds.splitlines() if re.search(r'\s'+re.escape(s)+r'\s+\(from VM27CxxProvider\)\s*$',line)]
   assert len(lines)==1 and 'VM27CxxProvider' in lines[0],(s,lines)
  if role=='macos':
   z=run('mac-fixture-execute',[binary],20)
   records=[json.loads(x) for x in z.stdout.decode().splitlines()]
   assert records[-1]['record']=='summary' and records[-1]['passed'] and records[-1]['failures']==0
   assert records[-1]['created']==records[-1]['released']==64
 for p in inputs:assert H(p)==original[str(p)]
 manifest={'schema':'Unchanged CP/runtime ordinary leaf fixture preparation v1','products':all_products,
  'macNativeHashGoldenCount':len(g['hashes']),'macFixturePassed':True,
  'iosProviderWholeBytesUnchanged':True,'iosExecution':False,'deviceOperations':0,
  'nativeCPUCalls':0,'productionPackageModified':False,'originalVZExecuted':False,
  'original27ProcessGlobalNamespaceProven':False,'full27Backend':False}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 pins=[row(p) for p in inputs]+[row(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name!='freeze.json']
 assert len({x['path'] for x in pins})==len(pins)
 (out/'freeze.json').write_text(json.dumps({'files':pins},indent=2)+'\n')
 print(json.dumps({'manifest':row(out/'manifest.json'),'freeze':row(out/'freeze.json'),'macFixture':records[-1]},indent=2))
if __name__=='__main__':
 assert len(sys.argv)==2;main(sys.argv[1])
